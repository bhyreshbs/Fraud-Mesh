"""Live Suricata sensor (PRD §7.4 adapter, §9.2 ingestion): follow a growing eve.json like `tail -F` and post every
alert line as a signed network_ids_alert Envelope.

CLI:  python -m api.adapters.suricata_live <path/to/eve.json> [--api URL] [--from-start] [--state FILE]
                                           [--batch N] [--poll SECONDS] [--once]

  --api URL       API base URL (default $FM_API or http://127.0.0.1:8000)
  --from-start    with no saved state, read the file from byte 0 (default: start at the end, i.e. only new alerts)
  --state FILE    byte offset + file identity, saved after each successful post (default data/suricata_live.state)
  --batch N       N > 1: POST /v1/events/batch with up to N events (max 500); N = 1: POST /v1/events (default 100)
  --poll SECONDS  how often to look for new lines (default 0.5)
  --once          process what is in the file now, save state and exit (cron / tests)

Delivery is at-least-once: the offset is committed only after the API answered 202/409 (or refused a line for good),
so a crash or Ctrl+C re-reads at most the lines that were in flight. Event ids are generated per line, so a line that
is re-read after a restart is a new event to the API; inside one run a retried request keeps its event_id, so the
API's DUPLICATE_EVENT (409) makes retries safe.

The tailer (EveTailer) and the sender (Poster) are separate so tests drive them with a temp file and an
httpx.MockTransport; no API or database is needed.
"""
from __future__ import annotations

import json
import logging
import os
import random
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import Path

import httpx

from api.adapters.suricata import eve_to_envelope
from engine.contracts import Envelope

try:
    from scripts.tls import httpx_kwargs
except ImportError:  # scripts/tls.py is optional (TLS / mTLS settings for senders)
    def httpx_kwargs(source: str | None = None) -> dict:
        return {}

log = logging.getLogger("fraudmesh.suricata_live")

SOURCE = "network-ids"
MAX_BATCH = 500                      # PRD §9.2
READ_CHUNK = 4 * 1024 * 1024         # most bytes read per poll; a line longer than this is dropped as malformed
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRY_AFTER_S = 300.0

Ident = tuple[int, int]              # (st_dev, st_ino) of the file being followed


# ------------------------------------------------------------------ tailer


def _ident(st: os.stat_result) -> Ident:
    return (int(st.st_dev), int(st.st_ino))


class EveTailer:
    """Yields complete lines appended to `path`, each with the byte offset just past its newline.

    Opens, reads and closes the file on every poll (portable, and never keeps a writer from rotating the file).
    - missing file: wait (poll returns []);
    - partial last line (no newline yet): not returned until the newline arrives;
    - rotation (the path now names a different file: dev/inode changed): restart at byte 0 of the new file;
    - truncation (size < offset): restart at byte 0.
    `offset` is the read position; the caller decides when it is committed.
    """

    def __init__(self, path: str | os.PathLike, offset: int = 0, ident: Ident | None = None,
                 start_at_end: bool = False, read_chunk: int = READ_CHUNK) -> None:
        self.path = Path(path)
        self.offset = offset
        self.ident = ident
        self.start_at_end = start_at_end and ident is None
        self.read_chunk = read_chunk
        self.rotations = 0
        self.truncations = 0
        self.oversized = 0
        self._discarding = False           # inside a line longer than read_chunk: drop bytes up to its newline

    def _end_of_last_line(self, size: int) -> int:
        """Offset just past the last newline in the file (a half-written last line is read when it completes)."""
        if size == 0:
            return 0
        with open(self.path, "rb") as f:
            pos = size
            while pos > 0:
                step = min(65536, pos)
                f.seek(pos - step)
                chunk = f.read(step)
                i = chunk.rfind(b"\n")
                if i >= 0:
                    return pos - step + i + 1
                pos -= step
        return 0

    def poll(self) -> list[tuple[bytes, int]]:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []
        ident = _ident(st)
        if self.ident is None:
            if self.start_at_end:
                self.offset = self._end_of_last_line(st.st_size)
                log.info("following %s from the end (byte %d)", self.path, self.offset)
            self.start_at_end = False
        elif ident != self.ident and ident[1] != 0:
            log.info("%s was rotated (new file); reading it from the start", self.path)
            self.rotations += 1
            self.offset, self._discarding = 0, False
        elif st.st_size < self.offset:
            log.info("%s was truncated (%d < %d bytes); reading it from the start", self.path, st.st_size, self.offset)
            self.truncations += 1
            self.offset, self._discarding = 0, False
        self.ident = ident
        if st.st_size <= self.offset:
            return []
        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                data = f.read(min(st.st_size - self.offset, self.read_chunk))
        except FileNotFoundError:          # rotated away between stat and open
            return []
        out: list[tuple[bytes, int]] = []
        pos = self.offset
        start = 0
        if self._discarding:
            nl = data.find(b"\n")
            if nl < 0:
                self.offset = pos + len(data)
                return []
            start, self._discarding = nl + 1, False
        while True:
            nl = data.find(b"\n", start)
            if nl < 0:
                break
            out.append((data[start:nl], pos + nl + 1))
            start = nl + 1
        if start == 0 and len(data) >= self.read_chunk:      # no newline in a whole chunk: drop this giant line
            log.warning("line at byte %d is longer than %d bytes; skipped", pos, self.read_chunk)
            self.oversized += 1
            self._discarding = True
            self.offset = pos + len(data)
            return out
        self.offset = pos + start
        return out


# ------------------------------------------------------------------- state


@dataclass
class TailState:
    path: str
    offset: int = 0
    ident: Ident | None = None

    @classmethod
    def load(cls, state_file: str | os.PathLike, path: str) -> TailState | None:
        try:
            d = json.loads(Path(state_file).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (ValueError, OSError) as e:
            log.warning("ignoring unreadable state file %s: %s", state_file, e)
            return None
        if os.path.abspath(d.get("path", "")) != os.path.abspath(path):
            log.warning("state file %s is for %s, not %s; ignoring it", state_file, d.get("path"), path)
            return None
        ident = d.get("ident")
        return cls(path=path, offset=int(d.get("offset", 0)), ident=tuple(ident) if ident else None)

    def save(self, state_file: str | os.PathLike) -> None:
        p = Path(state_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(json.dumps({"path": self.path, "offset": self.offset, "ident": list(self.ident) if self.ident else None,
                                   "saved_at": int(time.time())}), encoding="utf-8")
        os.replace(tmp, p)


# ------------------------------------------------------------------ poster


@dataclass
class Stats:
    lines: int = 0
    alerts: int = 0
    non_alert: int = 0
    malformed: int = 0
    accepted: int = 0
    duplicate: int = 0
    rejected: dict[str, int] = field(default_factory=dict)
    retries: int = 0

    def reject(self, code: str) -> None:
        self.rejected[code] = self.rejected.get(code, 0) + 1

    def summary(self) -> str:
        rej = ", ".join(f"{k}={v}" for k, v in sorted(self.rejected.items())) or "0"
        return (f"lines={self.lines} alerts={self.alerts} non_alert={self.non_alert} malformed={self.malformed} "
                f"accepted={self.accepted} duplicate={self.duplicate} rejected={rej} retries={self.retries}")


def _error_code(r: httpx.Response) -> str:
    try:
        return str(r.json()["error"]["code"])
    except Exception:
        return f"HTTP_{r.status_code}"


def _retry_after(r: httpx.Response) -> float | None:
    v = r.headers.get("retry-after")
    if not v:
        return None
    try:
        return min(MAX_RETRY_AFTER_S, max(0.0, float(v)))
    except ValueError:
        pass
    try:
        return min(MAX_RETRY_AFTER_S, max(0.0, parsedate_to_datetime(v).timestamp() - time.time()))
    except (TypeError, ValueError):
        return None


def _default_signer(source: str, body: bytes) -> dict[str, str]:
    from scripts.sign import sign  # settings (HMAC_SECRETS) are read on first use, after .env was loaded
    return sign(source, body)


class Poster:
    """Sends Envelopes, signed per request (fresh timestamp on every attempt). Transient failures (connection errors,
    429 with Retry-After, 503 ENGINE_UNAVAILABLE / other 5xx) are retried with capped exponential backoff + jitter,
    forever; permanent refusals (401/403/413/422/...) of a line are logged and the line is skipped."""

    def __init__(self, client: httpx.Client, *, signer: Callable[[str, bytes], dict[str, str]] = _default_signer,
                 stats: Stats | None = None, backoff_base: float = 0.5, backoff_cap: float = 30.0,
                 sleep: Callable[[float], None] = time.sleep, rand: Callable[[], float] = random.random) -> None:
        self.client = client
        self.signer = signer
        self.stats = stats or Stats()
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap
        self.sleep = sleep
        self.rand = rand

    def _backoff(self, attempt: int) -> float:
        d = min(self.backoff_cap, self.backoff_base * (2 ** attempt))
        return d * (0.5 + self.rand() / 2)              # "equal jitter": between d/2 and d

    def _send(self, path: str, body: bytes) -> httpx.Response:
        """POST until the answer is not transient; returns that response."""
        attempt = 0
        while True:
            try:
                r = self.client.post(path, content=body, headers=self.signer(SOURCE, body))
            except httpx.TransportError as e:
                delay, why = self._backoff(attempt), f"{type(e).__name__}: {e}"
            else:
                if r.status_code not in RETRY_STATUS:
                    return r
                ra = _retry_after(r)
                delay = ra if ra is not None else self._backoff(attempt)
                why = f"{r.status_code} {_error_code(r)}"
            self.stats.retries += 1
            log.warning("POST %s failed (%s); retrying in %.1fs", path, why, delay)
            self.sleep(delay)
            attempt += 1

    def post_one(self, env: Envelope) -> None:
        r = self._send("/v1/events", env.model_dump_json().encode())
        if r.status_code == 202:
            self.stats.accepted += 1
        elif r.status_code == 409:
            self.stats.duplicate += 1
        else:
            code = _error_code(r)
            self.stats.reject(code)
            log.error("event %s (sid %s) refused: %s %s; line skipped", env.event_id, env.payload.get("signature_id"),
                      r.status_code, code)

    def post_batch(self, envs: list[Envelope]) -> None:
        pending, attempt = list(envs), 0
        while pending:
            body = json.dumps({"events": [e.model_dump(mode="json") for e in pending]}).encode()
            r = self._send("/v1/events/batch", body)
            if r.status_code != 202:
                log.error("batch of %d refused: %s %s; sending its events one by one", len(pending), r.status_code, _error_code(r))
                for e in pending:
                    self.post_one(e)
                return
            data = r.json()
            self.stats.accepted += int(data.get("accepted", 0))
            retry: set[str] = set()
            for item in data.get("rejected", []):
                code = str(item.get("code"))
                if code == "ENGINE_UNAVAILABLE":            # backlog filled mid-batch: not stored, send again
                    retry.add(str(item.get("event_id")))
                elif code == "DUPLICATE_EVENT":
                    self.stats.duplicate += 1
                else:
                    self.stats.reject(code)
                    log.error("event %s refused in batch: %s; line skipped", item.get("event_id"), code)
            pending = [e for e in pending if e.event_id in retry]
            if pending:
                delay = self._backoff(attempt)
                self.stats.retries += 1
                log.warning("%d event(s) hit ENGINE_UNAVAILABLE; retrying in %.1fs", len(pending), delay)
                self.sleep(delay)
                attempt += 1

    def post(self, envs: list[Envelope], batch: int) -> None:
        if not envs:
            return
        if batch <= 1:
            for e in envs:
                self.post_one(e)
        else:
            for i in range(0, len(envs), batch):
                self.post_batch(envs[i:i + batch])


# ---------------------------------------------------------------- follower


class Follower:
    """Glue: tailer lines -> Envelopes -> poster, committing (offset, file identity) after each successful post."""

    def __init__(self, tailer: EveTailer, poster: Poster, state_file: str | os.PathLike | None, batch: int = 100) -> None:
        self.tailer = tailer
        self.poster = poster
        self.stats = poster.stats
        self.state_file = state_file
        self.batch = max(1, min(MAX_BATCH, batch))
        self.committed = TailState(str(tailer.path), tailer.offset, tailer.ident)

    def commit(self, offset: int) -> None:
        new = TailState(str(self.tailer.path), offset, self.tailer.ident)
        if new == self.committed:
            return
        self.committed = new
        if self.state_file is not None:
            new.save(self.state_file)

    def _to_envelope(self, raw: bytes) -> Envelope | None:
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return None
        self.stats.lines += 1
        try:
            env = eve_to_envelope(text)
        except Exception as e:                            # bad JSON, missing fields, bad timestamp, not an object…
            self.stats.malformed += 1
            log.warning("malformed eve line skipped (%s: %s)", type(e).__name__, str(e)[:120])
            return None
        if env is None:
            self.stats.non_alert += 1
            return None
        self.stats.alerts += 1
        return env

    def process(self, lines: Iterable[tuple[bytes, int]]) -> int:
        """Post the alerts among `lines`, committing after every flushed group. Returns lines seen."""
        pending: list[Envelope] = []
        last_end = None
        n = 0
        for raw, end in lines:
            n += 1
            env = self._to_envelope(raw)
            if env is not None:
                pending.append(env)
            last_end = end
            if len(pending) >= self.batch:
                self.poster.post(pending, self.batch)
                pending = []
                self.commit(end)
        if pending:
            self.poster.post(pending, self.batch)
        if last_end is not None:
            self.commit(last_end)
        return n

    def step(self) -> int:
        lines = self.tailer.poll()
        n = self.process(lines)
        if not lines:
            self.commit(self.tailer.offset)    # e.g. an oversized line was skipped, or the file was rotated/truncated
        return n

    def run(self, poll: float = 0.5, once: bool = False, sleep: Callable[[float], None] = time.sleep,
            report_every: float = 60.0) -> None:
        last_report = time.monotonic()
        while True:
            n = self.step()
            if n:
                continue                           # more may already be waiting (reads are chunked)
            if once:
                return
            if time.monotonic() - last_report >= report_every:
                log.info("%s", self.stats.summary())
                last_report = time.monotonic()
            sleep(poll)


# --------------------------------------------------------------------- CLI


def _arg(argv: list[str], name: str, default: str | None) -> str | None:
    if name in argv:
        i = argv.index(name)
        if i + 1 >= len(argv):
            raise SystemExit(f"{name} needs a value")
        return argv[i + 1]
    return default


def main(argv: list[str]) -> int:
    if not argv or argv[0].startswith("-"):
        print(__doc__)
        return 2
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    import scripts._env  # noqa: F401  (loads .env so HMAC_SECRETS is available before settings are read)

    path = argv[0]
    api = _arg(argv, "--api", os.getenv("FM_API", "http://127.0.0.1:8000")).rstrip("/")
    state_file = _arg(argv, "--state", "data/suricata_live.state")
    batch = int(_arg(argv, "--batch", "100"))
    poll = float(_arg(argv, "--poll", "0.5"))
    once = "--once" in argv
    from_start = "--from-start" in argv

    saved = TailState.load(state_file, path)
    if saved is not None:
        tailer = EveTailer(path, offset=saved.offset, ident=saved.ident)
        log.info("resuming %s at byte %d (state %s)", path, saved.offset, state_file)
    else:
        tailer = EveTailer(path, start_at_end=not from_start)
    if once and not os.path.exists(path):
        log.error("%s does not exist", path)
        return 1
    if not os.path.exists(path):
        log.info("waiting for %s to appear", path)

    with httpx.Client(base_url=api, timeout=10, **httpx_kwargs(SOURCE)) as client:
        follower = Follower(tailer, Poster(client), state_file, batch=batch)
        log.info("posting alerts to %s (%s)", api, "/v1/events/batch" if follower.batch > 1 else "/v1/events")
        try:
            follower.run(poll=poll, once=once)
        except KeyboardInterrupt:
            follower.committed.save(state_file)   # already saved at every commit; written again so it surely exists
            log.info("interrupted; state saved at byte %d", follower.committed.offset)
            print(follower.stats.summary())
            return 130
    print(follower.stats.summary())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
