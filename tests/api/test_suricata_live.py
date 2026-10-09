"""Live Suricata follower (api/adapters/suricata_live.py): tailer, state, poster. No API or Postgres: a temp eve.json
and an httpx.MockTransport that checks the PRD §7.2 signature like the API does."""
from __future__ import annotations

import json
import os
import time

import httpx
import pytest

from api.adapters.suricata_live import EveTailer, Follower, Poster, Stats, TailState, main
from api.signing import signature
from tests.api.conftest import TEST_HMAC


def alert(sid: int, ip: str = "185.220.101.7") -> str:
    return json.dumps({"timestamp": "2026-10-09T00:39:00.000000+0530", "event_type": "alert", "src_ip": ip,
                       "src_port": 51544, "dest_ip": "10.0.1.20", "dest_port": 443, "proto": "TCP",
                       "alert": {"signature_id": sid, "signature": f"sig {sid}", "category": "Attempted User Privilege Gain",
                                 "severity": 2}})


FLOW = json.dumps({"timestamp": "2026-10-09T00:39:04.512000+0530", "event_type": "flow", "src_ip": "1.2.3.4"})


def append(path, *lines: str, newline: bool = True) -> None:
    with open(path, "a", encoding="utf-8", newline="") as f:
        f.write("\n".join(lines) + ("\n" if newline else ""))


class FakeApi:
    """Records accepted events; `script` is a list of responses (or exceptions) used before normal behaviour."""

    def __init__(self, script: list | None = None, reject_sids: set[int] | None = None) -> None:
        self.script = list(script or [])
        self.reject_sids = reject_sids or set()
        self.requests: list[httpx.Request] = []
        self.events: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = request.content
        h = request.headers
        assert h["x-fm-source"] == "network-ids"
        assert abs(int(h["x-fm-timestamp"]) - time.time()) < 300
        assert h["x-fm-signature"] == signature(TEST_HMAC["network-ids"], h["x-fm-timestamp"], body)
        if self.script:
            nxt = self.script.pop(0)
            if isinstance(nxt, Exception):
                raise nxt
            return nxt
        data = json.loads(body)
        if request.url.path == "/v1/events":
            if data["payload"]["signature_id"] in self.reject_sids:
                return httpx.Response(422, json={"error": {"code": "VALIDATION_FAILED", "message": "x", "request_id": "r"}})
            self.events.append(data)
            return httpx.Response(202, json={"event_id": data["event_id"], "status": "accepted"})
        assert request.url.path == "/v1/events/batch"
        rejected = []
        for e in data["events"]:
            if e["payload"]["signature_id"] in self.reject_sids:
                rejected.append({"event_id": e["event_id"], "code": "VALIDATION_FAILED"})
            else:
                self.events.append(e)
        return httpx.Response(202, json={"accepted": len(data["events"]) - len(rejected), "rejected": rejected})

    def sids(self) -> list[int]:
        return [e["payload"]["signature_id"] for e in self.events]


def make(tmp_path, api: FakeApi, batch: int = 1, from_start: bool = True, state: bool = True):
    eve = tmp_path / "eve.json"
    state_file = tmp_path / "data" / "live.state"
    saved = TailState.load(state_file, str(eve)) if state else None
    tailer = EveTailer(eve, offset=saved.offset, ident=saved.ident) if saved else EveTailer(eve, start_at_end=not from_start)
    sleeps: list[float] = []
    client = httpx.Client(base_url="http://fm.test", transport=httpx.MockTransport(api.handler))
    poster = Poster(client, stats=Stats(), sleep=sleeps.append, rand=lambda: 1.0)
    return eve, state_file, Follower(tailer, poster, state_file, batch=batch), sleeps


# ------------------------------------------------------------------ tailer


def test_follows_appended_lines_and_waits_for_missing_file(tmp_path):
    api = FakeApi()
    eve, _, f, _ = make(tmp_path, api)
    assert f.step() == 0                                # file does not exist yet: wait
    append(eve, alert(1))
    f.step()
    append(eve, alert(2), alert(3))
    f.step()
    assert f.step() == 0
    assert api.sids() == [1, 2, 3]
    assert all(e["event_type"] == "network_ids_alert" and e["source"] == "network-ids" for e in api.events)


def test_partial_line_waits_for_newline(tmp_path):
    api = FakeApi()
    eve, _, f, _ = make(tmp_path, api)
    line = alert(7)
    append(eve, line[:40], newline=False)
    assert f.step() == 0 and api.events == []
    append(eve, line[40:])
    f.step()
    assert api.sids() == [7]


def test_rotation_reopens_new_file_from_start(tmp_path):
    api = FakeApi()
    eve, _, f, _ = make(tmp_path, api)
    append(eve, alert(1), alert(2), alert(3))
    f.step()
    os.replace(eve, tmp_path / "eve.json.1")             # logrotate: rename, then the sensor writes a new file
    append(eve, alert(10))
    f.step()
    assert api.sids() == [1, 2, 3, 10]
    assert f.tailer.rotations == 1


def test_truncation_restarts_at_zero(tmp_path):
    api = FakeApi()
    eve, _, f, _ = make(tmp_path, api)
    append(eve, alert(1), alert(2))
    f.step()
    with open(eve, "w", encoding="utf-8", newline="") as fh:   # copytruncate
        fh.write(alert(20) + "\n")
    f.step()
    assert api.sids() == [1, 2, 20]
    assert f.tailer.truncations == 1


def test_non_alert_and_malformed_lines_skipped(tmp_path):
    api = FakeApi()
    eve, _, f, _ = make(tmp_path, api)
    append(eve, FLOW, "{not json", "[1, 2]", json.dumps({"event_type": "alert"}), "", alert(5))
    f.step()
    assert api.sids() == [5]
    s = f.stats
    assert (s.non_alert, s.malformed, s.alerts) == (1, 3, 1)


def test_default_starts_at_end_of_file(tmp_path):
    api = FakeApi()
    eve = tmp_path / "eve.json"
    append(eve, alert(1), alert(2))
    append(eve, alert(3)[:30], newline=False)           # half-written line at startup is read once complete
    _, _, f, _ = make(tmp_path, api, from_start=False)
    f.step()
    append(eve, alert(3)[30:], alert(4))
    f.step()
    assert api.sids() == [3, 4]


def test_oversized_line_is_skipped(tmp_path):
    api = FakeApi()
    eve = tmp_path / "eve.json"
    client = httpx.Client(base_url="http://fm.test", transport=httpx.MockTransport(api.handler))
    f = Follower(EveTailer(eve, read_chunk=600), Poster(client, sleep=lambda s: None), None)
    append(eve, "x" * 3000, alert(9))
    for _ in range(10):
        f.step()
    assert api.sids() == [9] and f.tailer.oversized == 1


# ------------------------------------------------------------------- state


def test_state_resume_no_resend_no_skip(tmp_path):
    api = FakeApi()
    eve, state_file, f, _ = make(tmp_path, api)
    append(eve, alert(1), alert(2))
    f.step()
    saved = json.loads(state_file.read_text())
    assert saved["offset"] == eve.stat().st_size and saved["ident"]
    append(eve, alert(3))                                # written while the follower was down
    _, _, f2, _ = make(tmp_path, api, from_start=False)  # restart: state wins over "start at end"
    f2.step()
    append(eve, alert(4))
    f2.step()
    assert api.sids() == [1, 2, 3, 4]


def test_offset_not_committed_when_post_interrupted(tmp_path):
    api = FakeApi(script=[httpx.Response(503, json={"error": {"code": "ENGINE_UNAVAILABLE"}})])
    eve, state_file, f, _ = make(tmp_path, api)
    append(eve, alert(1))
    f.step()
    first = json.loads(state_file.read_text())["offset"]
    append(eve, alert(2))

    def boom(_delay):
        raise KeyboardInterrupt
    f.poster.sleep = boom
    api.script = [httpx.Response(503, json={"error": {"code": "ENGINE_UNAVAILABLE"}})]
    with pytest.raises(KeyboardInterrupt):
        f.step()
    assert json.loads(state_file.read_text())["offset"] == first      # alert 2 will be re-read after restart
    _, _, f2, _ = make(tmp_path, api)
    f2.step()
    assert api.sids() == [1, 2]


def test_rotation_while_down_reads_new_file_from_start(tmp_path):
    api = FakeApi()
    eve, _, f, _ = make(tmp_path, api)
    append(eve, alert(1), alert(2), alert(3))
    f.step()
    os.replace(eve, tmp_path / "eve.json.1")
    append(eve, alert(4))
    _, _, f2, _ = make(tmp_path, api)
    f2.step()
    assert api.sids() == [1, 2, 3, 4]


def test_state_for_another_path_is_ignored(tmp_path):
    state_file = tmp_path / "s.state"
    TailState(str(tmp_path / "other.json"), 99, (1, 2)).save(state_file)
    assert TailState.load(state_file, str(tmp_path / "eve.json")) is None
    state_file.write_text("garbage")
    assert TailState.load(state_file, str(tmp_path / "eve.json")) is None


# ------------------------------------------------------------------ poster


def test_single_mode_uses_events_endpoint(tmp_path):
    api = FakeApi()
    eve, _, f, _ = make(tmp_path, api, batch=1)
    append(eve, alert(1), alert(2))
    f.step()
    assert [r.url.path for r in api.requests] == ["/v1/events", "/v1/events"]
    assert f.stats.accepted == 2


def test_batch_mode_uses_batch_endpoint(tmp_path):
    api = FakeApi()
    eve, _, f, _ = make(tmp_path, api, batch=2)
    append(eve, alert(1), FLOW, alert(2), alert(3))
    f.step()
    assert [r.url.path for r in api.requests] == ["/v1/events/batch", "/v1/events/batch"]
    assert [len(json.loads(r.content)["events"]) for r in api.requests] == [2, 1]
    assert api.sids() == [1, 2, 3] and f.stats.accepted == 3


def test_batch_size_capped_at_500(tmp_path):
    api = FakeApi()
    _, _, f, _ = make(tmp_path, api, batch=10_000)
    assert f.batch == 500


@pytest.mark.parametrize("batch", [1, 3])
def test_retry_on_503_429_and_connection_error_then_success(tmp_path, batch):
    api = FakeApi(script=[
        httpx.ConnectError("refused"),
        httpx.Response(503, json={"error": {"code": "ENGINE_UNAVAILABLE", "message": "full", "request_id": "r"}}),
        httpx.Response(429, headers={"Retry-After": "7"}, json={"error": {"code": "RATE_LIMITED"}}),
    ])
    eve, state_file, f, sleeps = make(tmp_path, api, batch=batch)
    append(eve, alert(1))
    f.step()
    assert api.sids() == [1]
    assert len(api.requests) == 4 and f.stats.retries == 3
    assert sleeps == [0.5, 1.0, 7.0]                     # backoff (rand=1 -> full delay), then Retry-After
    assert json.loads(state_file.read_text())["offset"] == eve.stat().st_size
    sigs = {r.headers["x-fm-signature"] for r in api.requests}
    assert len(sigs) >= 1                                # every attempt is (re)signed and verified by FakeApi


def test_backoff_is_capped(tmp_path):
    p = Poster(httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(202))), backoff_base=1, backoff_cap=30,
               rand=lambda: 1.0)
    assert p._backoff(20) == 30
    assert 15 <= Poster(p.client, backoff_cap=30, backoff_base=1, rand=lambda: 0.0)._backoff(20) <= 30


def test_401_and_422_line_skipped(tmp_path):
    api = FakeApi(script=[httpx.Response(401, json={"error": {"code": "SIGNATURE_INVALID", "message": "x", "request_id": "r"}})],
                  reject_sids={2})
    eve, state_file, f, _ = make(tmp_path, api, batch=1)
    append(eve, alert(1), alert(2), alert(3))
    f.step()
    assert api.sids() == [3]
    assert f.stats.rejected == {"SIGNATURE_INVALID": 1, "VALIDATION_FAILED": 1}
    assert len(api.requests) == 3                        # no retry loop on permanent refusals
    assert json.loads(state_file.read_text())["offset"] == eve.stat().st_size


def test_batch_level_401_falls_back_to_single_posts(tmp_path):
    api = FakeApi(script=[httpx.Response(401, json={"error": {"code": "STALE_TIMESTAMP"}})])
    eve, _, f, _ = make(tmp_path, api, batch=5)
    append(eve, alert(1), alert(2))
    f.step()
    assert [r.url.path for r in api.requests] == ["/v1/events/batch", "/v1/events", "/v1/events"]
    assert api.sids() == [1, 2]


def test_batch_items_hit_by_full_backlog_are_resent(tmp_path):
    api = FakeApi()
    eve, _, f, sleeps = make(tmp_path, api, batch=5)
    append(eve, alert(1), alert(2))
    real = api.handler

    def first_partial(request):
        api.handler = real
        data = json.loads(request.content)
        api.requests.append(request)
        api.events.append(data["events"][0])
        return httpx.Response(202, json={"accepted": 1, "rejected": [
            {"event_id": data["events"][1]["event_id"], "code": "ENGINE_UNAVAILABLE"}]})
    api.script = []
    f.poster.client = httpx.Client(base_url="http://fm.test", transport=httpx.MockTransport(lambda r: api.handler(r)))
    api.handler = first_partial
    f.step()
    assert api.sids() == [1, 2] and len(sleeps) == 1
    resent = json.loads(api.requests[-1].content)["events"]
    assert len(resent) == 1                              # only the refused one, same event_id
    assert resent[0]["event_id"] == api.events[1]["event_id"]


def test_409_counts_as_delivered(tmp_path):
    api = FakeApi(script=[httpx.Response(409, json={"error": {"code": "DUPLICATE_EVENT"}})])
    eve, state_file, f, _ = make(tmp_path, api)
    append(eve, alert(1))
    f.step()
    assert f.stats.duplicate == 1 and not f.stats.rejected
    assert json.loads(state_file.read_text())["offset"] == eve.stat().st_size


def test_signature_headers_verify(tmp_path):
    api = FakeApi()
    eve, _, f, _ = make(tmp_path, api, batch=2)
    append(eve, alert(1), alert(2))
    f.step()
    (r,) = api.requests
    ts = r.headers["x-fm-timestamp"]
    assert r.headers["x-fm-source"] == "network-ids"
    assert r.headers["x-fm-signature"] == signature(TEST_HMAC["network-ids"], ts, r.content)
    assert r.headers["content-type"] == "application/json"


def test_cli_once_end_to_end(tmp_path, monkeypatch):
    api = FakeApi()
    eve = tmp_path / "eve.json"
    append(eve, alert(1), FLOW, alert(2))
    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(base_url=kw["base_url"], transport=httpx.MockTransport(api.handler)))
    state = tmp_path / "st" / "s.state"
    assert main([str(eve), "--from-start", "--once", "--state", str(state), "--batch", "1"]) == 0
    assert api.sids() == [1, 2]
    assert main([str(eve), "--once", "--state", str(state)]) == 0           # resume: nothing new, nothing resent
    assert api.sids() == [1, 2]
    assert main([str(tmp_path / "missing.json"), "--once", "--state", str(state)]) == 1
