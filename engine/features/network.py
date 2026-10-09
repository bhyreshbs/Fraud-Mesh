"""Network, device-consistency and session-context features (v3 phases 5, 6.1, 6.2). Plugged into FeatureWindows.

Same contract as engine/features/features.py: compute(ev) reads state from EARLIER events only, update(ev) then adds
the event; event time only, never the wall clock. Inputs are the 1.1.0 StoredEvent fields (network_type and
network_confidence from the API's offline enrichment; browser_timezone, platform, webgl_renderer, screen, telemetry
and session from the client). Every field is optional: absent inputs give the neutral value (factor 1.0, flags 0).

Features (floats):
  geo_confidence_factor       multiplier for location evidence: 1.0 unless the ip is vpn/tor/hosting or unknown with
                              low confidence (network_intel.yaml geo_confidence); 1.0 when not enriched
  net_anonymiser              1 if network_type is hosting, vpn or tor
  tz_mismatch                 1 if browser_timezone and ip_timezone are both known and have different UTC offsets now
  device_inconsistency        number of contradictions between platform, pointer type, WebGL renderer and screen
  device_inconsistency_mask   which ones (DEVICE_FLAGS)
  session_seen                1 if this session token was seen before (within ttl_h)
  session_change              1 if, inside one session, the network changed (ASN or network_type) AND the device
                              context changed (device token, platform, WebGL renderer or customer), for a combination
                              not reported before in this session. Wi-Fi <-> mobile with the same device is NOT a change.
  session_change_mask         which parts changed (SESSION_FLAGS)
Memory: at most max_sessions sessions (least recently seen dropped); idle sessions expire after ttl_h.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from engine.contracts import StoredEvent
from engine.netintel.intel import ANONYMISING, geo_confidence_factor

CONFIG_FILE = Path(__file__).resolve().parents[1] / "detectors" / "rules" / "session_device.yaml"

NETWORK_FEATURE_NAMES = ["geo_confidence_factor", "net_anonymiser", "tz_mismatch", "device_inconsistency",
                         "device_inconsistency_mask", "session_seen", "session_change", "session_change_mask"]
DEVICE_FLAGS = {1: "mobile platform with a mouse pointer", 2: "desktop platform with a mobile GPU",
                4: "mobile platform with a desktop GPU", 8: "software WebGL renderer",
                16: "mobile platform with a desktop-sized screen", 32: "platform changed inside the session"}
SESSION_FLAGS = {1: "ASN changed", 2: "network type changed", 4: "device changed", 8: "platform changed",
                 16: "WebGL renderer changed", 32: "customer changed", 64: "now on hosting/vpn/tor"}
MAX_SIGNATURES_PER_SESSION = 16


@lru_cache(maxsize=4)
def load_session_device_config(path: str | Path = CONFIG_FILE) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def describe(mask: float, flags: dict[int, str]) -> str:
    m = int(mask)
    return ", ".join(text for bit, text in flags.items() if m & bit) or "none"


# ---------------------------------------------------------------------------- stateless helpers
def _utc_offset(tz: str, at: datetime) -> timedelta | None:
    try:
        from zoneinfo import ZoneInfo
        return at.astimezone(ZoneInfo(tz)).utcoffset()
    except Exception:                                         # unknown name or no tz database: compare names instead
        return None


def tz_mismatch(browser_tz: str | None, ip_tz: str | None, at: datetime) -> bool:
    if not browser_tz or not ip_tz:
        return False
    a, b = _utc_offset(browser_tz, at), _utc_offset(ip_tz, at)
    if a is not None and b is not None:
        return a != b
    return browser_tz.strip().lower() != ip_tz.strip().lower()


def _has(text: str | None, words: list[str]) -> bool:
    t = (text or "").lower()
    return bool(t) and any(w in t for w in words)


def _short_side(screen: str | None) -> int | None:
    try:
        w, h = (int(float(x)) for x in str(screen).lower().replace("×", "x").split("x")[:2])
        return min(w, h)
    except (ValueError, TypeError):
        return None


def device_mask(ev: StoredEvent, cfg: dict[str, Any], first_platform: str | None = None) -> int:
    c = cfg["device_consistency"]
    mobile = _has(ev.platform, c["mobile_platform"])
    desktop = not mobile and _has(ev.platform, c["desktop_platform"])
    pointer = ev.telemetry.pointer_type if ev.telemetry is not None else None
    mask = 0
    if mobile and pointer == "mouse":
        mask |= 1
    if desktop and _has(ev.webgl_renderer, c["mobile_gpu"]):
        mask |= 2
    if mobile and _has(ev.webgl_renderer, c["desktop_gpu"]):
        mask |= 4
    if _has(ev.webgl_renderer, c["software_gpu"]):
        mask |= 8
    side = _short_side(ev.screen) if mobile else None
    if side is not None and side > int(c["mobile_max_short_side"]):
        mask |= 16
    if first_platform and ev.platform and first_platform != ev.platform:
        mask |= 32
    return mask


# ---------------------------------------------------------------------------- session state
@dataclass
class _Session:
    last_seen: datetime
    network_type: str | None = None
    asn: str | None = None
    device: str | None = None
    platform: str | None = None
    webgl: str | None = None
    customer: str | None = None
    reported: set[tuple] = field(default_factory=set)


def _signature(ev: StoredEvent) -> tuple:
    return (ev.network_type, ev.asn, ev.device, ev.platform, ev.webgl_renderer, ev.customer)


def _changed(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and a != b


def session_change_mask(s: _Session, ev: StoredEvent) -> int:
    mask = 0
    if _changed(s.asn, ev.asn):
        mask |= 1
    if _changed(s.network_type, ev.network_type) and "unknown" not in (s.network_type, ev.network_type):
        mask |= 2
    if _changed(s.device, ev.device):
        mask |= 4
    if _changed(s.platform, ev.platform):
        mask |= 8
    if _changed(s.webgl, ev.webgl_renderer):
        mask |= 16
    if _changed(s.customer, ev.customer):
        mask |= 32
    if mask & 3 and ev.network_type in ANONYMISING and s.network_type not in ANONYMISING:
        mask |= 64
    return mask


def is_suspicious(mask: int) -> bool:
    """Network changed AND device context changed. Network alone (Wi-Fi <-> mobile) or device alone is not enough."""
    return bool(mask & 3) and bool(mask & (4 | 8 | 16 | 32))


class NetworkWindows:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.cfg = load_session_device_config() if config is None else config
        s = self.cfg["session"]
        self.ttl = timedelta(hours=float(s["ttl_h"]))
        self.max_sessions = int(s["max_sessions"])
        self.reset()

    def reset(self) -> None:
        self._sessions: OrderedDict[str, _Session] = OrderedDict()

    def __len__(self) -> int:
        return len(self._sessions)

    def _live(self, ses: str | None, now: datetime) -> _Session | None:
        s = self._sessions.get(ses) if ses else None
        if s is None or now - s.last_seen > self.ttl:
            return None
        return s

    def compute(self, ev: StoredEvent) -> dict[str, float]:
        f = dict.fromkeys(NETWORK_FEATURE_NAMES, 0.0)
        f["geo_confidence_factor"] = geo_confidence_factor(ev.network_type, ev.network_confidence)
        f["net_anonymiser"] = float(ev.network_type in ANONYMISING)
        f["tz_mismatch"] = float(tz_mismatch(ev.browser_timezone, ev.ip_timezone, ev.occurred_at))
        s = self._live(ev.session, ev.occurred_at)
        dm = device_mask(ev, self.cfg, s.platform if s is not None else None)
        f["device_inconsistency"] = float(bin(dm).count("1"))
        f["device_inconsistency_mask"] = float(dm)
        if s is not None:
            f["session_seen"] = 1.0
            sm = session_change_mask(s, ev)
            f["session_change_mask"] = float(sm)
            f["session_change"] = float(is_suspicious(sm) and _signature(ev) not in s.reported)
        return f

    def update(self, ev: StoredEvent) -> None:
        if not ev.session:
            return
        now = ev.occurred_at
        s = self._live(ev.session, now)
        if s is None:
            s = _Session(last_seen=now, network_type=ev.network_type, asn=ev.asn, device=ev.device,
                         platform=ev.platform, webgl=ev.webgl_renderer, customer=ev.customer)
            self._sessions[ev.session] = s
            self._sessions.move_to_end(ev.session)
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
            return
        if is_suspicious(session_change_mask(s, ev)) and len(s.reported) < MAX_SIGNATURES_PER_SESSION:
            s.reported.add(_signature(ev))
        # the first-seen context is kept; attributes the first event did not carry are filled in once
        s.network_type = s.network_type or ev.network_type
        s.asn = s.asn or ev.asn
        s.device = s.device or ev.device
        s.platform = s.platform or ev.platform
        s.webgl = s.webgl or ev.webgl_renderer
        s.customer = s.customer or ev.customer
        s.last_seen = max(s.last_seen, now)
        self._sessions.move_to_end(ev.session)
