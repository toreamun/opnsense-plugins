"""Pure helpers: MAC/IP/mask conversions, address classification, filesystem-safe
tokens, jitter, atomic writes and clock formatting -- plus one small stateful
utility, _RateLimit, for throttling noisy log lines.

No project dependencies (stdlib only), so anything can import from here.
"""
import ipaddress
import os
import random
import re
import time

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

# Shared sentinel: a unique object distinct from every real value AND from None,
# for the two places None is itself meaningful -- "argument not supplied" keyword
# defaults (an optional CARP-role probe result) and "no state recorded yet"
# markers. One canonical object so identity/equality checks agree across modules;
# policy / route / keeper import it rather than each minting their own.
_UNSET = object()


class _RateLimit:
    """Monotonic-time throttle for noisy, possibly attacker-driven log lines.
    ready() returns (ok, suppressed): ok is True at most once per `interval`
    seconds, and suppressed is how many calls were dropped since the previous ok
    -- so a malformed-packet or spoof storm collapses to one line per interval
    that also reports how much it hid, instead of churning the log. Single-thread
    use only (the call sites are the capture/main threads that already own their
    logging); it holds no lock."""

    def __init__(self, interval):
        self._interval = interval
        self._deadline = 0.0   # monotonic; 0 => the first call is always allowed
        self._suppressed = 0

    def ready(self):
        """(ok, suppressed): ok True at most once per interval; suppressed is 0
        while inside a window and, on the ok call, the count hidden since the
        previous ok."""
        now = time.monotonic()
        if now >= self._deadline:
            dropped, self._suppressed = self._suppressed, 0
            self._deadline = now + self._interval
            return True, dropped
        self._suppressed += 1
        return False, 0

    def emit(self, log_fn, fmt, *args):
        """Log `fmt % args` through log_fn at most once per interval, appending a
        "(+N more suppressed)" note when calls were dropped since the last emit --
        so the throttle and the suppressed-count wording live in one place instead
        of at each call site."""
        ok, dropped = self.ready()
        if ok:
            suffix = f" (+{dropped} more suppressed)" if dropped else ""
            log_fn(fmt + "%s", *args, suffix)

    def reset(self):
        """Start a fresh window: the next ready() waits a full interval again. Used
        when another line has just conveyed the same state (an immediate INFO on a
        change), so the throttled periodic repeat should not fire right after it."""
        self._deadline = time.monotonic() + self._interval
        self._suppressed = 0


_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _mask_to_bits(mask):
    """Dotted-quad subnet mask (DHCP option 1) -> prefix length, or None if absent
    or unparseable."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except (ValueError, TypeError):
        return None


def _sane_ipv4(ip):
    """True for a plausible host IPv4 lease address (rejects 0.0.0.0, multicast,
    reserved, loopback and link-local) -- used to avoid rewriting the CARP VIP
    from a malformed or rogue ACK."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (addr.version == 4 and not addr.is_unspecified and not addr.is_multicast
            and not addr.is_reserved and not addr.is_loopback and not addr.is_link_local)


def _is_localish(ip):
    """True if the address is private (RFC 1918) or CGNAT (RFC 6598) -- i.e. not a
    globally routable public address (independent of the Python version's view of
    CGNAT)."""
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr in _CGNAT


def _same_ip_class(a, b):
    """True if a and b are in the same routability class (both local-ish or both
    public). A follow that crosses classes (e.g. CGNAT -> a public IP) is almost
    certainly a spoofed/rogue ACK, not a legitimate reassignment."""
    try:
        return _is_localish(a) == _is_localish(b)
    except ValueError:
        return False


def _fs_safe(s):
    """Filesystem-safe token (keeperconf.keeper_id mirrors this charset for
    the configd scripts)."""
    return re.sub(r"[^A-Za-z0-9]", "_", s or "")


def _new_xid():
    """A fresh random transaction id (nonzero 32-bit, regenerated per exchange
    so stale replies cannot match)."""
    return random.randint(1, 0xFFFFFFFF)


def _jittered(base):
    """A retransmit/backoff delay with +/-25% uniform jitter (RFC 2131 4.1
    recommends a randomized backoff). Both HA nodes share the chaddr, so
    jittering the acquire and REBIND retransmit cadences keeps them from
    broadcasting in lockstep and colliding at the server. (The T1/T2 lease
    timers are deterministic and shared too, but jittering those is a
    lease-timing change, not a 4.1 retransmit concern, so they stay exact.)"""
    return base * random.uniform(0.75, 1.25)


def mac2raw(m):
    """Colon/dash-separated MAC string -> 6 raw bytes (BOOTP chaddr)."""
    return bytes.fromhex(m.replace(":", "").replace("-", ""))


def _atomic_write(path, content):
    """Write via tmp + rename so a crash mid-write cannot leave a partial file."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def _clock_at(offset):
    """Local wall-clock HH:MM of a moment `offset` seconds from now. Log
    lines state future moments (renew/rebind/lease expiry) as relative
    durations; the clock time saves the reader the mental arithmetic."""
    return time.strftime("%H:%M", time.localtime(time.time() + offset))
