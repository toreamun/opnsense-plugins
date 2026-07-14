"""Protocol codes, timing tunables and the phase labels.

Only the stdlib enum import; every other module depends on this one.
"""
from enum import IntEnum, StrEnum

# The daemon's single shared logger name; getLogger(LOGGER_NAME) in every
# module, so a mistyped literal cannot spawn a second handler-less logger.
LOGGER_NAME = "lease-keeper"


class MsgType(IntEnum):
    """DHCP message types (RFC 2131 option 53). One table serves the wire code,
    the readable name (logging, via mtype_name) and equality checks; codec's
    send-side code map derives its values from here too."""
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8


# Aliases for the types the code compares against by bare name.
OFFER, ACK, NAK = MsgType.OFFER, MsgType.ACK, MsgType.NAK


class BootpOp(IntEnum):
    """BOOTP op field (RFC 951): client-to-server messages are REQUEST, the
    server's answers are REPLY. Distinct from the DHCP message type -- every
    DORA packet is a BOOTREQUEST whether it is a DISCOVER or a REQUEST, so a
    received frame must carry REPLY to be one of ours."""
    REQUEST = 1
    REPLY = 2


class ArpOp(IntEnum):
    """ARP operation codes (RFC 826): the nudge sends a REQUEST, and only a
    REPLY (is-at) counts as the gateway's reachability confirmation."""
    REQUEST = 1
    REPLY = 2


class DhcpOpt(IntEnum):
    """DHCP option codes (RFC 2132) for exactly the options the keeper sends or
    reads, plus the two options-field markers (PAD/END). Names the wire numbers
    that would otherwise be magic literals in the codec's encoder/decoder tables
    and the parameter request list."""
    PAD = 0
    SUBNET_MASK = 1
    ROUTER = 3
    HOSTNAME = 12
    REQUESTED_ADDR = 50
    LEASE_TIME = 51
    MESSAGE_TYPE = 53
    SERVER_ID = 54
    PARAM_REQ_LIST = 55
    MESSAGE = 56
    RENEWAL_TIME = 58
    REBINDING_TIME = 59
    VENDOR_CLASS_ID = 60
    CLIENT_ID = 61
    END = 255


def mtype_name(code):
    """Readable DHCP message-type name for logging; falls back to type=<n> for a
    code not in MsgType (the reply is untrusted wire input)."""
    try:
        return MsgType(code).name
    except ValueError:
        return f"type={code}"


# Bound for joining a helper thread on stop (both capture backends): a stuck
# reader/sniffer is left to exit on its own rather than hang the main thread.
THREAD_JOIN_TIMEOUT = 2

# Options we ask the server to include on every DISCOVER/REQUEST (RFC 2132 option
# 55, Parameter Request List). Subnet mask + router drive follow mode's
# cross-subnet decision; lease/server-id/T1/T2 drive renew timing. Many servers
# return ONLY options named in the PRL, so without this the keeper can silently
# miss the mask/router it needs to follow a cross-subnet renumber.
PARAM_REQ_LIST = [DhcpOpt.SUBNET_MASK, DhcpOpt.ROUTER, DhcpOpt.LEASE_TIME,
                  DhcpOpt.SERVER_ID, DhcpOpt.RENEWAL_TIME, DhcpOpt.REBINDING_TIME]

# Timing / retry tunables (seconds unless noted).
HB_REFRESH = 30            # rewrite the heartbeat at least this often while holding a lease
DEFAULT_LEASE = 3600       # fallback lease time if the server sends none
DORA_ATTEMPTS = 5          # DISCOVER and REQUEST attempts per acquire
REBOOT_ATTEMPTS = 2        # INIT-REBOOT REQUEST attempts before falling back to a full DISCOVER
RENEW_ATTEMPTS = 3         # REQUEST attempts per renew
REPLY_TIMEOUT = 4          # wait for an OFFER/ACK during acquire
RENEW_TIMEOUT = 3          # wait for an ACK during renew
ATTEMPT_BACKOFF_CAP = 8    # max wait between acquire attempts
SEND_RETRY_DELAY = 2       # wait after a failed packet send before retrying
REBIND_POLL_STEP = 10      # how often to re-try RENEW during the REBIND window
REDORA_MIN = 10            # initial wait after a failed acquire; also the hold-poll cadence while no carrier
# Caps worst-case re-acquire lag at ~45s even if the link-return fast path (below)
# is missed; the backoff doubles 10 -> 20 -> 40 -> 45.
REDORA_MAX = 45            # max exponential-backoff wait after a failed acquire
LINK_POLL_STEP = 3         # while UNBOUND, poll interface carrier this often (s) for the link-return fast path
LINK_KICK_DEBOUNCE = 8     # min seconds between link-return re-DORA kicks (damps a flapping link)
SNIFFER_RETRY = 5          # wait before retrying a failed packet-sniffer start
SNIFFER_WARMUP = 0.5       # let the capture thread attach before the first send
LOOP_ERROR_BACKOFF = 10    # wait after an unexpected main-loop error before retrying

# Follow (VIP-rewrite) throttle + apply-retry.
MIN_FOLLOW_INTERVAL = 60   # min seconds between follow (VIP rewrite) events -- damps flap/spoof storms
FOLLOW_RETRY_DEADLINE = 120  # re-drive follow_update if we are not restarted within this after firing

# Lease-timer math (RFC 2131 defaults + floors).
T1_FACTOR = 0.5            # renew at this fraction of the lease (RFC default)
T2_FACTOR = 0.875          # rebind by this fraction of the lease (RFC default)
MIN_T1 = 30                # floor for the renew timer (very short leases)
MIN_LEASE = 2 * MIN_T1     # floor for an accepted lease time, so a tiny (even hostile) opt-51 can't spin renews
REBIND_MARGIN = 15         # ensure T2 is at least this far past T1

# Wire constants (BOOTP flags, Ethernet/IPv4 broadcast, DHCP ports).
BROADCAST_FLAG = 0x8000    # BOOTP flags: ask the server to broadcast OFFER/ACK
ETHER_BROADCAST = "ff:ff:ff:ff:ff:ff"
ETHER_ZERO = "00:00:00:00:00:00"     # ARP "target unknown" hardware address
IPV4_BROADCAST = "255.255.255.255"   # limited broadcast (never routed off-link)
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68

ARP_NUDGE_MIN = 30         # floor for --arp-nudge so a typo cannot flood the segment


class Phase(StrEnum):
    """Which exchange saw a changed ACK -- log text and policy input at once.
    FollowPolicy relaxes its expected-server check on REBIND (at T2 any server
    may legitimately answer). A StrEnum so the member both compares by value and
    formats to its label in log lines."""
    DORA = "DORA"
    REBOOT = "REBOOT"
    RENEW = "RENEW"
    REBIND = "REBIND"
    OBSERVED = "OBSERVED"
