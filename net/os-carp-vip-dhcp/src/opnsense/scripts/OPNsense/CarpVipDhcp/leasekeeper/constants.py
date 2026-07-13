"""Protocol codes, timing tunables and the phase / message-type tables.

Pure literals with no imports, so every other module can depend on this one.
"""

# DHCP message types (RFC 2131).
OFFER, ACK, NAK = 2, 5, 6
BOOTREPLY = 2              # BOOTP op field: a server->client reply (unrelated to OFFER)

# Options we ask the server to include on every DISCOVER/REQUEST (RFC 2132 option
# 55, Parameter Request List). Subnet mask (1) + router (3) drive follow mode's
# cross-subnet decision; lease/server-id/T1/T2 (51/54/58/59) drive renew timing.
# Many servers return ONLY options named in the PRL, so without this the keeper
# can silently miss the mask/router it needs to follow a cross-subnet renumber.
PARAM_REQ_LIST = [1, 3, 51, 54, 58, 59]

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
MIN_FOLLOW_INTERVAL = 60   # min seconds between follow (VIP rewrite) events -- damps flap/spoof storms
FOLLOW_RETRY_DEADLINE = 120  # re-drive follow_update if we are not restarted within this after firing
T1_FACTOR = 0.5            # renew at this fraction of the lease (RFC default)
T2_FACTOR = 0.875          # rebind by this fraction of the lease (RFC default)
MIN_T1 = 30                # floor for the renew timer (very short leases)
MIN_LEASE = 2 * MIN_T1     # floor for an accepted lease time, so a tiny (even hostile) opt-51 can't spin renews
REBIND_MARGIN = 15         # ensure T2 is at least this far past T1
BROADCAST_FLAG = 0x8000    # BOOTP flags: ask the server to broadcast OFFER/ACK
ETHER_BROADCAST = "ff:ff:ff:ff:ff:ff"
ETHER_ZERO = "00:00:00:00:00:00"     # ARP "target unknown" hardware address
IPV4_BROADCAST = "255.255.255.255"   # limited broadcast (never routed off-link)
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
ARP_NUDGE_MIN = 30         # floor for --arp-nudge so a typo cannot flood the segment
LOG_MAX_BYTES = 512 * 1024
LOG_BACKUPS = 3

# Changed-address phase labels: which exchange saw the differing ACK. Log
# text and policy input at once -- FollowPolicy relaxes its expected-server
# check on PHASE_REBIND (at T2 any server may legitimately answer).
PHASE_DORA = "DORA"
PHASE_REBOOT = "REBOOT"
PHASE_RENEW = "RENEW"
PHASE_REBIND = "REBIND"
PHASE_OBSERVED = "OBSERVED"

# DHCP message-type names (option 53), for readable reply logging.
MTYPE_NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
               5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
