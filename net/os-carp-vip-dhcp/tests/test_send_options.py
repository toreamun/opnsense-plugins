"""The operator's Send Options and Request Options in the daemon: the option
list and its wire bytes, the Parameter Request List order, the checks that turn
an unusable setting into a configuration error, and what such an error stops."""
# pylint: disable=protected-access, missing-function-docstring
import types

from conftest import CHADDR_STR

SAGEM = (60, b"sagem")
TOKEN = (90, bytes(range(10)))
NATIVE_ORDER = [1, 28, 51, 58, 59, 119, 3, 6, 90, 15, 120, 125]


def _keeper(lk, **kw):
    """A Keeper on the canonical test identity, with a capture stand-in that
    records every DHCP send (a real bpf fd is not available here)."""
    kw.setdefault("hbfile", None)
    keeper = lk.Keeper("eth0", CHADDR_STR, "100.64.4.7", **kw)
    sent = []
    keeper.sent = sent
    keeper._capture = keeper._dhcp._capture = types.SimpleNamespace(
        send_dhcp=sent.append, start=lambda: True, stop=lambda: None, alive=lambda: True,
        vlan_pcp_error=None)
    keeper._probe_carp_master = lambda: True
    return keeper


def _wire(options):
    return [o for o in options if isinstance(o, tuple)]


# ---- codec and the request list ----

def test_raw_option_is_sent_as_code_and_bytes(lk):
    assert lk._encode_dhcp_options([(90, b"\x01\x02"), "end"]) == bytes([90, 2, 1, 2, 255])


def test_request_list_puts_the_operators_order_first(lk):
    # The order native dhclient sends, then the keeper's own codes it lacks (54).
    assert lk.request_list(NATIVE_ORDER) == NATIVE_ORDER + [54]


def test_request_list_without_request_options_is_the_keepers_own(lk):
    assert lk.request_list() == list(lk.PARAM_REQ_LIST)


def test_request_list_drops_duplicates(lk):
    assert lk.request_list([6, 6, 1]) == [6, 1, 3, 51, 54, 58, 59]


# ---- Send Options in each message type (RFC 2131 table 5) ----

def test_requests_carry_the_send_options_and_request_list(lk):
    keeper = _keeper(lk, send_opts=[SAGEM, TOKEN], request_codes=[119, 6])
    keeper._dhcp._send_dhcp(lk.SendMsgType.DISCOVER, [])
    opts = _wire(keeper.sent[0].options)
    assert SAGEM in opts and TOKEN in opts
    assert (lk.DhcpOptName.PARAM_REQ_LIST, [119, 6, 1, 3, 51, 54, 58, 59]) in opts


def test_release_carries_no_send_options(lk):
    keeper = _keeper(lk, send_opts=[TOKEN])
    keeper._dhcp.release("100.64.4.7", "100.64.4.1")
    assert not [o for o in _wire(keeper.sent[0].options) if isinstance(o[0], int)]


def test_send_options_summary_shows_codes_and_lengths_only(lk):
    keeper = _keeper(lk, send_opts=[SAGEM, TOKEN])
    assert keeper._dhcp.send_options_summary() == "60 (5 bytes), 90 (10 bytes)"
    assert _keeper(lk, send_opts=[(90, b"\x01")])._dhcp.send_options_summary() == "90 (1 byte)"
    assert _keeper(lk)._dhcp.send_options_summary() == ""


# ---- configuration errors ----

def test_option_problem(lk):
    no_ids = []
    vendor = [(lk.DhcpOptName.VENDOR_CLASS_ID, "acme")]
    assert lk.option_problem(no_ids, [SAGEM, TOKEN]) is None
    assert "reserved option 53" in lk.option_problem(no_ids, [(53, b"\x01")])
    assert "twice" in lk.option_problem(no_ids, [TOKEN, TOKEN])
    assert "twice" in lk.option_problem(vendor, [SAGEM])       # the vendor class field sends 60
    assert "0 bytes" in lk.option_problem(no_ids, [(90, b"")])
    assert "256 bytes" in lk.option_problem(no_ids, [(90, b"x" * 256)])
    assert lk.option_problem(no_ids, [(57, b"\x05\xdc")]) is None    # 57 is not reserved


def test_an_identity_option_too_long_to_encode_is_a_config_error_not_a_crash(lk):
    # A hand-edited keeper.conf hostname over 255 bytes cannot be encoded either.
    keeper = _keeper(lk, hostname="h" * 300)
    assert "option 12 is 300 bytes" in keeper._config_error


def test_release_carries_a_client_id_from_send_options(lk):
    # RELEASE carries the client-id the requests used, whichever field it came from.
    cid = (61, b"\x01\x00\x00\x5e\x00\x01\x08")
    keeper = _keeper(lk, send_opts=[cid])
    keeper._dhcp.release("100.64.4.7", "100.64.4.1")
    assert (lk.DhcpOptName.CLIENT_ID, cid[1]) in _wire(keeper.sent[0].options)
    assert keeper._dhcp.client_id == cid[1]


def test_an_option_too_long_to_encode_is_a_config_error_not_a_crash(lk):
    # A hand-edited keeper.conf can hold more than 255 bytes for one option, which
    # cannot even be encoded: the keeper must start with a config error (daemon(8)
    # would otherwise restart a crashing keeper in a loop).
    keeper = _keeper(lk, send_opts=[(90, b"x" * 256)])
    assert "256 bytes" in keeper._config_error


def test_a_keeper_with_a_config_error_sends_no_dhcp(lk, tmp_path, caplog):
    hb = tmp_path / "hb"
    keeper = _keeper(lk, hbfile=str(hb), send_opts=[(53, b"\x01")])
    assert "reserved option 53" in caplog.text
    keeper._sleep_interruptible = lambda *_a, **_k: False
    keeper._maintain_step()
    assert not keeper.sent                       # no DISCOVER, nothing at all
    assert " cfgerr=1" in hb.read_text()         # the banner's cause, on this node
    assert keeper.claim_once() == 2              # --once sends nothing either


def test_a_config_error_from_keeper_conf_is_kept(lk):
    keeper = _keeper(lk, config_error="keeper.conf DHCP options unusable (x)")
    assert keeper._config_error == "keeper.conf DHCP options unusable (x)"


def test_a_request_over_one_frame_is_a_config_error(lk):
    big = [(code, b"x" * 255) for code in range(200, 206)]    # ~1550 bytes of options
    keeper = _keeper(lk, send_opts=big)
    assert "more than one 1500-byte frame" in keeper._config_error


def test_a_request_over_576_bytes_only_warns(lk, caplog):
    keeper = _keeper(lk, send_opts=[(200, b"x" * 255), (201, b"x" * 100)])
    assert keeper._config_error is None
    assert "larger than the 576 that RFC 2131 guarantees" in caplog.text


def test_a_normal_request_neither_errors_nor_warns(lk, caplog):
    keeper = _keeper(lk, send_opts=[SAGEM, TOKEN], request_codes=NATIVE_ORDER)
    assert keeper._config_error is None
    assert "RFC 2131 guarantees" not in caplog.text
    assert lk.request_size([], [SAGEM, TOKEN], NATIVE_ORDER) < 576
