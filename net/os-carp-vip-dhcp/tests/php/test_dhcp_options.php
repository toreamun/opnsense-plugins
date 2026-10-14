<?php

/*
 * Tests for OPNsense\CarpVipDhcp\DhcpOptions (the Send Options / Request Options
 * syntax and the bytes the keeper sends). Plain php, no framework:
 *     php net/os-carp-vip-dhcp/tests/php/test_dhcp_options.php
 * Prints every failure and exits non-zero if there was one.
 */

require __DIR__ . '/../../src/opnsense/mvc/app/models/OPNsense/CarpVipDhcp/DhcpOptions.php';

use OPNsense\CarpVipDhcp\DhcpOptions;

$failures = 0;
$checks = 0;

function check($cond, $what)
{
    global $failures, $checks;
    $checks++;
    if (!$cond) {
        $failures++;
        echo "FAIL: $what\n";
    }
}

/* Send Options text -> keeper.conf "code:hex", with no errors. */
function sends($text, $expected)
{
    $r = DhcpOptions::parseSendOptions($text);
    $got = DhcpOptions::encodeSendOptions($r['options']);
    check($r['errors'] === [], "no errors for: $text (got " . implode(' | ', $r['errors']) . ')');
    check($got === $expected, "bytes for: $text (got $got, want $expected)");
}

/* Send Options text that is refused with one message containing $fragment. */
function refuses($text, $fragment, array $extraReserved = [])
{
    $r = DhcpOptions::parseSendOptions($text, $extraReserved);
    check($r['options'] === [], "nothing accepted for: $text");
    check(
        count($r['errors']) === 1 && strpos($r['errors'][0], $fragment) !== false,
        "one error containing '$fragment' for: $text (got " . implode(' | ', $r['errors']) . ')'
    );
}

/* ---- the option table: the code is the position in core's list ---- */
check(DhcpOptions::code('subnet-mask') === 1, 'subnet-mask is 1');
check(DhcpOptions::code('host-name') === 12, 'host-name is 12');
check(DhcpOptions::code('dhcp-class-identifier') === 60, 'dhcp-class-identifier is 60');
check(DhcpOptions::code('dhcp-client-identifier') === 61, 'dhcp-client-identifier is 61');
check(DhcpOptions::code('user-class') === 77, 'user-class is 77');
check(DhcpOptions::code('option-90') === 90, 'option-90 is 90');
check(DhcpOptions::code('domain-search') === 119, 'domain-search is 119');
check(DhcpOptions::code('classless-routes') === 121, 'classless-routes is 121');
check(DhcpOptions::code('option-254') === 254, 'option-254 is 254');
check(DhcpOptions::code('option-60') === null, 'option-60 is not a name (60 has one)');

/* ---- Send Options that work, with the bytes dhclient sends for them ---- */
sends('dhcp-class-identifier "sagem"', '60:' . bin2hex('sagem'));
/* RFC 3004 user class: the "+" (0x2b = 43) is the length of the 43-character class. */
sends(
    'user-class "+FSVDSL_livebox.Internet.softathome.Livebox5"',
    '77:2b' . bin2hex('FSVDSL_livebox.Internet.softathome.Livebox5')
);
sends('dhcp-client-identifier 01:00:00:5e:00:01:08', '61:0100005e000108');
sends('dhcp-client-identifier "isp-login.1"', '61:' . bin2hex('isp-login.1'));
sends(
    'option-90 00:00:00:00:00:00:00:00:00:00:00:1a:09:00:00:05:58:01:03:41',
    '90:00000000000000000000001a0900000558010341'
);
sends('option-90 0:1:a:ff', '90:00010aff');                   /* one-digit octets, as dhclient */
sends('option-125 "a/b c,d"', '125:' . bin2hex('a/b c,d'));   /* "/", space and comma in text */
sends('  dhcp-class-identifier   "sagem"  ', '60:' . bin2hex('sagem'));
sends('option-90 ' . implode(':', array_fill(0, 255, 'ab')), '90:' . str_repeat('ab', 255));   /* the limit */

/* Several lines keep their order; blank lines and any line ending are fine. */
$r = DhcpOptions::parseSendOptions("dhcp-class-identifier \"sagem\"\r\n\r\noption-90 01\ruser-class \"+a\"\n");
check($r['errors'] === [], 'multi-line: no errors');
check(
    DhcpOptions::encodeSendOptions($r['options']) === '60:736167656d,90:01,77:2b61',
    'multi-line: order and bytes (got ' . DhcpOptions::encodeSendOptions($r['options']) . ')'
);
check(DhcpOptions::parseSendOptions('') === ['options' => [], 'errors' => []], 'empty text is no options');
check(DhcpOptions::parseSendOptions("\n  \n") === ['options' => [], 'errors' => []], 'blank lines only');

/* ---- Send Options that are refused, with a message that says why ---- */
refuses('send dhcp-class-identifier "sagem";', "remove 'send' and the ';'");
refuses('dhcp-class-identifier "sagem";', "remove 'send' and the ';'");
refuses('vendor-class "sagem"', "Unknown option name 'vendor-class'");
refuses('option-60 "sagem"', "Unknown option name 'option-60'");
refuses('routers 10.0.0.1', "Option 'routers' (format IA) is not supported");
refuses('dhcp-max-message-size 05:dc', "Option 'dhcp-max-message-size' (format S) is not supported");
refuses('host-name "fw1"', 'set by the Hostname field');
refuses('dhcp-message-type 03', 'the keeper sets the message type');
refuses('dhcp-parameter-request-list 01:03', 'use Request Options');
refuses('user-class +FSVDSL', 'a text option: write user-class "..."');
refuses('dhcp-class-identifier', 'no value');
refuses('dhcp-class-identifier ""', 'no value');
refuses('dhcp-class-identifier "a\\b"', 'backslash is not supported');
refuses('dhcp-class-identifier "a|b"', 'character not supported yet');
refuses('dhcp-client-identifier "user@isp"', 'character not supported yet');
refuses('dhcp-class-identifier "a"b"', 'one pair of double quotes');
refuses('option-90 abc', 'neither text in quotes nor colon-separated hex');
refuses('option-90 01:002', 'neither text in quotes nor colon-separated hex');
refuses('option-90 01 02', 'neither text in quotes nor colon-separated hex');
refuses('option-90 ' . implode(':', array_fill(0, 256, 'ab')), 'is 256 bytes; one option holds at most 255');
refuses(
    'dhcp-class-identifier "sagem"',
    'set by the DHCP vendor class field',
    [60 => 'dhcp-class-identifier (option 60) is set by the DHCP vendor class field']
);

/* A duplicate is refused; the first one stays. */
$r = DhcpOptions::parseSendOptions("option-90 01\noption-90 02");
check(DhcpOptions::encodeSendOptions($r['options']) === '90:01', 'duplicate: the first one stays');
check(count($r['errors']) === 1 && strpos($r['errors'][0], 'set more than once') !== false, 'duplicate: one error');

/* Every bad line is reported, the good ones still parse. */
$r = DhcpOptions::parseSendOptions("routers 1.2.3.4\ndhcp-class-identifier \"sagem\"\nfoo 1");
check(count($r['errors']) === 2, 'two bad lines, two errors');
check(DhcpOptions::encodeSendOptions($r['options']) === '60:736167656d', 'the good line still parses');

/* ---- Request Options ---- */
$r = DhcpOptions::parseRequestOptions(
    "subnet-mask\nbroadcast-address\ndhcp-lease-time\ndhcp-renewal-time\ndhcp-rebinding-time\n"
    . "domain-search\nrouters\ndomain-name-servers\noption-90\ndomain-name\noption-120\noption-125\n"
);
check($r['errors'] === [], 'request: no errors');
check(
    DhcpOptions::encodeRequestOptions($r['codes']) === '1,28,51,58,59,119,3,6,90,15,120,125',
    'request: native order kept (got ' . DhcpOptions::encodeRequestOptions($r['codes']) . ')'
);
$r = DhcpOptions::parseRequestOptions("routers\nrouters\nsubnet-mask");
check($r['codes'] === [3, 1], 'request: duplicates dropped, first position kept');
$r = DhcpOptions::parseRequestOptions('subnet-mask, routers');
check($r['codes'] === [] && strpos($r['errors'][0], 'one option name per line, no commas') !== false, 'request: commas');
$r = DhcpOptions::parseRequestOptions('subnet-mask routers');
check($r['codes'] === [] && count($r['errors']) === 1, 'request: two names on one line');
$r = DhcpOptions::parseRequestOptions('no-such-option');
check($r['codes'] === [] && strpos($r['errors'][0], 'Unknown option name') !== false, 'request: unknown name');
check(DhcpOptions::parseRequestOptions('') === ['codes' => [], 'errors' => []], 'request: empty');

echo "$checks checks, $failures failed\n";
exit($failures === 0 ? 0 : 1);
