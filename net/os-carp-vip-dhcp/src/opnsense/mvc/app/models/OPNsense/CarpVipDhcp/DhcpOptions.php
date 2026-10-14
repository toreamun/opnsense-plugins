<?php

/*
 * Copyright (C) 2026 Tore Amundsen
 * Copyright (C) 2026 Deciso B.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\CarpVipDhcp;

/**
 * The DHCP Send Options and Request Options syntax of the interface page
 * (core's Dhcp4SendOptionsField / Dhcp4RequestOptionsField), turned into the
 * bytes the keeper sends. Plain PHP with no OPNsense dependency: the model uses
 * it to validate and to fill the *Encoded fields, and a php script tests it in CI.
 *
 * Send Options: one option per line, "name value". The value is text in double
 * quotes, or for a format-X option also colon-separated hex (01:00:5e). Only
 * text (t) and text-or-hex (X) options are supported; the keeper does not
 * encode addresses, numbers or lists. Request Options: one option name per line.
 */
class DhcpOptions
{
    /** The largest value one option can carry: its length field is one byte. */
    private const MAX_OPTION_BYTES = 255;

    /**
     * Codes Send Options must not set: the DHCP protocol fields the keeper
     * itself owns (requested address, lease time, overload, message type,
     * server identifier, parameter request list), the
     * relay agent option, pad/end, and the hostname (the Hostname field).
     */
    private const RESERVED = [
        0 => 'pad',
        12 => 'host-name (option 12) is set by the Hostname field',
        50 => 'the keeper sets the requested address (option 50)',
        51 => 'the keeper sets the lease time (option 51)',
        52 => 'option overload (option 52) is not supported',
        53 => 'the keeper sets the message type (option 53)',
        54 => 'the keeper sets the server identifier (option 54)',
        55 => 'use Request Options for the parameter request list (option 55)',
        82 => 'the relay agent option (option 82) is for relays, not clients',
        255 => 'end',
    ];

    /** Characters allowed in a value: core's set plus "/" and minus "\". */
    private const VALUE_CHARS = '/^[a-zA-Z0-9 .,:_+\-\/]*$/D';

    /** Colon-separated hex octets, one or two digits each, as dhclient reads them. */
    private const HEX_VALUE = '/^[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2})*$/D';

    /**
     * Option name => [code, dhclient format]; the code is the position in core's
     * list. Copied from opnsense/core (Deciso B.V., BSD-2, see the header)
     * src/opnsense/mvc/app/models/OPNsense/Interfaces/FieldTypes/Dhcp4SendOptionsField.php
     * at commit 05a5ab8f83a697cca893554e8ebd2c65764271e8, which lists the options
     * of FreeBSD dhclient (sbin/dhclient/tables.c).
     */
    private static $names = [
        'subnet-mask' => [1, 'I'],
        'time-offset' => [2, 'l'],
        'routers' => [3, 'IA'],
        'time-servers' => [4, 'IA'],
        'ien116-name-servers' => [5, 'IA'],
        'domain-name-servers' => [6, 'IA'],
        'log-servers' => [7, 'IA'],
        'cookie-servers' => [8, 'IA'],
        'lpr-servers' => [9, 'IA'],
        'impress-servers' => [10, 'IA'],
        'resource-location-servers' => [11, 'IA'],
        'host-name' => [12, 't'],
        'boot-size' => [13, 'S'],
        'merit-dump' => [14, 't'],
        'domain-name' => [15, 't'],
        'swap-server' => [16, 'I'],
        'root-path' => [17, 't'],
        'extensions-path' => [18, 't'],
        'ip-forwarding' => [19, 'f'],
        'non-local-source-routing' => [20, 'f'],
        'policy-filter' => [21, 'IIA'],
        'max-dgram-reassembly' => [22, 'S'],
        'default-ip-ttl' => [23, 'B'],
        'path-mtu-aging-timeout' => [24, 'L'],
        'path-mtu-plateau-table' => [25, 'SA'],
        'interface-mtu' => [26, 'S'],
        'all-subnets-local' => [27, 'f'],
        'broadcast-address' => [28, 'I'],
        'perform-mask-discovery' => [29, 'f'],
        'mask-supplier' => [30, 'f'],
        'router-discovery' => [31, 'f'],
        'router-solicitation-address' => [32, 'I'],
        'static-routes' => [33, 'IIA'],
        'trailer-encapsulation' => [34, 'f'],
        'arp-cache-timeout' => [35, 'L'],
        'ieee802-3-encapsulation' => [36, 'f'],
        'default-tcp-ttl' => [37, 'B'],
        'tcp-keepalive-interval' => [38, 'L'],
        'tcp-keepalive-garbage' => [39, 'f'],
        'nis-domain' => [40, 't'],
        'nis-servers' => [41, 'IA'],
        'ntp-servers' => [42, 'IA'],
        'vendor-encapsulated-options' => [43, 'X'],
        'netbios-name-servers' => [44, 'IA'],
        'netbios-dd-server' => [45, 'IA'],
        'netbios-node-type' => [46, 'B'],
        'netbios-scope' => [47, 't'],
        'font-servers' => [48, 'IA'],
        'x-display-manager' => [49, 'IA'],
        'dhcp-requested-address' => [50, 'I'],
        'dhcp-lease-time' => [51, 'L'],
        'dhcp-option-overload' => [52, 'B'],
        'dhcp-message-type' => [53, 'B'],
        'dhcp-server-identifier' => [54, 'I'],
        'dhcp-parameter-request-list' => [55, 'BA'],
        'dhcp-message' => [56, 't'],
        'dhcp-max-message-size' => [57, 'S'],
        'dhcp-renewal-time' => [58, 'L'],
        'dhcp-rebinding-time' => [59, 'L'],
        'dhcp-class-identifier' => [60, 't'],
        'dhcp-client-identifier' => [61, 'X'],
        'option-62' => [62, 'X'],
        'option-63' => [63, 'X'],
        'nisplus-domain' => [64, 't'],
        'nisplus-servers' => [65, 'IA'],
        'tftp-server-name' => [66, 't'],
        'bootfile-name' => [67, 't'],
        'mobile-ip-home-agent' => [68, 'IA'],
        'smtp-server' => [69, 'IA'],
        'pop-server' => [70, 'IA'],
        'nntp-server' => [71, 'IA'],
        'www-server' => [72, 'IA'],
        'finger-server' => [73, 'IA'],
        'irc-server' => [74, 'IA'],
        'streettalk-server' => [75, 'IA'],
        'streettalk-directory-assistance-server' => [76, 'IA'],
        'user-class' => [77, 't'],
        'option-78' => [78, 'X'],
        'option-79' => [79, 'X'],
        'option-80' => [80, 'X'],
        'option-81' => [81, 'X'],
        'option-82' => [82, 'X'],
        'option-83' => [83, 'X'],
        'option-84' => [84, 'X'],
        'nds-servers' => [85, 'IA'],
        'nds-tree-name' => [86, 'X'],
        'nds-context' => [87, 'X'],
        'option-88' => [88, 'X'],
        'option-89' => [89, 'X'],
        'option-90' => [90, 'X'],
        'option-91' => [91, 'X'],
        'option-92' => [92, 'X'],
        'option-93' => [93, 'X'],
        'option-94' => [94, 'X'],
        'option-95' => [95, 'X'],
        'option-96' => [96, 'X'],
        'option-97' => [97, 'X'],
        'option-98' => [98, 'X'],
        'option-99' => [99, 'X'],
        'option-100' => [100, 'X'],
        'option-101' => [101, 'X'],
        'option-102' => [102, 'X'],
        'option-103' => [103, 'X'],
        'option-104' => [104, 'X'],
        'option-105' => [105, 'X'],
        'option-106' => [106, 'X'],
        'option-107' => [107, 'X'],
        'option-108' => [108, 'X'],
        'option-109' => [109, 'X'],
        'option-110' => [110, 'X'],
        'option-111' => [111, 'X'],
        'option-112' => [112, 'X'],
        'option-113' => [113, 'X'],
        'url' => [114, 't'],
        'option-115' => [115, 'X'],
        'option-116' => [116, 'X'],
        'option-117' => [117, 'X'],
        'option-118' => [118, 'X'],
        'domain-search' => [119, 't'],
        'option-120' => [120, 'X'],
        'classless-routes' => [121, 'BA'],
        'option-122' => [122, 'X'],
        'option-123' => [123, 'X'],
        'option-124' => [124, 'X'],
        'option-125' => [125, 'X'],
        'option-126' => [126, 'X'],
        'option-127' => [127, 'X'],
        'option-128' => [128, 'X'],
        'option-129' => [129, 'X'],
        'option-130' => [130, 'X'],
        'option-131' => [131, 'X'],
        'option-132' => [132, 'X'],
        'option-133' => [133, 'X'],
        'option-134' => [134, 'X'],
        'option-135' => [135, 'X'],
        'option-136' => [136, 'X'],
        'option-137' => [137, 'X'],
        'option-138' => [138, 'X'],
        'option-139' => [139, 'X'],
        'option-140' => [140, 'X'],
        'option-141' => [141, 'X'],
        'option-142' => [142, 'X'],
        'option-143' => [143, 'X'],
        'option-144' => [144, 'X'],
        'option-145' => [145, 'X'],
        'option-146' => [146, 'X'],
        'option-147' => [147, 'X'],
        'option-148' => [148, 'X'],
        'option-149' => [149, 'X'],
        'option-150' => [150, 'X'],
        'option-151' => [151, 'X'],
        'option-152' => [152, 'X'],
        'option-153' => [153, 'X'],
        'option-154' => [154, 'X'],
        'option-155' => [155, 'X'],
        'option-156' => [156, 'X'],
        'option-157' => [157, 'X'],
        'option-158' => [158, 'X'],
        'option-159' => [159, 'X'],
        'option-160' => [160, 'X'],
        'option-161' => [161, 'X'],
        'option-162' => [162, 'X'],
        'option-163' => [163, 'X'],
        'option-164' => [164, 'X'],
        'option-165' => [165, 'X'],
        'option-166' => [166, 'X'],
        'option-167' => [167, 'X'],
        'option-168' => [168, 'X'],
        'option-169' => [169, 'X'],
        'option-170' => [170, 'X'],
        'option-171' => [171, 'X'],
        'option-172' => [172, 'X'],
        'option-173' => [173, 'X'],
        'option-174' => [174, 'X'],
        'option-175' => [175, 'X'],
        'option-176' => [176, 'X'],
        'option-177' => [177, 'X'],
        'option-178' => [178, 'X'],
        'option-179' => [179, 'X'],
        'option-180' => [180, 'X'],
        'option-181' => [181, 'X'],
        'option-182' => [182, 'X'],
        'option-183' => [183, 'X'],
        'option-184' => [184, 'X'],
        'option-185' => [185, 'X'],
        'option-186' => [186, 'X'],
        'option-187' => [187, 'X'],
        'option-188' => [188, 'X'],
        'option-189' => [189, 'X'],
        'option-190' => [190, 'X'],
        'option-191' => [191, 'X'],
        'option-192' => [192, 'X'],
        'option-193' => [193, 'X'],
        'option-194' => [194, 'X'],
        'option-195' => [195, 'X'],
        'option-196' => [196, 'X'],
        'option-197' => [197, 'X'],
        'option-198' => [198, 'X'],
        'option-199' => [199, 'X'],
        'option-200' => [200, 'X'],
        'option-201' => [201, 'X'],
        'option-202' => [202, 'X'],
        'option-203' => [203, 'X'],
        'option-204' => [204, 'X'],
        'option-205' => [205, 'X'],
        'option-206' => [206, 'X'],
        'option-207' => [207, 'X'],
        'option-208' => [208, 'X'],
        'option-209' => [209, 'X'],
        'option-210' => [210, 'X'],
        'option-211' => [211, 'X'],
        'option-212' => [212, 'X'],
        'option-213' => [213, 'X'],
        'option-214' => [214, 'X'],
        'option-215' => [215, 'X'],
        'option-216' => [216, 'X'],
        'option-217' => [217, 'X'],
        'option-218' => [218, 'X'],
        'option-219' => [219, 'X'],
        'option-220' => [220, 'X'],
        'option-221' => [221, 'X'],
        'option-222' => [222, 'X'],
        'option-223' => [223, 'X'],
        'option-224' => [224, 'X'],
        'option-225' => [225, 'X'],
        'option-226' => [226, 'X'],
        'option-227' => [227, 'X'],
        'option-228' => [228, 'X'],
        'option-229' => [229, 'X'],
        'option-230' => [230, 'X'],
        'option-231' => [231, 'X'],
        'option-232' => [232, 'X'],
        'option-233' => [233, 'X'],
        'option-234' => [234, 'X'],
        'option-235' => [235, 'X'],
        'option-236' => [236, 'X'],
        'option-237' => [237, 'X'],
        'option-238' => [238, 'X'],
        'option-239' => [239, 'X'],
        'option-240' => [240, 'X'],
        'option-241' => [241, 'X'],
        'option-242' => [242, 'X'],
        'option-243' => [243, 'X'],
        'option-244' => [244, 'X'],
        'option-245' => [245, 'X'],
        'option-246' => [246, 'X'],
        'option-247' => [247, 'X'],
        'option-248' => [248, 'X'],
        'option-249' => [249, 'X'],
        'option-250' => [250, 'X'],
        'option-251' => [251, 'X'],
        'option-252' => [252, 'X'],
        'option-253' => [253, 'X'],
        'option-254' => [254, 'X'],
    ];

    /**
     * Parse Send Options text. $fieldOptions maps more codes to the reason they
     * are refused (options another field of the keeper sets). Returns
     * ['options' => [[code, bytes], ...] in the order given, 'errors' => [message, ...]].
     */
    public static function parseSendOptions($text, array $fieldOptions = [])
    {
        $options = [];
        $errors = [];
        $seen = [];
        foreach (self::lines($text) as $line) {
            if (preg_match('/^send\s/i', $line) || substr($line, -1) === ';') {
                $errors[] = sprintf("%s: remove 'send' and the ';'. Enter one option per line as: name value.", $line);
                continue;
            }
            $parts = preg_split('/\s+/', $line, 2);
            $name = $parts[0];
            if (!isset(self::$names[$name])) {
                $errors[] = self::unknownName($name);
                continue;
            }
            list($code, $format) = self::$names[$name];
            $reason = self::RESERVED[$code] ?? $fieldOptions[$code] ?? null;
            if ($reason !== null) {
                $errors[] = sprintf('%s: %s.', $name, $reason);
                continue;
            }
            list($bytes, $error) = self::valueBytes($name, $code, $format, $parts[1] ?? '');
            if ($error === null && isset($seen[$code])) {
                $error = sprintf('Option %d (%s) is set more than once.', $code, $name);
            }
            if ($error !== null) {
                $errors[] = $error;
                continue;
            }
            $seen[$code] = true;
            $options[] = [$code, $bytes];
        }
        return ['options' => $options, 'errors' => $errors];
    }

    /**
     * Parse Request Options text: one option name per line. Returns
     * ['codes' => [code, ...] in the order given without duplicates, 'errors' => [...]].
     */
    public static function parseRequestOptions($text)
    {
        $codes = [];
        $errors = [];
        foreach (self::lines($text) as $line) {
            if (strpos($line, ',') !== false || preg_match('/\s/', $line)) {
                $errors[] = sprintf('%s: Request Options takes one option name per line, no commas.', $line);
                continue;
            }
            if (!isset(self::$names[$line])) {
                $errors[] = self::unknownName($line);
                continue;
            }
            $code = self::$names[$line][0];
            if (!in_array($code, $codes, true)) {
                $codes[] = $code;
            }
        }
        return ['codes' => $codes, 'errors' => $errors];
    }

    /** keeper.conf form of parsed send options: "code:hex,code:hex" (lowercase hex). */
    public static function encodeSendOptions(array $options)
    {
        $fields = [];
        foreach ($options as $option) {
            $fields[] = $option[0] . ':' . bin2hex($option[1]);
        }
        return implode(',', $fields);
    }

    /** keeper.conf form of parsed request options: "code,code". */
    public static function encodeRequestOptions(array $codes)
    {
        return implode(',', $codes);
    }

    /** The option code for a name, or null when the name is unknown. */
    public static function code($name)
    {
        return isset(self::$names[$name]) ? self::$names[$name][0] : null;
    }

    /** Trimmed, non-empty lines (any of \r\n, \n, \r ends a line). */
    private static function lines($text)
    {
        $out = [];
        foreach (preg_split('/\r\n|\r|\n/', (string)$text) as $line) {
            $line = trim($line);
            if ($line !== '') {
                $out[] = $line;
            }
        }
        return $out;
    }

    /** The message for a name that is not in the option table. */
    private static function unknownName($name)
    {
        return sprintf("Unknown option name '%s'. Use the names from the interface page, or option-N.", $name);
    }

    /**
     * [bytes, null] for one option value, or [null, message]. Text is one pair of
     * double quotes around allowed characters; a format-X option also takes
     * colon-separated hex. Other formats are refused.
     */
    private static function valueBytes($name, $code, $format, $value)
    {
        if ($format !== 't' && $format !== 'X') {
            return [null, sprintf("Option '%s' (format %s) is not supported in Send Options yet.", $name, $format)];
        }
        if ($value === '') {
            return [null, sprintf('%s: no value.', $name)];
        }
        if (strpos($value, '\\') !== false) {
            return [null, sprintf('%s: backslash is not supported in values yet.', $name)];
        }
        $quoted = strlen($value) >= 2 && $value[0] === '"' && substr($value, -1) === '"';
        $inner = $quoted ? substr($value, 1, -1) : $value;
        if (strpos($inner, '"') !== false) {
            return [null, sprintf('%s: a value has one pair of double quotes around the whole text.', $name)];
        }
        if (!preg_match(self::VALUE_CHARS, $inner)) {
            return [null, sprintf(
                '%s: character not supported yet. Allowed: letters, digits, space and . , : _ + - /',
                $name
            )];
        }
        if ($quoted) {
            $bytes = $inner;
        } elseif ($format === 't') {
            return [null, sprintf(
                'Option %d is %s, a text option: write %s "..." with the text in quotes. '
                . 'Hex for text options is not supported yet.',
                $code,
                $name,
                $name
            )];
        } elseif (preg_match(self::HEX_VALUE, $inner)) {
            $bytes = '';
            foreach (explode(':', $inner) as $octet) {
                $bytes .= chr(hexdec($octet));
            }
        } else {
            return [null, sprintf('%s: the value is neither text in quotes nor colon-separated hex.', $name)];
        }
        if ($bytes === '') {
            return [null, sprintf('%s: no value.', $name)];
        }
        if (strlen($bytes) > self::MAX_OPTION_BYTES) {
            return [null, sprintf(
                'Option %d (%s) is %d bytes; one option holds at most %d.',
                $code,
                $name,
                strlen($bytes),
                self::MAX_OPTION_BYTES
            )];
        }
        return [$bytes, null];
    }
}
