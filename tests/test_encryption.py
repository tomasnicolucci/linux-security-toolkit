"""Builds a fake /proc tree to test the network monitor."""

import ipaddress
import os
import shutil
import socket
import struct
from pathlib import Path

HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode\n"
)


def encode(ip, port):
    address = ipaddress.ip_address(ip)

    if address.version == 4:
        host = "%08X" % struct.unpack("=I", socket.inet_aton(ip))[0]
    else:
        host = "".join("%08X" % word for word in struct.unpack("=4I", address.packed))

    return f"{host}:{port:04X}"


class FakeProc:
    def __init__(self, root):
        self.root = Path(root)
        shutil.rmtree(self.root, ignore_errors=True)
        (self.root / "net").mkdir(parents=True)
        (self.root / "sys/net/ipv4").mkdir(parents=True)
        (self.root / "sys/net/ipv4/ip_local_port_range").write_text("32768\t60999\n")
        self.rows = {"tcp": [], "tcp6": [], "udp": [], "udp6": []}
        self.next_inode = 1000

    def socket(self, table, local, remote, state, pid=None, uid=0):
        self.next_inode += 1
        inode = 0 if state == "06" else self.next_inode

        self.rows[table].append(
            f"{len(self.rows[table]):4d}: {encode(*local)} {encode(*remote)} "
            f"{state} 00000000:00000000 00:00000000 00000000 {uid:5d}        "
            f"0 {inode} 1 0000000000000000 100 0 0 10 0"
        )

        if pid is not None and inode:
            self.share(inode, pid)

        return inode

    def share(self, inode, pid):
        descriptors = self.root / str(pid) / "fd"
        descriptors.mkdir(parents=True, exist_ok=True)
        os.symlink(f"socket:[{inode}]", descriptors / str(len(list(descriptors.iterdir())) + 3))

    def process(self, pid, name, exe, cmdline, uid=0):
        directory = self.root / str(pid)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "comm").write_text(name + "\n")
        (directory / "cmdline").write_bytes(cmdline.replace(" ", "\0").encode() + b"\0")
        (directory / "status").write_text(f"Name:\t{name}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        (directory / "fd").mkdir(exist_ok=True)

        if exe:
            os.symlink(exe, directory / "exe")

    def write(self):
        for table, rows in self.rows.items():
            if rows or table in ("tcp", "udp"):
                (self.root / "net" / table).write_text(
                    HEADER + "\n".join(rows) + ("\n" if rows else "")
                )


ANY = "0.0.0.0"
LOOPBACK = "127.0.0.1"


def scenario(root):
    """A server with normal services and several suspicious situations."""
    p = FakeProc(root)

    # Normal services
    p.process(100, "nginx", "/usr/sbin/nginx", "nginx: master process", 0)
    p.process(101, "nginx", "/usr/sbin/nginx", "nginx: worker process", 33)
    inode = p.socket("tcp", (ANY, 80), (ANY, 0), "0A", 100)
    p.share(inode, 101)
    p.socket("tcp", (ANY, 443), (ANY, 0), "0A", 100)
    p.process(300, "sshd", "/usr/sbin/sshd", "sshd: /usr/sbin/sshd -D", 0)
    p.socket("tcp", (ANY, 22), (ANY, 0), "0A", 300)
    p.socket("tcp6", ("::", 22), ("::", 0), "0A", 300)
    p.process(210, "postgres", "/usr/lib/postgresql/16/bin/postgres", "postgres", 114)
    p.socket("tcp", (LOOPBACK, 5432), (ANY, 0), "0A", 210, 114)
    p.process(1100, "dnsmasq", "/usr/sbin/dnsmasq", "dnsmasq", 0)
    p.socket("udp", (ANY, 53), (ANY, 0), "07", 1100)
    p.socket("udp", (ANY, 45000), (ANY, 0), "07", 1100)     # ephemeral: a client
    p.socket("tcp6", ("::ffff:127.0.0.1", 7000), ("::", 0), "0A", 300)

    # Risky services exposed to the network
    p.process(200, "redis-server", "/usr/bin/redis-server", "redis-server *:6379", 999)
    p.socket("tcp", (ANY, 6379), (ANY, 0), "0A", 200, 999)
    p.process(400, "dockerd", "/usr/bin/dockerd", "dockerd -H tcp://0.0.0.0:2375", 0)
    p.socket("tcp", (ANY, 2375), (ANY, 0), "0A", 400)
    p.process(1200, "memcached", "/usr/bin/memcached", "memcached -U 11211", 0)
    p.socket("udp", (ANY, 11211), (ANY, 0), "07", 1200)
    p.socket("tcp", (ANY, 2049), (ANY, 0), "0A")             # NFS, no visible process

    # Suspicious processes
    p.process(500, "bash", "/usr/bin/bash", "bash -i", 1000)
    p.socket("tcp", ("192.0.2.10", 51000), ("203.0.113.50", 4444), "01", 500, 1000)
    p.process(600, ".x", "/tmp/.x/miner", "/tmp/.x/miner --pool", 1001)
    p.socket("tcp", ("192.0.2.10", 51002), ("198.51.100.7", 3333), "01", 600, 1001)
    p.process(700, "apache2", "/usr/sbin/apache2 (deleted)", "apache2 -k start", 33)
    p.socket("tcp", (ANY, 8080), (ANY, 0), "0A", 700, 33)
    p.process(800, "evil", "/dev/shm/evil (deleted)", "/dev/shm/evil", 0)
    p.socket("tcp", (ANY, 31337), (ANY, 0), "0A", 800)
    p.process(900, "kworker-x", "/memfd:payload (deleted)", "[kworker/0:1]", 0)
    p.socket("tcp", ("192.0.2.10", 51004), ("203.0.113.77", 443), "01", 900)
    p.process(1000, "nc", "/usr/bin/nc.openbsd", "nc -l 9999", 1000)
    p.socket("tcp", (ANY, 9999), (ANY, 0), "0A", 1000, 1000)

    # Floods
    for i in range(120):
        p.socket("tcp", (ANY, 80), ("198.51.100.99", 20000 + i), "01", 100, 33)

    for i in range(60):
        p.socket("tcp", (ANY, 80), (f"192.0.2.{100 + i}", 30000 + i), "03")

    for i in range(30):
        p.socket("tcp", (ANY, 80), ("198.51.100.5", 40000 + i), "06")

    p.write()

    return p
