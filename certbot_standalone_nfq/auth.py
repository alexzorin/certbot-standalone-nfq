#!/usr/bin/env python3

import subprocess
import threading
from typing import Callable, Iterable, List, Optional, Type

import fnfqueue
from acme import challenges
from certbot import achallenges, configuration, interfaces
from certbot.plugins.common import Plugin
from scapy.config import conf as scapy_conf
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send
from scapy.supersocket import L3RawSocket

ACME_REQ_PATH = b"/.well-known/acme-challenge/"
NFQUEUE_ID = 8555


class Authenticator(interfaces.Authenticator, Plugin):

    description = """Works like the --standalone plugin, but still works if you already \
have a web server running on port 80. It does this by temporarily putting all port 80 \
traffic into an NFQUEUE and stealing ACME challenge validation requests from the queue. \
Other requests are unaffected.
"""

    conn: fnfqueue.Connection
    queue: fnfqueue.Queue
    thread: threading.Thread
    account_thumbprint: bytes
    http_port: int

    def __init__(self, config: Optional[configuration.NamespaceConfig], name: str) -> None:
        if not config:
            raise RuntimeError("Certbot configuration must be present")
        self.http_port = config.http01_port
        super().__init__(config, name)

    def perform(self, achalls: Iterable[achallenges.AnnotatedChallenge]
                ) -> List[challenges.ChallengeResponse]:
        # Every challenge in the order will have the same account thumbprint, just take the first.
        key_authz: bytes = achalls[0].response_and_validation()[1].encode()
        self.account_thumbprint = key_authz.split(b".")[1]

        self.conn = fnfqueue.Connection()
        self.queue = self.conn.bind(NFQUEUE_ID)
        # FIXME: buffer can be smaller.
        self.queue.set_mode(65531, fnfqueue.COPY_PACKET)
        set_nfqueue_enabled(True, self.http_port)

        self.thread = threading.Thread(target=self.drain_queue)
        self.thread.start()

        return [ac.response_and_validation()[0] for ac in achalls]

    def drain_queue(self):
        for pkt_in in self.conn:
            if self.handle_packet(IP(pkt_in.payload)):
                pkt_in.drop()
            else:
                pkt_in.accept()

    def handle_packet(self, pkt_ip: IP) -> bool:
        if not pkt_ip.haslayer(HTTPRequest):
            return False

        if not (pkt_ip[HTTPRequest].Method == b'GET' and
                pkt_ip[HTTPRequest].Path.startswith(ACME_REQ_PATH)):
            return False

        key_authz = pkt_ip[HTTPRequest].Path.lstrip(
            ACME_REQ_PATH) + b"." + self.account_thumbprint

        pkt = IP(dst=pkt_ip.src, chksum=None)
        pkt /= TCP(
            sport=pkt_ip[TCP].dport, dport=pkt_ip[TCP].sport, seq=pkt_ip[TCP].ack,
            ack=pkt_ip[TCP].seq + len(pkt_ip[TCP].payload), flags="PA", chksum=None)
        pkt /= HTTP()
        pkt /= HTTPResponse(
            Server=b"acme-nfq", Connection=b"close", Content_Length=str(len(key_authz)).encode())
        pkt /= key_authz
        send(pkt, verbose=False)
        return True

    def cleanup(self, unused_achalls: Iterable[achallenges.AnnotatedChallenge]) -> None:
        set_nfqueue_enabled(False, self.http_port)
        self.conn.close()

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        pass

    def prepare(self) -> None:
        scapy_conf.L3socket = L3RawSocket

    def more_info(self) -> str:
        return ""

    def get_chall_pref(self, unused_domain: str) -> Iterable[Type[challenges.Challenge]]:
        # TODO: it's probably possible to implement both DNS and ALPN with this strategy
        return [challenges.HTTP01]


def set_nfqueue_enabled(on: bool, port: int):
    # TODO: we can probably use nftables Python bindings to do this
    ops = {True: "I", False: "D"}
    command = f"iptables -{ops[on]} INPUT -p tcp --dport {port} -j NFQUEUE --queue-num {NFQUEUE_ID}"
    exit_code = subprocess.Popen(command.split(" ")).wait()
    if exit_code != 0:
        raise RuntimeError("Adding the iptables rule failed.")
