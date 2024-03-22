#!/usr/bin/env python3

import socket
import subprocess
import threading
from time import sleep
from typing import Callable, Iterable, List, NamedTuple, Optional, Set, Type

import fnfqueue
from acme import challenges
from certbot import achallenges, configuration, interfaces
from certbot.errors import PluginError
from certbot.plugins.common import Plugin
from pyroute2.nftables.expressions import genex
from pyroute2.nftables.main import NFTables
from scapy.config import conf as scapy_conf
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP
from scapy.packet import bind_bottom_up, bind_layers
from scapy.sendrecv import send
from scapy.supersocket import L3RawSocket

NFQUEUE_ID = 8555


class backwards_compatible_authenticator(object):
    """Provides support for both Certbot <1.19.0 and >=2.0.0."""
    def __call__(self, obj):
        try:
            import zope.interface
            from certbot.interfaces import IAuthenticator, IPluginFactory
            zope.interface.implementer(IAuthenticator)(obj)
            zope.interface.provider(IPluginFactory)(obj)
        except ImportError:
            pass
        finally:
            return obj


@backwards_compatible_authenticator()
class Authenticator(interfaces.Authenticator, Plugin):
    description = """Works like the --standalone plugin, but still works if you already \
have a web server running on port 80. It does this by temporarily putting all port 80 \
traffic into an NFQUEUE and stealing ACME challenge validation requests from the queue. \
Other requests are unaffected.
"""

    class ConnTuple(NamedTuple):
        saddr: str
        daddr: str
        sport: int
        dport: int

    conn: fnfqueue.Connection
    queue: fnfqueue.Queue
    thread: threading.Thread
    account_thumbprint: bytes
    http_port: int
    hijacked_conns: Set[ConnTuple]

    def __init__(self, config: Optional[configuration.NamespaceConfig], name: str) -> None:
        if not config:
            raise RuntimeError("Certbot configuration must be present")
        self.http_port = config.http01_port
        self.hijacked_conns = set()
        super().__init__(config, name)

    def perform(
        self, achalls: Iterable[achallenges.AnnotatedChallenge]
    ) -> List[challenges.ChallengeResponse]:
        achalls
        # Every challenge in the order will have the same account thumbprint, just take the first.
        key_authz: bytes = list(achalls)[0].response_and_validation()[1].encode()
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
            result = self.handle_packet(pkt_in)
            if result is None:
                pkt_in.mangle()
            elif result:
                pkt_in.drop()
            else:
                pkt_in.accept()

    def handle_packet(self, pkt_in: fnfqueue.Packet) -> Optional[bool]:
        """
        Return values:
        - True: Drop the packet
        - False: Pass the packet through
        - None: The packet has been modified, pass the packet through (mangle)
        """
        pkt_ip: IP = IP(pkt_in.payload)
        if not pkt_ip.haslayer(TCP):
            return False

        conn = Authenticator.ConnTuple(pkt_ip.src, pkt_ip.dst, pkt_ip[TCP].sport, pkt_ip[TCP].dport)
        if conn in self.hijacked_conns:
            return self.handle_connection_shutdown(pkt_ip, conn)

        if not pkt_ip.haslayer(HTTPRequest):
            return False

        ACME_REQ_PATH = b"/.well-known/acme-challenge/"
        if not (
            pkt_ip[HTTPRequest].Method == b"GET"
            and pkt_ip[HTTPRequest].Path.startswith(ACME_REQ_PATH)
        ):
            return False

        # Forge the HTTP response (FIN is set to expedite the socket shutdown)
        key_authz = pkt_ip[HTTPRequest].Path[len(ACME_REQ_PATH) :] + b"." + self.account_thumbprint
        pkt = IP(dst=conn.saddr, chksum=None)
        pkt /= TCP(
            sport=conn.dport,
            dport=conn.sport,
            seq=pkt_ip[TCP].ack,
            ack=pkt_ip[TCP].seq + len(pkt_ip[TCP].payload),
            flags="FPA",
            chksum=None,
        )
        pkt /= HTTP()
        pkt /= HTTPResponse(
            Server=b"certbot-standalone-nfq",
            Connection=b"close",
            Content_Length=str(len(key_authz)).encode(),
        )
        pkt /= key_authz
        send(pkt, verbose=False)

        # We will need to forge responses to the ACME server's FIN-ACK
        self.hijacked_conns.add(conn)

        # We will have to mangle this packet in order to drop the local
        # webserver connection. If we forge a reset with scapy, then
        # the kernel won't see it, epoll won't work properly, it will continue
        # to retransmit etc.
        pkt_rst: IP = pkt_ip.copy()
        # TODO: we should really drop the payload from this packet, but so far
        # removing the payload and decrementing the seq isn't working properly.
        # So here we just add the RST flag and leave everything the same.
        pkt_rst[TCP].flags = pkt_rst[TCP].flags + "R"
        del pkt_rst[TCP].chksum
        pkt_in.payload = bytes(pkt_rst)

        return None

    def handle_connection_shutdown(self, pkt_ip: IP, conn: ConnTuple) -> bool:
        if pkt_ip[TCP].flags.F:  # ACK the FIN
            pkt = IP(dst=conn.saddr, chksum=None)
            pkt /= TCP(
                sport=conn.dport,
                dport=conn.sport,
                seq=pkt_ip[TCP].ack,
                ack=pkt_ip[TCP].seq + 1,
                flags="A",
                chksum=None,
            )
            send(pkt, verbose=False)
        return True

    def cleanup(self, unused_achalls: Iterable[achallenges.AnnotatedChallenge]) -> None:
        set_nfqueue_enabled(False, self.http_port)
        # This sleep is a bit of a hack. There is a race between tearing down the queue
        # rule and closing the netlink connection, because some packets may still be in the
        # queue after we close the connection. To ensure they are drained, we sleep for a
        # short time, and then close the connection to netlink.
        sleep(1.0)
        self.conn.close()

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        pass

    def prepare(self) -> None:
        self._check_modules()
        self._check_port_is_bound()
        self._setup_scapy()

    def _check_modules(self) -> None:
        required_modules = [
            "nft_queue",  # The 'queue' expression we use in set_nfqueue_enabled
            "nfnetlink_queue",  # fnfqueue communicates with nfqueue over netfilter
        ]
        for mod in required_modules:
            proc = subprocess.run(
                ["modprobe", mod], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            if proc.returncode != 0:
                raise PluginError(
                    "certbot-standalone-nfq requires support for nfqueue in the Linux kernel. "
                    f"This is usually available by default, but the {mod} module could not be "
                    f"loaded on your system: {proc.stdout.decode()}."
                )

    def _setup_scapy(self) -> None:
        # Scapy's HTTP layer detection does not seem to work if the HTTP port
        # is not 80 or 8080, those are hardcoded. It's possible that the user
        # will be using some alternate port (port forwarding, Pebble, etc)
        # so we can get the layer detection working on that port too.
        scapy_conf.L3socket = L3RawSocket
        if self.http_port != 80:
            bind_bottom_up(TCP, HTTP, sport=self.http_port)
            bind_bottom_up(TCP, HTTP, dport=self.http_port)
            bind_layers(TCP, HTTP, sport=self.http_port, dport=self.http_port)

    def _check_port_is_bound(self) -> None:
        # Try test a binding to self.http_port. If it succeeds, the user is probably
        # holding the plugin wrong.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", self.http_port))
                raise PluginError(
                    "The certbot-standalone-nfq plugin expects a webserver to already "
                    f"be running on port {self.http_port}, but there is nothing running "
                    "on that port. Are you sure you don't mean to use the --standalone "
                    "plugin?"
                )
            except OSError as e:
                pass

    def more_info(self) -> str:
        return ""

    def get_chall_pref(self, unused_domain: str) -> Iterable[Type[challenges.Challenge]]:
        # TODO: it's probably possible to implement both DNS and ALPN with this strategy
        return [challenges.HTTP01]


def set_nfqueue_enabled(on: bool, port: int):
    with NFTables(nfgen_family=1) as nft: # NFPROTO_INET
        nft.begin()
        if on:
            # If the table wasn't cleaned up properly last time, do it now
            try:
                set_nfqueue_enabled(False, port)
            except Exception:
                pass
            # nft add table inet certbot_standalone_nfq
            nft.table("add", name="certbot_standalone_nfq")
            # nft 'add chain inet certbot_standalone_nfq acme_http_requests { type filter hook input priority 1 ; policy accept; }'
            nft.chain(
                "add",
                table="certbot_standalone_nfq",
                name="acme_http_requests",
                hook="input",
                type="filter",
                policy=1,
                priority=1,
            )
            # nft add rule inet certbot_standalone_nfq acme_http_requests tcp dport 80 queue num 8555 bypass
            exprs = (
                # pushes NFT_META_L4PROTO into REG_1
                (genex("meta", {"KEY": 16, "DREG": 0x01}),),
                # matches REG_1 (NFT_META_L4PROTO) with 0x06 (TCP)
                (
                    genex(
                        "cmp",
                        {
                            "SREG": 1,
                            "OP": 0,
                            "DATA": {"attrs": [("NFTA_DATA_VALUE", b"\x06")]},
                        },
                    ),
                ),
                # pushes the TCP port to REG_1
                (
                    genex(
                        "payload",
                        {"DREG": 0x01, "BASE": 0x02, "OFFSET": 2, "LEN": 2},
                    ),
                ),
                # compares REG_1 (TCP port) with port 80
                (
                    genex(
                        "cmp",
                        {
                            "SREG": 1,
                            "OP": 0,
                            "DATA": {"attrs": [("NFTA_DATA_VALUE", port.to_bytes(2, "big"))]},
                        },
                    ),
                ),
                # pushes nfqueue to 8555 with bypass
                (genex("queue", {"NUM": NFQUEUE_ID, "TOTAL": 1, "FLAGS": 0x01}),),
            )
            nft.rule(
                "add",
                table="certbot_standalone_nfq",
                chain="acme_http_requests",
                expressions=exprs,
            )
        else:
            nft.table("del", name="certbot_standalone_nfq")
        nft.commit()
