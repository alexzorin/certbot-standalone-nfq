import os
from setuptools import setup

install_requires = [
    "scapy",
    "pyroute2",
    "fnfqueue"
]
if not os.environ.get("SNAP_BUILD"):
    install_requires.extend(["certbot>=1.25.0", "acme>=1.25.0"])
else:
    install_requires.append("packaging")

setup(
    name="certbot-standalone-nfq",
    install_requires=install_requires,
)
