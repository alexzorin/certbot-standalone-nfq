# certbot-standalone-nfq

[![certbot-standalone-nfq](https://snapcraft.io/certbot-standalone-nfq/badge.svg)](https://snapcraft.io/certbot-standalone-nfq)

HTTP authenticator plugin for [Certbot](https://certbot.eff.org/) which is compatible with any web server! (Linux only and `root` is required.)

## How?

It works by asking the Linux kernel to temporarily divert incoming port 80 HTTP traffic into
a queue. The Certbot plugin then picks out the Let's Encrypt validation requests from the
queue and responds to them. All other traffic reaches its original destination, totally
unchanged. This all happens very quickly and no traffic disruptions occur.

## Why?

- Avoids messing about with any webserver configuration, meaning that it can work well
  with tricky webservers like Apache Tomcat.
- Avoids having a proxy in front of your normal webserver, which means all source addresses
  (and indeed every network packet) are totally preserved!

It is inspired [by this community thread](https://community.letsencrypt.org/t/using-nfqueue-on-linux-as-a-novel-webserver-agnostic-http-authenticator).

## Installation

### via `snap`

Using the `certbot` snap is the easiest way to use this plugin. See [here](https://certbot.eff.org/instructions?ws=other&os=snap) for instructions on installing Certbot via `snap`.

```bash
sudo snap install certbot-standalone-nfq
sudo snap set certbot trust-plugin-with-root=ok
sudo snap connect certbot:plugin certbot-standalone-nfq
```

### via `pip`

A source tarball [is available](https://pypi.org/project/certbot-standalone-nfq/#files).

| How did you install Certbot?                                                                          | How to install the plugin                             |
|-------------------------------------------------------------------------------------------------------|-------------------------------------------------------|
| From `snap`                                                                                           | Don't use `pip`! Use the snap instructions above.     |
| Using the [official Certbot `pip` instructions](https://certbot.eff.org/instructions?ws=other&os=pip) | `sudo /opt/certbot/bin/pip install certbot-standalone-nfq` |
| From `apt`, `yum`, `dnf` or any other distro package manager. (Requires Certbot 1.25.0 or newer.)     | `pip install certbot-standalone-nfq`                       |

## Usage

`certbot-standalone-nfq` should just work without having to configure anything:

```bash
certbot certonly -a standalone-nfq \
-d "example.com" -d "www.example.com" \
--dry-run
```

If (for some reason, like port forwarding shenanigans) your web server is listening on
a port other than 80, you can use the `--http-01-port` argument of Certbot to change
the port that the plugin will divert the traffic from.