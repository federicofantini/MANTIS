# MANTIS

<p align="center">
  <img src="image.png" alt="Mantis image" width="30%" height="30%" style="border-radius: 12%">
</p>

<p align="center">
  <a href="https://github.com/federicofantini/MANTIS/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/federicofantini/MANTIS?style=flat-square" alt="License">
  </a>
  <a href="https://github.com/federicofantini/MANTIS/stargazers">
    <img src="https://img.shields.io/github/stars/federicofantini/MANTIS?style=flat-square" alt="Stars">
  </a>
  <a href="https://github.com/federicofantini/MANTIS/network/members">
    <img src="https://img.shields.io/github/forks/federicofantini/MANTIS?style=flat-square" alt="Forks">
  </a>
  <a href="https://github.com/federicofantini/MANTIS/issues">
    <img src="https://img.shields.io/github/issues/federicofantini/MANTIS?style=flat-square" alt="Open Issues">
  </a>
  <a href="https://github.com/federicofantini/MANTIS/commits/main">
    <img src="https://img.shields.io/github/last-commit/federicofantini/MANTIS?style=flat-square" alt="Last Commit">
  </a>
  <a href="https://github.com/federicofantini/MANTIS/actions">
    <img src="https://github.com/federicofantini/MANTIS/actions/workflows/main.yml/badge.svg" alt="Build Status">
  </a>
  <a href="https://github.com/federicofantini/MANTIS/releases">
    <img src="https://img.shields.io/github/v/release/federicofantini/MANTIS?style=flat-square" alt="Latest Release">
  </a>
</p>


## Introduction
MANTIS is a lightweight motion detection system designed for Raspberry Pi, aimed at providing real-time surveillance and alerting capabilities without giving up privacy. It uses OpenCV to detect movement through a connected camera and automatically captures images or video recordings when motion is detected. These alerts are then securely sent to a remote server using xmpp+omemo or matrix.org protocol, enabling E2EE and decentralized communication. The goal of MANTIS is to offer a simple, efficient, and **privacy-respecting** home or office security solution using open-source tools.

## Quickstart
### Fix Raspi camera
- fix `/boot/firmware/config.txt` (https://forums.raspberrypi.com/viewtopic.php?t=331441)
  - uncommenting out `#auto_detect_camera=1`
  - add `start_x=1`
  - add `gpu_mem=128`
### Setup the python environment
- install system dependencies
  - `sudo apt install libolm-dev libsodium-dev libxeddsa-dev libgl1`
- setup venv and install mantis inside
  - `sudo mkdir -p /opt/mantis/ && sudo chown -R $USER:$USER /opt/mantis && cd /opt/mantis/ && python3 -m venv venv && source venv/bin/activate`
  - `python3 -m pip install https://github.com/federicofantini/MANTIS/releases/download/v1.0.2/mantis-0.1-py3-none-any.whl`
  - `deactivate`
- setup login and config data
  - `wget https://raw.githubusercontent.com/federicofantini/MANTIS/refs/heads/main/.env.template && mv .env.template .env`
    - (configure your accounts!!)
- setup account avatar
  - `wget https://raw.githubusercontent.com/federicofantini/MANTIS/refs/heads/main/image.png`
    - (or any other image, as long as it has that name)
### Setup the new user
- `sudo useradd -r -s /usr/sbin/nologin -d /opt/mantis mantis`
- `sudo usermod -aG video mantis`
### Create `start.sh` script
- `/opt/mantis/start.sh`
  - ```bash
    #!/bin/bash
    source /opt/mantis/venv/bin/activate
    python3 -m mantis.main
    ```
- `chmod +x /opt/mantis/start.sh`
- `sudo chown -R mantis:mantis /opt/mantis`
### First run
- we need to trust the new device from element, follow the instructions provided by mantis
  - `sudo -u mantis /opt/mantis/start.sh`
### After the first run, create a systemd service
- `/etc/systemd/system/mantis.service`
  - ```
    [Unit]
    Description=MANTIS - motion detection system
    After=network.target

    [Service]
    Type=simple
    User=mantis
    WorkingDirectory=/opt/mantis/
    ExecStart=/opt/mantis/start.sh
    Restart=on-failure
    Environment="PYTHONUNBUFFERED=1"

    [Install]
    WantedBy=multi-user.target
    ```
- `sudo systemctl daemon-reload`
- `sudo systemctl enable mantis.service`
- `sudo systemctl start mantis.service`

## Motion detection stuff (theory + examples)
- [motion decetion stuff](Motion-detection.ipynb)

## Xmpp vs Matrix

### XMPP

#### What is XMPP?
XMPP (Extensible Messaging and Presence Protocol) is an open and decentralized communication protocol designed for instant messaging, presence updates, and real-time data exchange. Based on XML, XMPP allows clients and servers to communicate using a well-defined structure and extensible mechanisms.

#### XMPP Federated Architecture
One of XMPP’s key features is its federated design, which allows anyone to host their own server. Much like email, this creates a distributed ecosystem where users on different domains can communicate freely without relying on a single central authority. This model promotes data sovereignty, resilience, and privacy.

#### XMPP Modularity by Design: The Power of XEPs
XMPP’s flexibility is largely due to its modular architecture, powered by a wide set of XMPP Extension Protocols (XEPs). These extensions define additional functionality that can be layered on top of the core protocol, including:
- End-to-end encryption (e.g., OMEMO, OpenPGP)
- Group chats (Multi-User Chat)
- File transfers
- Push notifications
- Message carbons and message archive management
- Voice/video via Jingle

This modularity makes XMPP highly customizable and adaptable for various use cases—from personal messaging apps to IoT communication, chatbots, and enterprise collaboration tools.

#### On XMPP and OMEMO: Notes from Soatok’s Critique
In the blog post *["Against XMPP/OMEMO"](https://soatok.blog/2024/08/04/against-xmppomemo/)* (August 2024), Soatok offers a detailed and critical analysis of the XMPP+OMEMO ecosystem from a cryptographic standpoint. Although OMEMO (XEP-0384) was created to bring end-to-end encryption (E2EE) to XMPP—drawing from the Signal protocol—Soatok argues that its current state is insufficient for secure messaging.

Below is a structured summary of the key cryptographic concerns raised in the article.

##### 1. Protocol Fragmentation and Stagnation
> *“Almost every OMEMO implementation I can find is still on version 0.3.0 (or earlier)...”*

- Most XMPP clients use outdated versions of the OMEMO spec.
- Newer versions (e.g. 0.4.0+) bring important updates like AES-256-CBC, but are not widely adopted.
- This creates confusion for researchers and weakens the effectiveness of the encryption.


##### 2. Lack of Cryptographic Rationale
> *“OMEMO doesn’t attempt to provide even the vaguest rationale for its design choices...”*

- Changes in algorithms and parameters (e.g. from AES-GCM to AES-CBC + HMAC) are undocumented.
- The truncation of HMAC tags to 128 bits was introduced without justification.
- Soatok highlights the absence of clear reasoning and changelog transparency, contrasting with better-documented efforts like PASETO.


##### 3. Weaknesses in Pre-0.4.0 OMEMO (AES-GCM)
> *“AES-128-GCM doesn’t commit to the key, which can lead to an attack that we call ‘Invisible Salamanders’.”*

- AES-GCM lacks key commitment, making it vulnerable in some contexts.
- Limited nonce space (96-bit) increases risk of key reuse and cryptographic wear-out.


##### 4. Post-0.4.0 OMEMO Issues (AES-CBC + HMAC)
> *“Even the current version (0.8.3) doesn’t instruct implementations to use constant-time comparison...”*

- Security improvements are inconsistently documented and not enforced.
- The truncated HMAC-SHA-256 authentication tag reduces resistance to forgery attacks, with no clear rationale.


##### 5. Ecosystem-Level Risks
> *“The most popular app (Conversations) being an absolute mess of complications...”*

- Conversations (and forks) bundle multiple cryptographic systems (PGP, TLS, OMEMO) with questionable separation and maintenance.
- Relies on outdated versions of BouncyCastle and libsignal, missing security patches (e.g. CVE-2023-33202).
- Lacks dependency updates and modern development practices like automated vulnerability scanning.


##### Conclusion (Quoted)
> *“As things stand today, I cannot recommend anyone use XMPP + OMEMO.”*

Soatok concludes that the combination of:
- slow protocol evolution,
- undocumented cryptographic decisions,
- vulnerable implementations, and
- poor defaults

...renders OMEMO unsuitable for secure private messaging. While acknowledging that OMEMO was “the least-bad effort to staple encryption onto XMPP” the author ultimately recommends looking elsewhere for reliable E2EE—such as Matrix or Signal.

### Matrix

#### What is matrix?
Matrix is a decentralized communication protocol designed for instant messaging, VoIP, and real-time synchronization across devices. Its main goal is to enable interoperability between different communication platforms, offering a modern and open alternative to protocols like XMPP.

Unlike centralized systems (such as WhatsApp or Signal), Matrix doesn't rely on a single server: each user can connect through a trusted server, and messages are federated between servers similar to how email or XMPP works.

In terms of security, Matrix uses end-to-end encryption via the Olm/Megolm algorithm, which is inspired by the Signal Protocol. This makes it similar to both Signal, known for its strong end-to-end encryption, and XMPP + OMEMO, where OMEMO is an extension based on the Signal Protocol to encrypt messages.

## Project Background and Development History
As one of the MANTIS project's goals is to put a motion detection system on a Raspberry Pi with real-time notification through **encrypted messaging**, I initially selected XMPP+OMEMO due to its federated protocol, its real-time aspect, and end-to-end encryption support.

Throughout development, I encountered a variety of challenges.

The first job was to make available at least a minimal example of a bot that was able to communicate using the encryption that is available from OMEMO.
You can use this as a jumping point: https://github.com/Syndace/slixmpp-omemo/blob/main/examples/echo_client.py.

So I drew inspiration from these two projects for how they implemented encryption and the calling of library functions:
- https://github.com/m6freeman/ollama_slixmpp_omemo_bot
- https://github.com/spiccinini/xarebot

Then I attempted to register on at least a total of ten different instances of this site https://providers.xmpp.net/ for conducting some communication tests. The major issue I was facing was finding a server that supported registering, didn't ban me if I was using a bot, and supported OMEMO encryption (XEP-0384).

*Spoiler: despite trying multiple times, I couldn’t find a suitable server that met all my criteria, and after running into dead end after dead end, I lost patience and gave up on that route.*

That's why I went ahead and set up my own instance https://secxmpp.net (please, read on) by using prosody on my VPS purchased especially for this purpose. After doing some work on the server installation for about 2 days I managed to communicate through OMEMO but there was a huge issue: installation of an HTTP server for file upload. I attempted a few times but not with a great deal of success. Disheartened, I turned to Google where I read the blog post by Soatok and from it I realized it is totally not the protocol I need, so I gave up on it.

In a few hours the following day I managed to set up an instance of Matrix and get it running... very very simple.

## Architecture
```
          +---------------------------------------------+
          |           main.py (MainThread)              |
          |   (load environment, select Matrix/XMPP,    |
          |    enable/disable alarm system)             |---------------------+
          +---------------------------------------------+                     |   
                                      |                                       |
                                      v                                       |
          +---------------------------------------------------------+         |
          |                  mantis.py (MainThread)                 |         |
          |                  - Connect to Matrix                    |         |
          |                  - Handle login                         |         |
          |                  - commands                             |         |
  +------>|                  - encrypted uploads                    |         |
  |       |                     (_send_image(),                     |         |
  |       |                      _send_video)                       |         |
  |       +---------------------------------------------------------+         |
  |                                   |                                       |
  |                   +---------------+---------------------------------------+
  |                   |                                                       |
  |                   v                                                       v
  |       +-------------------------------+                            +---------------+
  |       |   AlarmSystem Thread          |                            |    Logger     |
  |       |     - Motion detection        |--------------------------->| (Centralized  |
  |       |     - Camera management       |                            |   logging)    |
  |       |     - Task processing         |                            +---------------+
  |       |        - take_picture         |
  |       |        - record_video         |
  |       |        - arm alarm system     |
  |       |                               |
  |       |     (synchronization via      |
  |       |     threading.Condition)      |
  |       +-------------------------------+
  |                      |
  |         alarm/take_picture/record/video
  |                      |
  +----------------------+
```
