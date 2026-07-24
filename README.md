# ft_nmap

📖 **English** | [Français](README.fr.md)

> A multithreaded IPv4 port scanner written in C, rebuilding a subset of the famous
> [Nmap](https://nmap.org). It uses **raw sockets** to forge its own probe packets and
> the **pcap** library to capture the replies, then reports the state of each port for
> each scan type. This is a 42 school project (`ft_nmap`).

---

## Table of contents

1. [Quick start](#quick-start)
2. [Usage & options](#usage--options)
3. [The `POSITIONAL_TARGET` switch](#the-positional_target-switch)
4. [Mandatory part — what is implemented](#mandatory-part--what-is-implemented)
5. [Bonus part — extra flags](#bonus-part--extra-flags)
6. [How it all works — a beginner's course](#how-it-all-works--a-beginners-course)
7. [Project structure](#project-structure)
8. [Credits](#credits)

---

## Quick start

### Requirements
- Linux (kernel > 3.14)
- `gcc`, `make`
- `libpcap` (`-lpcap`) and `pthread` (`-lpthread`)
- **root privileges** (raw sockets require them)

```bash
# install the dependency if needed (Debian/Ubuntu)
sudo apt-get install libpcap-dev

# build
make

# run (needs root)
sudo ./ft_nmap --ip 127.0.0.1 --ports 1-1024 --scan SYN --speedup 50
```

### Makefile rules
| Rule | Effect |
|------|--------|
| `make` / `make all` | Build `ft_nmap` (relinks only if needed) |
| `make clean` | Remove object files |
| `make fclean` | Remove objects **and** the binary |
| `make re` | `fclean` then rebuild from scratch |

---

## Usage & options

```
ft_nmap [OPTIONS] --ip <ip|hostname>
ft_nmap [OPTIONS] --file <file>
```

| Option | Argument | Description | Part |
|--------|----------|-------------|------|
| `--ip` | IP / hostname | A single target to scan | Mandatory |
| `-f`, `--file` | path | Read a list of targets from a file (whitespace-separated) | Mandatory |
| `-p`, `--ports` | list/range | Ports to scan: `80`, `1-1024`, `80,443`, `1,5-15` (default `1-1024`, **max 1024**) | Mandatory |
| `-s`, `--scan` | types | Scan types, `/`-separated: `SYN/NULL/ACK/FIN/XMAS/UDP` (default: all) | Mandatory |
| `--speedup` | 0–250 | Number of parallel threads (`0` = single-threaded) | Mandatory |
| `--version-detection` | — | Probe open ports to identify the running service/version | **Bonus** |
| `--reverse-dns` | — | Resolve each IP back to a hostname (PTR lookup) | **Bonus** |
| `--ttl` | 1–255 | IP Time-To-Live of the packets we send (default `64`) | **Bonus** |
| `--spoof` | IP | Forge a fake source address (stealth; replies won't come back) | **Bonus** |
| `--open` | — | Show only open ports, hide closed/filtered | **Bonus** |
| `--progress` | — | Live progress dashboard during the scan | **Bonus** |
| `--help` | — | Print the help screen and exit | Mandatory |

You can also pass a **CIDR block** as a target (e.g. `192.168.1.0/24`); it is expanded into
every address it covers (bonus, up to a `/16`).

### Examples
```bash
# Full default scan of one host (ports 1-1024, all scan types)
sudo ./ft_nmap --ip scanme.nmap.org

# Fast SYN scan of a port range with 100 threads
sudo ./ft_nmap --ip 10.0.0.5 --ports 20-1024 --scan SYN --speedup 100

# Two scan types at once, only show what's open
sudo ./ft_nmap --ip 127.0.0.1 --ports 1-100 --scan SYN/ACK --open

# Read targets from a file, identify the services, show a live dashboard
sudo ./ft_nmap --file targets.txt --version-detection --progress
```

---

## The `POSITIONAL_TARGET` switch

At the very top of `include/ft_nmap.h` there is a compile-time switch:

```c
# define POSITIONAL_TARGET  0
```

It controls **how you pass the target on the command line**, and you rebuild the project
(`make re`) after changing it.

| Value | Behaviour | Example |
|-------|-----------|---------|
| **`0`** (submission) | Targets come **only** from `--ip` or `--file`. A bare argument is rejected. This matches exactly the usage required by the subject. | `ft_nmap --ip 127.0.0.1` |
| **`1`** (nmap-style) | The target is given as a **positional argument**, like the real `nmap`. The `--ip` option does not exist in this mode. | `ft_nmap 127.0.0.1` |

**Why two modes?** The subject explicitly requires the `--ip IP_ADDRESS` form, so the
project is submitted with `POSITIONAL_TARGET = 0`. The `= 1` mode is a convenience that
mimics the real `nmap` (`nmap 127.0.0.1`) for everyday use. Both modes are fully
functional and leak-free; only the way you type the target changes.

---

## Mandatory part — what is implemented

Everything the subject asks for is done:

- ✅ Executable named **`ft_nmap`** with a proper **`--help`** menu.
- ✅ Accepts a **single IPv4 address or hostname** (FQDN accepted; resolution delegated to the system).
- ✅ Reads a **list of targets from a file** (`--file`), free formatting (any whitespace separates them).
- ✅ **Threads** to speed up the scan: `--speedup`, default **0** (mono-thread), max **250**.
- ✅ The six scan types: **SYN, NULL, ACK, FIN, XMAS, UDP**.
  - Each type can run **on its own** or **several at once**.
  - If `--scan` is omitted, **all** types are used.
- ✅ Ports given as a **range or a list**; default **`1-1024`**; hard limit of **1024** ports.
- ✅ **Service type resolution**: each port is labelled with its well-known service name
  (`80 → http`, `22 → ssh`…) via the system services database.
- ✅ A **clean, readable result** with the elapsed time, colour-coded when the output is a terminal.
- ✅ Careful **error handling** (no segfault / double free) and **no memory leaks** (checked with valgrind).
- ✅ Only the **C standard library**, **pcap** and **pthread** are used for the mandatory part.

---

## Bonus part — extra flags

| Flag | Bonus category (from the subject) | What it does |
|------|-----------------------------------|--------------|
| `--version-detection` | DNS/Version management | Connects to each open port and reads its banner to guess the software/version. |
| `--reverse-dns` | DNS/Version management | Turns each IP back into a hostname (reverse/PTR DNS lookup). |
| `--ttl` | Flag to go over the IDS/Firewall | Lets you set the IP TTL of the probes (useful for evasion / low-TTL tricks). |
| `--spoof` | Hide the source address | Sends packets with a **fake source IP** (stealth — replies won't return to you). |
| `--open` | Additional flag | Displays **only** the open ports. |
| `--progress` | Additional flag | Shows a **live dashboard** (percentage, elapsed, ETA) while scanning. |
| CIDR targets | Additional flag | A target like `192.168.1.0/24` is expanded into every address of the block. |

---

## How it all works — a beginner's course

*This section assumes you have never heard of a "port" or how `ping` works. Read it top to
bottom and by the end you'll understand every line of output.*

### 1. How two computers talk

Think of the internet as a **postal system**:

- An **IP address** (e.g. `93.184.216.34`) is the **street address of a machine**. Every
  computer on a network has one.
- A **port** is like an **apartment number inside that building**. A machine has 65 535
  ports. Each network program (a website, an email server, SSH…) waits for visitors
  behind one specific port — a web server usually listens on port **80**, secure web on
  **443**, SSH on **22**, and so on. A program waiting behind a port is a **service**.
- A **packet** is a single **letter**: it has a "**to**" address, a "**from**" address, and
  some content. Computers don't send a continuous stream; they cut everything into packets
  and send them one by one.

So "connecting to a website" really means: *my machine sends packets to IP `x`, port `80`,
and the web server there sends packets back to my IP.*

### 2. `ping`: the simplest possible conversation

`ping` is the "knock on the door" of networking. Your machine sends a tiny packet that
means **"are you alive?"** (an *ICMP echo request*). If the other machine is up, it sends
back **"yes, I'm here"** (an *ICMP echo reply*). That round-trip is all `ping` does — it
does **not** talk to any port or service, it just checks the machine answers at all.

Port scanning is the next step: instead of asking *"is the machine alive?"*, we ask
*"is door number 80 open? is door 22 open?"* — one question per port.

### 3. TCP: a real conversation and its handshake

Most services (web, SSH, mail…) speak **TCP**. Before exchanging any data, TCP performs a
polite **3-step handshake**, like a phone call:

```
You  ──── SYN ───▶  Server     "Hi, can we talk?"        (SYN = synchronize)
You  ◀── SYN/ACK ── Server     "Sure, I'm listening."    (ACK = acknowledge)
You  ──── ACK ───▶  Server     "Great, let's go."
```

Every TCP packet carries a set of on/off **flags** that give it meaning:
`SYN` (start), `ACK` (acknowledge), `FIN` (finish), `RST` (reset/refuse),
plus `PSH` and `URG`. The scanner plays with these flags to learn things **without ever
finishing the handshake**.

Two useful facts the scanner relies on:
- If you knock (`SYN`) on an **open** port, the service answers `SYN/ACK`.
- If you send **anything** to a **closed** port, the machine slams the door with a `RST`
  ("reset — nobody's home").

### 4. What "port scanning" actually is

The scanner **forges packets by hand**, sends them to a target port, and **watches how the
target reacts**. The reaction (a `SYN/ACK`, a `RST`, an error, or *silence*) tells us
whether the port is open, closed, or hidden behind a firewall. Different **scan types**
send different flag combinations to squeeze out different information.

### 5. How ft_nmap sends and listens

Two low-level tools make this possible:

- **Raw socket** (to *send*): a normal program lets the operating system build the packet
  headers for it. A **raw socket** lets us write the **IP and TCP headers ourselves**, byte
  by byte — that's how we can set arbitrary flags, a fake source, a custom TTL, etc.
  Building packets by hand is a privileged operation, which is why **ft_nmap must run as
  root** (`sudo`).
- **pcap / BPF filter** (to *listen*): replies don't arrive on our socket in a convenient
  way, so we use the **pcap** library to sniff the network card directly and catch them. A
  **BPF filter** tells pcap "only show me packets coming back from this target, aimed at my
  probe ports", so we ignore all the unrelated traffic.

To match a reply to the right probe, each scan type sends from a **distinct source port**,
and pcap checks the reply is addressed back to that exact port.

### 6. The scan types, and how to read the answers

Every scan sends a probe and classifies the port from what comes back (or from **silence**,
which is itself a clue). Here is exactly what ft_nmap does:

| Scan | What it sends | Reply → verdict |
|------|---------------|-----------------|
| **SYN** | a lone `SYN` (a "half-open" handshake) | `SYN/ACK` → **open** · `RST` → **closed** · nothing → **filtered** |
| **NULL** | a packet with **no flags at all** | `RST` → **closed** · nothing → **open\|filtered** |
| **FIN** | only the `FIN` flag | `RST` → **closed** · nothing → **open\|filtered** |
| **XMAS** | `FIN`+`PSH`+`URG` (lit up "like a Christmas tree") | `RST` → **closed** · nothing → **open\|filtered** |
| **ACK** | only the `ACK` flag | `RST` → **unfiltered** · nothing → **filtered** |

Why these behave differently:

- **SYN scan** is the classic. It starts a handshake but **never finishes it** (it never
  sends the final `ACK`), so the connection is never fully established — hence "half-open"
  and stealthier than a full connection.
- **NULL / FIN / XMAS** exploit a rule of TCP: a **closed** port must answer `RST` to a
  weird packet, while an **open** port is required to **stay silent**. So *silence means the
  port is probably open* — but silence can also mean a firewall ate the packet, hence the
  honest verdict **open|filtered** ("open or filtered, can't be sure"). These scans also
  slip past some simple firewalls that only watch for `SYN`.
- **ACK scan** isn't about open/closed at all — it **maps the firewall**. If a `RST` comes
  back, the packet reached the host: the port is **unfiltered** (no firewall blocking it).
  If nothing comes back, a firewall silently dropped it: **filtered**.

### 7. UDP scanning (a different beast)

**UDP** has no handshake and no flags — you just fire a datagram and hope. So the logic is
inverted and relies on **ICMP** (the same protocol family as `ping`):

| Reply | Verdict |
|-------|---------|
| An **ICMP "port unreachable"** (type 3, code 3) | **closed** |
| A real **UDP answer** from the port | **open** |
| Another ICMP unreachable (codes 1, 2, 9, 10, 13) | **filtered** |
| **Nothing**, even after several tries | **open\|filtered** |

Because the kernel **rate-limits** those ICMP "closed" messages, ft_nmap **retransmits**
each UDP probe a few times before giving up — that's why UDP scans are slower.

### 8. The port states, in plain words

| State | Meaning |
|-------|---------|
| **Open** | A service is listening and answered. |
| **Closed** | The machine is reachable but nothing listens on that port. |
| **Filtered** | A firewall is silently dropping the probe; we can't tell what's behind it. |
| **Unfiltered** | (ACK scan) The port is reachable — not firewalled — but we can't tell open from closed. |
| **Open\|Filtered** | Either open or filtered; the scan type can't distinguish the two. |

When several scan types are run on the same port, ft_nmap combines them into a single
**conclusion** (an "open" from any scan wins).

### 9. Why threads make it fast

Scanning one port means *send, then wait up to a couple of seconds for a reply*. Doing
1024 ports × 6 scan types one after another would be painfully slow, because most of the
time is spent **waiting**. So ft_nmap builds a **work queue** where every job is one
`(port, scan type)` pair. With `--speedup N`, **N worker threads** each pull jobs from the
queue and scan in parallel — while one thread waits for a reply, the others keep working.
Results are written to separate slots, so no thread ever steps on another's data.

### 10. Service names

Finally, for every port ft_nmap looks up the **well-known service** associated with the
port number (via the system's services database) and prints it — `80 → http`,
`22 → ssh`, `53 → domain`… This is the "resolution of service types" the subject asks
for. The optional `--version-detection` goes further: it actually connects to open ports
and reads their banner to guess the **exact software and version**.

---

## Project structure

```
ft_nmap/
├── Makefile            Build rules (relinks only when needed)
├── source.mk           List of src/ source files
├── include/            Public headers (ft_nmap.h, config.h, network.h, worker.h, display.h)
├── src/                The scanner
│   ├── main.c              CLI options table + entry point
│   ├── build_config.c      Validates raw args into a usable config
│   ├── parse_port.c        Parses the --ports list/range
│   ├── parse_scan.c        Parses the --scan bitmask
│   ├── build_target.c      Builds the target list (--ip / --file)
│   ├── cidr.c              Expands CIDR blocks into targets
│   ├── network.c           Raw socket + interface / pcap setup
│   ├── forge_packet.c      Hand-builds the IP/TCP/UDP headers
│   ├── checksum.c          Internet checksum (RFC 1071)
│   ├── send_packet.c       Sends a forged packet
│   ├── set_filter.c        Compiles the BPF capture filter
│   ├── scan_one.c          Sends one probe and interprets the reply
│   ├── worker.c            Thread routine: pulls jobs from the queue
│   ├── nmap.c              Orchestration (prepare → scan each target → cleanup)
│   ├── show.c              Formats the results
│   ├── progress.c          The --progress dashboard
│   ├── version_detect.c    --version-detection banner grabbing
│   ├── reverse_dns.c       --reverse-dns PTR lookup
│   └── ...                 (helpers: source IP, link header length, flags…)
└── parser/             Standalone command-line argument parser (with its own README)
```

