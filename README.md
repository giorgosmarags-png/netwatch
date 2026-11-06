# netwatch

A small home network monitoring tool at Layer 2, written in C for Linux. It watches which devices show up on the network, keeps per-device statistics, and raises alerts when it sees unknown devices or suspicious ARP traffic.

I built it to better understand how Ethernet frames and ARP work under the hood, instead of only relying on ready-made tools (Wireshark, arpwatch, etc.). It is not meant to replace them.


## Features

- **Unknown device detection** using a whitelist of known MAC addresses (`known.txt`).
- **Per-device statistics:** packets, bytes, first seen / last seen, last known IP.
- **Vendor identification** from the first 3 bytes of the MAC (a small built-in OUI table), plus detection of *random / locally administered* MACs (e.g. phones using private Wi-Fi addresses).
- **Possible ARP spoofing detection**, using two checks:
  1. The MAC inside the ARP packet (`sender hardware address`) does not match the Ethernet source of the frame.
  2. The same IP suddenly appears with a different MAC than before.
- **Learn mode:** new devices are automatically registered as known and saved to the file on exit.
- **Timestamped logging** to the screen and optionally to a file.
- **Runtime control via signals**, no restart needed (see below).

## Requirements

- Linux (uses `AF_PACKET`; will not work on Windows/macOS)
- `gcc` (e.g. `sudo apt install build-essential`)
- root privileges (raw socket)

No external libraries, only the C standard library and the Linux headers.

## Build

```bash
gcc -Wall -Wextra -O2 -o netwatch netwatch.c
```

## Usage

```
sudo ./netwatch -i <interface> [-k known.txt] [-l netwatch.log] [-L]
```

| Option | Description |
|--------|-------------|
| `-i`   | Network interface (e.g. `eth0`, `wlan0`). Find yours with `ip link`. **Required.** |
| `-k`   | Known devices file (whitelist) |
| `-l`   | Log file (appended to) |
| `-L`   | Learn mode. Also requires `-k`. |

### First run (building the whitelist)



```bash
sudo ./netwatch -i wlan0 -L -k known.txt
```

Let it run for a while, then press Ctrl+C. `known.txt` is written **only on a clean exit** (Ctrl+C / SIGTERM). With `kill -9` nothing is saved. Afterwards, open the file, add names, and delete anything you don't recognize. The "WARN: cannot open known.txt" message on the first run is normal.

### Normal monitoring

```bash
sudo ./netwatch -i wlan0 -k known.txt -l netwatch.log
```

### `known.txt` format

```
# comments start with #
aa:bb:cc:dd:ee:ff Router
11:22:33:44:55:66 Johns-Phone
```

One device per line: MAC (17 characters, at the start of the line), a space, and an optional name.

### Signals

| Signal | Action |
|--------|--------|
| `SIGHUP`  | Reload the whitelist (`sudo pkill -HUP netwatch`) |
| `SIGUSR1` | Print the device table (`sudo pkill -USR1 netwatch`) |
| `SIGINT` / `SIGTERM` | Exit (prints the final table and saves in learn mode) |

## Example output

*(illustrative, to show the message format; the tool's own messages are in Greek)*

```
2026-11-06 20:15:02 [INFO ] netwatch started on wlan0 (MAC aa:bb:cc:dd:ee:ff)
2026-11-06 20:15:04 [INFO ] New ARP mapping: 192.168.1.1 -> 11:22:33:44:55:66
2026-11-06 20:15:09 [ALERT] UNKNOWN DEVICE: 3c:5a:b4:00:11:22 [Unknown]
2026-11-06 20:21:40 [ALERT] POSSIBLE ARP SPOOFING: IP 192.168.1.1 changed MAC 11:22:33:44:55:66 -> de:ad:be:ef:00:01
```

And the table from `SIGUSR1`:

```
MAC                IP              Status     Packets      Bytes  Last seen           Vendor / Name
...
```

## How it works (briefly)

1. Opens a **raw socket** `AF_PACKET` / `SOCK_RAW` and `bind`s it to the requested interface (via `SIOCGIFINDEX`).
2. Reads frames with `recvfrom` in a loop and ignores its own outgoing packets (`PACKET_OUTGOING`).
3. For each frame, it finds or creates an entry for the source MAC in a **hash table** (FNV-1a, 256 buckets, chaining) and updates the statistics.
4. If the frame is ARP, it checks the length and the fields (`hrd`, `pro`, `hln`, `pln`) before reading anything else, then applies the two spoofing checks using a second hash table mapping IP → MAC.
5. Signal handlers only set flags (`volatile sig_atomic_t`) that are read in the main loop; no real work is done inside the handlers. Signals are installed **without** `SA_RESTART`, so `recvfrom` is interrupted with `EINTR` and the loop reacts immediately.



## Future ideas

- [ ] Per-IP rate limit / cooldown on alerts
- [ ] Size limit on the tables (LRU eviction)
- [ ] Fix the parsing in `load_known` (`%n` in `sscanf`)
- [ ] `memcpy` the ARP fields into a local struct instead of casting (alignment-safe, e.g. on ARM)
- [ ] Load the full IEEE OUI file
- [ ] JSON / syslog output
- [ ] Optional promiscuous mode via `PACKET_ADD_MEMBERSHIP`
- [ ] NDP spoofing detection (IPv6)
- [ ] Automated tests with forged frames (scapy) and fuzzing `handle_arp` with AFL++/libFuzzer

## What I learned

- How an Ethernet frame and an ARP packet are structured, and why ARP has no authentication at all.
- Raw sockets on Linux, and the difference between creating a socket and binding it to an interface.
- Safe signal handling (flags instead of work inside the handler, `EINTR`).
- That a security tool has to be robust itself: it reads untrusted data, so checking lengths before every read is essential.

## Layout

```
netwatch.c   # all the code (single file)
known.txt    # whitelist (created with -L or by hand)
netwatch.log # log (if -l is given)
```



