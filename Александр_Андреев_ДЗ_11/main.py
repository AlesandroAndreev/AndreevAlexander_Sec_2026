#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from datetime import datetime, timezone
import asyncio

import pandas as pd
import matplotlib.pyplot as plt
import pyshark

DHCP_TYPE_MAP = {"1": "Discover", "2": "Offer", "3": "Request", "5": "ACK", "6": "NAK"}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pick_pcap(folder: Path) -> Path:
    files = sorted(folder.glob("*.pcapng")) + sorted(folder.glob("*.pcap"))
    if not files:
        raise FileNotFoundError("Нет .pcapng/.pcap рядом со скриптом.")
    return files[0]


def to_epoch(iso_ts: str) -> float:
    s = str(iso_ts).strip().replace("Z", "+00:00")
    if "." in s and "+" in s:
        head, rest = s.split(".", 1)
        frac, tz = rest.split("+", 1)
        frac = (frac[:6]).ljust(6, "0")
        s = f"{head}.{frac}+{tz}"
    dt = datetime.fromisoformat(s)
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def handshake_type(pkt) -> str:
    code = str(pkt.dhcp.option.type_tree[0].dhcp)  # DHCP Option 53
    return DHCP_TYPE_MAP.get(code, code)


def extract_dhcp(pcap: Path) -> pd.DataFrame:
    loop = asyncio.new_event_loop()
    cap = pyshark.FileCapture(str(pcap), display_filter="dhcp", keep_packets=False, use_json=True, eventloop=loop)

    rows = []
    for pkt in cap:
        dhcp = pkt.dhcp
        rows.append({
            "ts": to_epoch(pkt.sniff_timestamp),
            "handshake": handshake_type(pkt),
            "xid": dhcp.id,
            "client_mac": dhcp.mac_addr,
            "client_ip": dhcp.ip.client,
            "your_ip": dhcp.ip.your,
            "server_ip": dhcp.ip.server,
        })

    cap.close()
    loop.close()
    return pd.DataFrame(rows)


def main() -> None:
    folder = Path(__file__).resolve().parent
    pcap = pick_pcap(folder)

    df = extract_dhcp(pcap)
    df.to_csv(folder / "dhcp_events.csv", index=False)

    # Bar: распределение Discover/Offer/Request/ACK
    stats = df["handshake"].value_counts()
    plt.figure()
    plt.bar(stats.index.astype(str), stats.values)
    plt.yticks(range(0, 2, 1))
    plt.xlabel("DHCP handshake type (Option 53)")
    plt.ylabel("Count")
    plt.title("DHCP DORA distribution")
    plt.tight_layout()
    plt.savefig(folder / "dhcp_type_stats.png", dpi=200)
    plt.close()

    # Raw: 4 точки (по пакетам)
    plt.figure()
    t_rel = (df["ts"] - df["ts"].min()) * 1000
    plt.scatter(t_rel, range(len(df)))
    plt.xlim(-5, max(100, float(t_rel.max()) + 10))
    plt.xlabel("Time (ms from first packet)")
    plt.ylabel("Packet index")
    plt.title("Raw DHCP packets (DORA)")
    plt.tight_layout()
    plt.savefig(folder / "dhcp_activity.png", dpi=200)
    plt.close()

    # Log
    lines = [
        f"[{utc_now()}] PCAP: {pcap.name}",
        f"DHCP packets: {len(df)}",
        "Counts:",
        *[f"  {k}: {v}" for k, v in stats.to_dict().items()],
    ]
    (folder / "triage_log.txt").write_text("\n".join(lines), encoding="utf-8")

    print("OK")


if __name__ == "__main__":
    main()