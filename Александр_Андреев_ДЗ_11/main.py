#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from datetime import datetime, timezone
import asyncio
import sys

import pandas as pd
import matplotlib.pyplot as plt
import pyshark


DHCP_TYPE_MAP = {
    "1": "Discover",
    "2": "Offer",
    "3": "Request",
    "4": "Decline",
    "5": "ACK",
    "6": "NAK",
    "7": "Release",
    "8": "Inform",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pick_pcap(folder: Path, arg: str | None) -> Path:
    if arg:
        p = (folder / arg).resolve()
        if not p.exists():
            raise FileNotFoundError(f"File not found: {p}")
        return p
    files = sorted(folder.glob("*.pcapng")) + sorted(folder.glob("*.pcap"))
    if not files:
        raise FileNotFoundError("Нет .pcapng/.pcap рядом со скриптом (или передай имя файла).")
    return files[0]


def to_epoch(value) -> float:
    """epoch float OR ISO string like 2004-12-05T19:16:24.317453000Z -> epoch float"""
    if value is None:
        return 0.0

    s = str(value).strip()

    # try epoch-like
    try:
        return float(s)
    except ValueError:
        pass

    # ISO-like
    s = s.replace("Z", "+00:00")

    # cut nanoseconds -> microseconds
    if "." in s:
        head, rest = s.split(".", 1)
        tz_pos = None
        for sep in ("+", "-"):
            pos = rest.find(sep)
            if pos != -1:
                tz_pos = pos
                break
        if tz_pos is not None:
            frac = rest[:tz_pos]
            tz = rest[tz_pos:]
            frac = (frac[:6]).ljust(6, "0")
            s = f"{head}.{frac}{tz}"
        else:
            frac = (rest[:6]).ljust(6, "0")
            s = f"{head}.{frac}"

    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def extract_dhcp(pcap: Path) -> pd.DataFrame:
    loop = asyncio.new_event_loop()

    cap = pyshark.FileCapture(
        str(pcap),
        display_filter="bootp || dhcp",
        keep_packets=False,
        use_json=True,
        eventloop=loop,
    )

    rows = []
    try:
        for pkt in cap:
            layer = getattr(pkt, "bootp", None) or getattr(pkt, "dhcp", None)
            if not layer:
                continue

            # time: frame_info.time_epoch may be ISO in your setup; sniff_timestamp is ISO too
            ts_val = getattr(getattr(pkt, "frame_info", None), "time_epoch", None) or getattr(pkt, "sniff_timestamp", None)
            ts = to_epoch(ts_val)

            # Your field_names show 'type' and 'option.type' -> in pyshark it's usually 'type' / 'option_type'
            msg_raw = getattr(layer, "type", None) or getattr(layer, "option_type", None)
            msg_raw = str(msg_raw) if msg_raw is not None else None
            msg_type = DHCP_TYPE_MAP.get(msg_raw, msg_raw or "Unknown")

            ip_layer = getattr(pkt, "ip", None)

            rows.append({
                "ts": ts,
                "msg_type": msg_type,
                "src_ip": getattr(ip_layer, "src", None),
                "dst_ip": getattr(ip_layer, "dst", None),
                "xid": getattr(layer, "id", None),
                "client_ip": getattr(layer, "ip_client", None),
                "your_ip": getattr(layer, "ip_your", None),
                "server_ip": getattr(layer, "ip_server", None),
                "client_mac": getattr(layer, "hw_mac_addr", None),
            })
    finally:
        cap.close()
        loop.close()

    return pd.DataFrame(rows)


def save_outputs(folder: Path, pcap: Path, df: pd.DataFrame) -> None:
    df.to_csv(folder / "dhcp_events.csv", index=False)

    log_lines = [
        f"[{utc_now()}] PCAP: {pcap.name}",
        f"DHCP/BOOTP events: {len(df)}",
    ]

    if df.empty:
        log_lines.append("DF пуст: pyshark не извлёк события (но tshark их видит).")
        (folder / "triage_log.txt").write_text("\n".join(log_lines), encoding="utf-8")
        return

    # Bar: message types
    stats = df["msg_type"].fillna("Unknown").value_counts()

    plt.figure()
    plt.bar(stats.index.astype(str), stats.values)
    plt.xlabel("DHCP message type")
    plt.ylabel("Count")
    plt.title("DHCP message type distribution")
    plt.tight_layout()
    plt.savefig(folder / "dhcp_type_stats.png", dpi=200)
    plt.close()

    # Line: events per milliseconds (relative)
    plt.figure()

    t_rel = (df["ts"] - df["ts"].min()) * 1000  # ms
    packet_index = range(len(df))

    plt.scatter(t_rel, packet_index)

    plt.xlim(-5, 100)  # ← ВОТ ЭТО магия масштаба

    plt.xlabel("Time (milliseconds)")
    plt.ylabel("Packet index")
    plt.title("Raw DHCP packets")

    plt.tight_layout()
    plt.savefig(folder / "dhcp_activity.png", dpi=200)
    plt.close()

    log_lines += [
        "",
        "Message type counts:",
        *[f"  {k}: {v}" for k, v in stats.to_dict().items()],
        "",
        "Saved files:",
        "  dhcp_events.csv",
        "  dhcp_type_stats.png",
        "  dhcp_activity.png",
        "  triage_log.txt",
    ]
    (folder / "triage_log.txt").write_text("\n".join(log_lines), encoding="utf-8")


def main() -> None:
    folder = Path(__file__).resolve().parent
    arg = sys.argv[1] if len(sys.argv) > 1 else None

    pcap = pick_pcap(folder, arg)
    df = extract_dhcp(pcap)
    save_outputs(folder, pcap, df)

    print("OK. Saved in:", folder)


if __name__ == "__main__":
    main()