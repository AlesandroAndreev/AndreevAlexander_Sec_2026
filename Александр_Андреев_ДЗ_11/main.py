import json
import math
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

SCRIPT_DIR = Path(__file__).resolve().parent  # папка, где лежит .py
JSON_PATH = SCRIPT_DIR / "botsv1.json"
OUT_WIN = SCRIPT_DIR / "wineventlog_top10.png"
OUT_DNS = SCRIPT_DIR / "dns_top10.png"
OUT_COMBINED = SCRIPT_DIR / "combined_top10.png"


# ---------- helpers ----------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    s = s.lower()
    probs = [s.count(ch) / len(s) for ch in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def base_domain(qname: str) -> str:
    # Упрощённо: последние 2 метки (под .com/.net/.org и т.п. ок).
    parts = [p for p in str(qname).strip(".").split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else str(qname)

# ---------- load ----------

data = json.loads(JSON_PATH.read_text(encoding="utf-8"))

df = pd.json_normalize(data, sep=".")
df.columns = [c.replace(" ", "_") for c in df.columns]


# ---------- split ----------
# В этом датасете DNS события обычно имеют result.LogName == "DNS"
df_dns = df[df.get("result.LogName") == "DNS"].copy()
df_win = df[(df.get("result.LogName").notna()) & (df.get("result.LogName") != "DNS")].copy()


# ---------- WinEventLog: suspicious top-10 ----------
# Минимальный список "подозрительных" ID (можешь расширять)
SUSPICIOUS_EVENT_IDS = {
    4625,  # failed logon
    4688,  # process creation
    4689,  # process termination
    4697,  # service installed (Security)
    4698,  # scheduled task created
    4702,  # scheduled task updated
    4703,  # token right adjusted
    4719,  # audit policy changed
    4720, 4722, 4724, 4740,  # account created/enabled/reset/locked
    4728, 4732, 4756,        # added to privileged groups
    1102,  # audit log cleared
    7045,  # service installed (System)
}

df_win["event_id"] = pd.to_numeric(df_win.get("result.EventCode"), errors="coerce")
df_win["is_suspicious"] = df_win["event_id"].isin(SUSPICIOUS_EVENT_IDS)

win_counts = (
    df_win[df_win["is_suspicious"]]
    .groupby("event_id")
    .size()
    .sort_values(ascending=False)
)

win_top10 = win_counts.head(10)

# ---------- DNS: suspicious top-10 (heuristic score) ----------
# Эвристика: энтропия/длина лейбла/буквы+цифры/паттерн c2|malicious

df_dns["qname"] = df_dns.get("result.QueryName").astype(str)
df_dns["base_domain"] = df_dns["qname"].apply(base_domain)
df_dns["leftmost_label"] = df_dns["qname"].str.split(".").str[0].fillna("")
df_dns["entropy"] = df_dns["leftmost_label"].apply(shannon_entropy)
df_dns["len_label"] = df_dns["leftmost_label"].str.len().fillna(0)

df_dns["has_digits_and_letters"] = (
    df_dns["leftmost_label"].str.contains(r"[a-zA-Z]", regex=True)
    & df_dns["leftmost_label"].str.contains(r"\d", regex=True)
)
df_dns["looks_c2"] = (
    df_dns["qname"].str.contains(r"(^|\.)c2(\.|$)", regex=True)
    | df_dns["qname"].str.contains("malicious", case=False, regex=False)
)

df_dns["dns_score"] = (
    (df_dns["entropy"] > 3.2).astype(int) * 2
    + (df_dns["len_label"] >= 12).astype(int)
    + df_dns["has_digits_and_letters"].astype(int)
    + df_dns["looks_c2"].astype(int) * 3
)

dns_scores = df_dns.groupby("qname")["dns_score"].sum().sort_values(ascending=False)

# Если все score == 0, fallback на частоту запросов
if dns_scores.max() == 0:
    dns_scores = df_dns.groupby("qname").size().sort_values(ascending=False).astype(int)

# Для графика — показывать только >0 (если есть)
dns_scores_plot = dns_scores.copy()
if (dns_scores_plot > 0).any():
    dns_scores_plot = dns_scores_plot[dns_scores_plot > 0]

dns_top10 = dns_scores_plot.head(10)


# ---------- plot 1: WinEventLog ----------
plt.figure(figsize=(10, 5))
win_top10.sort_values(ascending=True).plot(kind="barh")
plt.title("WinEventLog: Top подозрительных EventID (по количеству)")
plt.xlabel("Количество событий")
plt.ylabel("EventID")
plt.tight_layout()
plt.savefig(OUT_WIN, dpi=200)


# ---------- plot 2: DNS ----------
plt.figure(figsize=(10, 5))
dns_top10.sort_values(ascending=True).plot(kind="barh")
plt.title("DNS: Top подозрительных запросов (по эвристическому score)")
plt.xlabel("Score")
plt.ylabel("QueryName")
plt.tight_layout()
plt.savefig(OUT_DNS, dpi=200)


# ---------- plot 3: combined ----------
combined = pd.concat(
    [
        win_top10.rename(lambda x: f"WinEventID {int(x)}" if pd.notna(x) else "WinEventID ?"),
        dns_top10.rename(lambda x: f"DNS {x}"),
    ]
).sort_values(ascending=False).head(10)

plt.figure(figsize=(10, 5))
combined.sort_values(ascending=True).plot(kind="barh")
plt.title("Объединённая визуализация: топ индикаторов (Win counts + DNS score)")
plt.xlabel("Значение (Win=кол-во, DNS=score)")
plt.ylabel("Индикатор")
plt.tight_layout()
plt.savefig(OUT_COMBINED, dpi=200)
