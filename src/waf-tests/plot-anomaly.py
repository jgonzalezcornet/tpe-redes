#!/usr/bin/env python3
"""Gráficos de anomaly scoring a partir de anomaly-scores.csv (PL2).

Genera dos PNG en docs/images/:
  - anomaly-scores.png    : score de cada request (benigno vs ataque) + línea de threshold.
  - anomaly-threshold.png : detección vs FP según el threshold (calculado de los scores).
"""
import csv
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "anomaly-scores.csv")
IMG = os.path.join(HERE, "..", "..", "docs", "images")
THRESHOLD = 5  # default CRS / elegido

rows = []
with open(CSV) as f:
    for r in csv.DictReader(f):
        rows.append((r["label"], int(r["score"]), r["payload"]))

# ---------- 1) distribución de scores ----------
rows_sorted = sorted(rows, key=lambda x: x[1])
labels = [p if len(p) <= 34 else p[:31] + "…" for _, _, p in rows_sorted]
scores = [s for _, s, _ in rows_sorted]
colors = ["#2a7" if lbl == "benign" else "#c33" for lbl, _, _ in rows_sorted]

fig, ax = plt.subplots(figsize=(8, 7))
ax.barh(range(len(scores)), scores, color=colors)
ax.set_yticks(range(len(scores)))
ax.set_yticklabels(labels, fontsize=8, fontfamily="monospace")
ax.axvline(THRESHOLD, color="#333", linestyle="--", linewidth=1)
ax.text(THRESHOLD + 0.3, 0.2, f"threshold = {THRESHOLD}", color="#333", fontsize=9)
ax.set_xlabel("Inbound anomaly score (PL2)")
ax.set_title("Anomaly score por request — benigno (verde) vs ataque (rojo)")
from matplotlib.patches import Patch

ax.legend(handles=[Patch(color="#2a7", label="benigno"), Patch(color="#c33", label="ataque")],
          loc="lower right")
fig.tight_layout()
fig.savefig(os.path.join(IMG, "anomaly-scores.png"), dpi=120)
print("wrote docs/images/anomaly-scores.png")

# ---------- 2) tradeoff detección/FP vs threshold ----------
atk = [s for lbl, s, _ in rows if lbl == "attack"]
ben = [s for lbl, s, _ in rows if lbl == "benign"]
n_atk, n_ben = len(atk), len(ben)
ts = list(range(1, max(atk + ben) + 2))
blocked = [sum(1 for s in atk if s >= t) for t in ts]   # ataques bloqueados
fps = [sum(1 for s in ben if s >= t) for t in ts]        # benignos bloqueados (FP)

fig, ax = plt.subplots(figsize=(8, 4.8))
ax.plot(ts, blocked, "-", color="#2a7", label=f"Ataques bloqueados (de {n_atk})")
ax.plot(ts, fps, "-", color="#c33", label=f"Falsos positivos (de {n_ben})")
ax.axvline(THRESHOLD, color="#333", linestyle="--", linewidth=1)
ax.text(THRESHOLD + 0.4, n_atk * 0.55, f"threshold elegido = {THRESHOLD}", color="#333", fontsize=9)
ax.axvline(11, color="#888", linestyle=":", linewidth=1)
ax.text(11 + 0.4, n_atk * 0.30, "T≥11 limpia el FP\npero pierde 5 ataques\n(score 5)",
        color="#888", fontsize=8)
ax.set_xlabel("inbound_anomaly_score_threshold")
ax.set_ylabel("Requests")
ax.set_title("Detección vs. falsos positivos según el anomaly threshold (PL2)")
ax.grid(True, alpha=0.3)
ax.legend(loc="upper right")
fig.tight_layout()
fig.savefig(os.path.join(IMG, "anomaly-threshold.png"), dpi=120)
print("wrote docs/images/anomaly-threshold.png")
