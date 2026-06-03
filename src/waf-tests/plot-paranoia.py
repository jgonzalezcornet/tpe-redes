#!/usr/bin/env python3
"""Plot the CRS detection-vs-false-positive tradeoff from paranoia-sweep.csv.

Reads paranoia-sweep.csv (written by paranoia-sweep.sh) and renders a line
chart to docs/images/paranoia-fp.png: attacks blocked and benign false
positives as a function of paranoia level.
"""
import csv
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "paranoia-sweep.csv")
OUT = os.path.join(HERE, "..", "..", "docs", "images", "paranoia-fp.png")

pls, blocked, fps, n_atk, n_ben = [], [], [], None, None
with open(CSV) as f:
    for row in csv.DictReader(f):
        pls.append(int(row["pl"]))
        blocked.append(int(row["attacks_blocked"]))
        fps.append(int(row["benign_blocked_fp"]))
        n_atk = int(row["attacks_total"])
        n_ben = int(row["benign_total"])

fig, ax = plt.subplots(figsize=(7, 4.5))
ax.plot(pls, blocked, "o-", color="#2a7", label=f"Ataques bloqueados (de {n_atk})")
ax.plot(pls, fps, "s-", color="#c33", label=f"Falsos positivos (de {n_ben})")
ax.set_xlabel("OWASP CRS Paranoia Level")
ax.set_ylabel("Requests")
ax.set_title("Detección vs. falsos positivos por Paranoia Level")
ax.set_xticks(pls)
ax.set_ylim(-0.5, max(n_atk, n_ben) + 0.5)
ax.grid(True, alpha=0.3)
ax.legend(loc="center left")
ax.annotate(
    "sweet spot\n(PL2 + exclusiones)",
    xy=(2, 1), xytext=(2.4, 4),
    arrowprops=dict(arrowstyle="->", color="gray"), color="gray", fontsize=9,
)
fig.tight_layout()
os.makedirs(os.path.dirname(OUT), exist_ok=True)
fig.savefig(OUT, dpi=120)
print(f"wrote {os.path.normpath(OUT)}")
