#!/usr/bin/env python3
"""Detección vs. falsos positivos por Paranoia Level (paranoia-sweep.csv) — look informe."""
import csv
import os

import matplotlib.pyplot as plt

import plotstyle as ps

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "paranoia-sweep.csv")

ps.apply()

pls, blocked, fps, n_atk, n_ben = [], [], [], None, None
with open(CSV) as f:
    for row in csv.DictReader(f):
        pls.append(int(row["pl"]))
        blocked.append(int(row["attacks_blocked"]))
        fps.append(int(row["benign_blocked_fp"]))
        n_atk = int(row["attacks_total"])
        n_ben = int(row["benign_total"])

fig, ax = plt.subplots(figsize=(9, 5.2))
ax.grid(True, axis="both")
ax.plot(pls, blocked, "o-", color=ps.SAFE, lw=2.4, ms=8, mec="white", mew=1.2,
        label=f"Ataques bloqueados (de {n_atk})", zorder=4)
ax.plot(pls, fps, "s-", color=ps.DANGER, lw=2.4, ms=8, mec="white", mew=1.2,
        label=f"Falsos positivos (de {n_ben})", zorder=4)
ax.set_xlabel("OWASP CRS Paranoia Level")
ax.set_ylabel("Requests")
ax.set_xticks(pls)
ax.set_xticklabels([f"PL{p}" for p in pls])
ax.set_ylim(-0.5, max(n_atk, n_ben) + 1)
ax.tick_params(length=0)
ax.legend(loc="center left")

if 2 in pls:
    i2 = pls.index(2)
    ax.annotate("punto óptimo\nPL2 + exclusiones", xy=(2, fps[i2]),
                xytext=(2.5, max(n_atk, n_ben) * 0.38), color=ps.MUTED, fontsize=9.5,
                ha="center", linespacing=1.3,
                arrowprops=dict(arrowstyle="-|>", color=ps.MUTED, lw=1.1))

ps.header(
    fig,
    "PL2 es el punto óptimo: PL3/PL4 disparan los falsos positivos",
    "Ataques bloqueados vs. falsos positivos del OWASP CRS por paranoia level",
    "Fuente: sweep PL1–PL4 sobre cluster local · 6 ataques / 10 búsquedas de borde",
)
ps.finish(fig, "paranoia-fp.png")
