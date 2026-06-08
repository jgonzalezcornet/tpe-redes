#!/usr/bin/env python3
"""Gráficos de anomaly scoring (anomaly-scores.csv, PL2) — look informe.

Genera dos PNG en docs/images/:
  - anomaly-scores.png    : score de cada request (benigno vs ataque) + umbral.
  - anomaly-threshold.png : detección vs FP según el umbral (derivado de los scores).
"""
import csv
import os

import matplotlib.pyplot as plt
from matplotlib.patches import Patch

import plotstyle as ps

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "anomaly-scores.csv")
THRESHOLD = 5  # default CRS / elegido

ps.apply()

rows = []
with open(CSV) as f:
    for r in csv.DictReader(f):
        rows.append((r["label"], int(r["score"]), r["payload"]))

# ---------- 1) distribución de scores ----------
rows_sorted = sorted(rows, key=lambda x: x[1])
labels = [p if len(p) <= 32 else p[:29] + "…" for _, _, p in rows_sorted]
scores = [s for _, s, _ in rows_sorted]
colors = [ps.SAFE if lbl == "benign" else ps.DANGER for lbl, _, _ in rows_sorted]

fig, ax = plt.subplots(figsize=(9.5, 7.2))
ax.grid(True, axis="x")
ax.grid(False, axis="y")
bars = ax.barh(range(len(scores)), scores, color=colors, edgecolor="white", linewidth=0.6, zorder=3)
ax.set_yticks(range(len(scores)))
ax.set_yticklabels(labels, fontsize=8.5, fontfamily="monospace")
ax.set_ylim(-0.6, len(scores) - 0.4)
ax.axvline(THRESHOLD, color=ps.INK, linestyle=(0, (4, 3)), linewidth=1.2, zorder=4)
ax.text(THRESHOLD + 0.6, 2.4, f"umbral de\nbloqueo = {THRESHOLD}",
        color=ps.INK, fontsize=9.5, fontweight="bold", linespacing=1.3, va="center")
ax.set_xlabel("Inbound anomaly score (PL2)")
ax.tick_params(length=0)
ax.legend(handles=[Patch(color=ps.SAFE, label="tráfico benigno"),
                   Patch(color=ps.DANGER, label="ataque")],
          loc="lower right")

ps.header(
    fig,
    "Los ataques cruzan el umbral de bloqueo; el tráfico benigno casi no suma",
    "Anomaly score acumulado por request a PL2 — bloqueo al alcanzar el umbral",
    "Fuente: cluster local · OWASP CRS PL2 · score medido por request",
    x=0.012,
)
ps.finish(fig, "anomaly-scores.png", rect=(0, 0.035, 1, 0.85))

# ---------- 2) tradeoff detección/FP vs umbral ----------
atk = [s for lbl, s, _ in rows if lbl == "attack"]
ben = [s for lbl, s, _ in rows if lbl == "benign"]
n_atk, n_ben = len(atk), len(ben)
ts = list(range(1, max(atk + ben) + 2))
blocked = [sum(1 for s in atk if s >= t) for t in ts]
fps = [sum(1 for s in ben if s >= t) for t in ts]

fig, ax = plt.subplots(figsize=(9, 5.2))
ax.grid(True, axis="both")
ax.plot(ts, blocked, "-", color=ps.SAFE, lw=2.4, label=f"Ataques bloqueados (de {n_atk})", zorder=4)
ax.plot(ts, fps, "-", color=ps.DANGER, lw=2.4, label=f"Falsos positivos (de {n_ben})", zorder=4)
ax.axvline(THRESHOLD, color=ps.INK, linestyle=(0, (4, 3)), linewidth=1.2, zorder=3)
ax.text(THRESHOLD + 0.3, n_atk * 0.5, f"umbral elegido = {THRESHOLD}", color=ps.INK,
        fontsize=9.5, fontweight="bold")
ax.axvline(11, color=ps.MUTED, linestyle=":", linewidth=1.2, zorder=3)
ax.text(11 + 0.4, n_atk * 0.24, "T≥11 limpia el FP\npero pierde 5 ataques\n(score 5)",
        color=ps.MUTED, fontsize=8.5, linespacing=1.3)
ax.set_xlabel("inbound_anomaly_score_threshold")
ax.set_ylabel("Requests")
ax.set_ylim(-0.4, max(n_atk, n_ben) + 1)
ax.tick_params(length=0)
ax.legend(loc="upper right")

ps.header(
    fig,
    "El umbral 5 maximiza la detección; subirlo solo sacrifica ataques",
    "Ataques bloqueados vs. falsos positivos según el anomaly threshold (PL2)",
    "Fuente: cluster local · derivado del score medido por request (PL2)",
)
ps.finish(fig, "anomaly-threshold.png")
