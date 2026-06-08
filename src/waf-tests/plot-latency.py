#!/usr/bin/env python3
"""Gráfico de overhead de latencia del WAF (latency-overhead.csv) — look informe."""
import csv
import os

import matplotlib.pyplot as plt

import plotstyle as ps

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "latency-overhead.csv")

ps.apply()

data = {}
with open(CSV) as f:
    for r in csv.DictReader(f):
        data[r["scenario"]] = r
off, on = data["sin_waf"], data["con_waf"]

metrics = [("p50", "p50"), ("p95", "p95"), ("p99", "p99"), ("mean_ms", "media")]
off_vals = [float(off[k]) for k, _ in metrics]
on_vals = [float(on[k]) for k, _ in metrics]
labels = [lbl for _, lbl in metrics]
dmean = float(on["mean_ms"]) - float(off["mean_ms"])

fig, ax = plt.subplots(figsize=(10, 5.6))
x = range(len(metrics))
w = 0.38
b1 = ax.bar([i - w / 2 for i in x], off_vals, w, label=f"sin WAF   ·  {float(off['rps']):.0f} req/s",
            color=ps.NEUTRAL, edgecolor="white", linewidth=0.6, zorder=3)
b2 = ax.bar([i + w / 2 for i in x], on_vals, w, label=f"con WAF  ·  {float(on['rps']):.0f} req/s",
            color=ps.SAFE, edgecolor="white", linewidth=0.6, zorder=3)
ax.bar_label(b1, fmt="%.0f", fontsize=9.5, padding=3, color=ps.MUTED)
ax.bar_label(b2, fmt="%.0f", fontsize=9.5, padding=3, color=ps.INK, fontweight="bold")

# delta por par (en gris, arriba)
for i, (o, n) in enumerate(zip(off_vals, on_vals)):
    ax.annotate(f"+{n - o:.0f} ms", (i, max(o, n)), textcoords="offset points",
                xytext=(0, 18), ha="center", fontsize=8.5, color=ps.DANGER, fontweight="bold")

ax.set_xticks(list(x))
ax.set_xticklabels([f"{l}" for l in labels])
ax.set_ylabel("Latencia por request (ms)")
ax.set_ylim(0, max(off_vals + on_vals) * 1.30)
ax.legend(loc="upper left", handlelength=1.1, handleheight=1.1)
ax.tick_params(length=0)

ps.header(
    fig,
    f"El WAF agrega solo ~{dmean:.0f} ms de latencia por request",
    "Latencia con vs. sin inspección L7 (ApacheBench, 25 conexiones concurrentes) — protección imperceptible para el cliente",
    "Fuente: cluster local · ModSecurity + OWASP CRS · medición ApacheBench",
)
ps.finish(fig, "latency-overhead.png")
