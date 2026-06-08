#!/usr/bin/env python3
"""Disponibilidad bajo ataque (availability-{off,on}.csv) — look informe."""
import csv
import os

import matplotlib.pyplot as plt

import plotstyle as ps

HERE = os.path.dirname(os.path.abspath(__file__))
ATTACK_AT = float(os.environ.get("ATTACK_AT", "12"))
YCAP = 90

ps.apply()


def load(name):
    t, ms, code = [], [], []
    with open(os.path.join(HERE, name)) as f:
        for r in csv.DictReader(f):
            t.append(float(r["t_sec"]))
            ms.append(float(r["latency_ms"]))
            code.append(r["http_code"])
    ok = sum(1 for c in code if c == "200")
    return t, ms, code, (100.0 * ok / len(code) if code else 0)


fig, ax = plt.subplots(figsize=(10, 5.6))
ax.grid(True, axis="both")  # líneas: grilla en ambos ejes, suave
avail = {}
off = None
for name, color, lbl in [("availability-off.csv", ps.DANGER, "sin WAF"),
                         ("availability-on.csv", ps.SAFE, "con WAF")]:
    if not os.path.exists(os.path.join(HERE, name)):
        continue
    t, ms, code, av = load(name)
    avail[lbl] = av
    if "off" in name:
        off = (t, ms, code)
    msc = [min(m, YCAP) for m in ms]
    ax.plot(t, msc, "-", color=color, lw=2.0, alpha=0.95, zorder=4 if "on" in name else 3)
    ft = [tt for tt, c in zip(t, code) if c != "200"]
    fm = [min(m, YCAP) for m, c in zip(ms, code) if c != "200"]
    if ft:
        ax.scatter(ft, fm, color=color, marker="x", s=42, lw=1.6, zorder=6)
        ax.text((min(ft) + max(ft)) / 2, YCAP * 0.10,
                f"✕  {len(ft)} requests fallidos (502/503)", color=ps.DANGER,
                fontsize=8.5, ha="center", va="center")

if off:
    t, ms, code = off
    ft = [tt for tt, c in zip(t, code) if c != "200"]
    if ft:
        d0, d1 = min(ft), max(ft)
        ax.axvspan(d0, d1, color=ps.DANGER, alpha=0.08, zorder=1)
        ax.text((d0 + d1) / 2, YCAP * 0.60, f"tienda caída\n≈ {d1 - d0:.0f} s",
                color=ps.DANGER, fontsize=13, ha="center", va="center", fontweight="bold",
                linespacing=1.3)
    rec = max((p for p in zip(t, ms, code) if p[2] == "200" and p[0] >= ATTACK_AT),
              key=lambda p: p[1], default=None)
    if rec and rec[1] > YCAP:
        ax.annotate(f"recuperación\n~{rec[1]:.0f} ms", xy=(rec[0], YCAP),
                    xytext=(rec[0] + 2.4, YCAP * 0.56), fontsize=8.5, color=ps.DANGER,
                    ha="left", linespacing=1.2,
                    arrowprops=dict(arrowstyle="-|>", color=ps.DANGER, lw=1.0))

ax.axvline(ATTACK_AT, color=ps.INK, linestyle=(0, (4, 3)), linewidth=1.1, zorder=2)
ax.text(ATTACK_AT + 0.5, YCAP * 0.93, "ataque", fontsize=9.5, color=ps.INK, fontweight="bold")
ax.text(ATTACK_AT + 0.5, YCAP * 0.865, "GET /utility/panic", fontsize=8.5, color=ps.MUTED)

# badges de disponibilidad a la derecha
ax.text(0.992, 0.93, f"con WAF: {avail.get('con WAF', 0):.0f}%", transform=ax.transAxes,
        ha="right", va="top", fontsize=11, color=ps.SAFE, fontweight="bold")
ax.text(0.992, 0.85, f"sin WAF: {avail.get('sin WAF', 0):.0f}%", transform=ax.transAxes,
        ha="right", va="top", fontsize=11, color=ps.DANGER, fontweight="bold")

ax.set_ylim(0, YCAP * 1.02)
ax.set_xlim(0, max(t))
ax.set_xlabel("Tiempo (s)")
ax.set_ylabel("Latencia del tráfico legítimo (ms)")
ax.tick_params(length=0)

dur = 0
if off:
    ft = [tt for tt, c in zip(off[0], off[2]) if c != "200"]
    dur = (max(ft) - min(ft)) if ft else 0
ps.header(
    fig,
    f"Sin WAF, un solo ataque deja la tienda caída ~{dur:.0f} segundos",
    "Disponibilidad del tráfico legítimo bajo un ataque a /utility/panic — con WAF la tienda ni se entera (100%)",
    "Fuente: cluster local · 40 s de muestreo, ataque en t=12 s · ModSecurity + OWASP CRS",
)
ps.finish(fig, "availability.png")
