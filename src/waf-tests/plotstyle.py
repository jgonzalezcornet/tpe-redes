"""Estilo visual compartido para los gráficos del WAF (look de informe ejecutivo).

Paleta sobria y coherente, tipografía limpia, ejes sin spines superiores/derechas,
grilla suave detrás, y un encabezado tipo "data journalism": titular en negrita que
dice la CONCLUSIÓN + subtítulo gris + hairline + pie de fuente.

Uso:
    import plotstyle as ps
    ps.apply()
    fig, ax = plt.subplots(figsize=(10, 5.6))
    ...
    ps.header(fig, "Titular con la conclusión", "Subtítulo explicativo", "Fuente: ...")
    ps.finish(fig, "salida.png")
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

# ---- paleta ----
INK = "#1d2733"      # texto / titulares
MUTED = "#5b6770"    # subtítulos, ticks, pie
GRID = "#e7eaef"     # grilla
HAIR = "#d4d9e0"     # hairline del encabezado
DANGER = "#d1495b"   # "sin WAF" / amenaza
SAFE = "#2a9d8f"     # "con WAF" / protegido
NEUTRAL = "#aab2bd"  # baseline
ACCENT = "#1d6fb8"   # acento azul

IMG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs", "images")


def apply():
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
        "font.size": 11,
        "text.color": INK,
        "axes.edgecolor": "#c4cad3",
        "axes.linewidth": 0.9,
        "axes.labelcolor": MUTED,
        "axes.labelsize": 10.5,
        "axes.titlesize": 11,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.axisbelow": True,
        "axes.grid": True,
        "axes.grid.axis": "y",
        "grid.color": GRID,
        "grid.linewidth": 1.0,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.frameon": False,
        "legend.fontsize": 9.5,
        "figure.dpi": 160,
        "savefig.dpi": 160,
    })


def header(fig, title, subtitle=None, footer=None, x=0.013):
    """Encabezado editorial: titular (conclusión) + subtítulo + hairline + pie."""
    fig.text(x, 0.965, title, ha="left", va="top", fontsize=16, fontweight="bold", color=INK)
    if subtitle:
        fig.text(x, 0.908, subtitle, ha="left", va="top", fontsize=10.5, color=MUTED)
    fig.add_artist(Line2D([x, 1 - x], [0.876, 0.876], color=HAIR, lw=1.1))
    if footer:
        fig.text(x, 0.018, footer, ha="left", va="bottom", fontsize=8, color=MUTED, style="italic")


def finish(fig, filename, rect=(0, 0.035, 1, 0.845)):
    """tight_layout dejando lugar para encabezado/pie, y guardar en docs/images/."""
    fig.tight_layout(rect=rect)
    out = os.path.join(IMG, filename)
    fig.savefig(out, facecolor="white")
    print(f"wrote docs/images/{filename}")
