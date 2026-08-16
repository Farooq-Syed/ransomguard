"""Save evaluation results as JSON + matplotlib charts."""
from __future__ import annotations

import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def save_json(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def bar_chart(x_labels, series: dict, path: str, title: str, ylabel: str, ylim=(0, 1.0)):
    import numpy as np
    x = np.arange(len(x_labels))
    width = 0.35
    fig, ax = plt.subplots(figsize=(max(7, 1.8 * len(x_labels)), 5))
    colors = {"v1": "#c44e52", "v2": "#55a868", "v1 -o-": "#c44e52", "v2 -o-": "#55a868"}
    for i, (label, values) in enumerate(series.items()):
        offset = (i - len(series) / 2) * width
        ax.bar(x + offset, values, width, label=label, color=colors.get(label))
    ax.set_xticks(x)
    ax.set_xticklabels(x_labels, rotation=20, ha="right")
    ax.set_ylim(*ylim)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend(loc="lower left")
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)


def line_chart(x_labels, series: dict, path: str, title: str, ylabel: str, ylim=(0, 1.05)):
    fig, ax = plt.subplots(figsize=(9, 5))
    for label, values in series.items():
        ax.plot(x_labels, values, marker="o", label=label)
    ax.set_ylim(*ylim)
    ax.set_ylabel(ylabel)
    ax.set_xlabel("fold (training window -> future test bucket)")
    ax.set_title(title)
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)
