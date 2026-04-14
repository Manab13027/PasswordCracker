"""
Reusable tkinter widget helpers.
"""

import tkinter as tk
from tkinter import ttk
from . import styles as S


def card(parent, **kwargs):
    return tk.Frame(parent, bg=S.BG_CARD, bd=0, relief=tk.FLAT, **kwargs)


def label(parent, text, color=None, font=None, **kwargs):
    return tk.Label(
        parent, text=text,
        bg=parent["bg"] if hasattr(parent, "__getitem__") else S.BG_DARK,
        fg=color or S.FG_WHITE,
        font=font or S.FONT_LABEL,
        **kwargs,
    )


def mono_label(parent, text, color=None, **kwargs):
    return label(parent, text, color=color, font=S.FONT_MONO, **kwargs)


def heading(parent, text, **kwargs):
    return label(parent, text, font=S.FONT_UI_LG, color=S.FG_WHITE, **kwargs)


def section_title(parent, text):
    frm = tk.Frame(parent, bg=parent["bg"])
    tk.Label(frm, text=text, bg=parent["bg"], fg=S.ACCENT,
             font=S.FONT_LABEL_B).pack(side=tk.LEFT)
    sep = tk.Frame(frm, bg=S.ACCENT, height=1)
    sep.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))
    return frm


def badge(parent, text, color=S.FG_GREEN):
    return tk.Label(
        parent, text=f" {text} ",
        bg=parent["bg"] if hasattr(parent, "__getitem__") else S.BG_DARK,
        fg=color, font=("Courier New", 10, "bold"),
        relief=tk.SOLID, bd=1,
    )


def btn(parent, text, command, color=S.ACCENT, width=12, **kwargs):
    b = tk.Button(
        parent, text=text, command=command,
        bg=color, fg=S.BG_DARK if color != S.BG_CARD else S.FG_WHITE,
        font=S.FONT_LABEL_B, relief=tk.FLAT, bd=0,
        activebackground=color, activeforeground=S.BG_DARK,
        cursor="hand2", width=width, **kwargs,
    )
    return b


def danger_btn(parent, text, command, **kwargs):
    return btn(parent, text, command, color=S.DANGER, **kwargs)


def scrolled_text(parent, height=10, **kwargs):
    frame = tk.Frame(parent, bg=S.BG_INPUT)
    txt = tk.Text(
        frame, height=height,
        bg=S.BG_INPUT, fg=S.FG_GREEN,
        font=S.FONT_MONO_SM, insertbackground=S.FG_GREEN,
        relief=tk.FLAT, bd=0, wrap=tk.WORD,
        **kwargs,
    )
    scroll = tk.Scrollbar(frame, command=txt.yview, bg=S.BG_CARD)
    txt.configure(yscrollcommand=scroll.set)
    scroll.pack(side=tk.RIGHT, fill=tk.Y)
    txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4)
    frame._text = txt
    return frame


def progress_bar(parent, max_val=100):
    style = ttk.Style()
    style.theme_use("default")
    style.configure(
        "Forensic.Horizontal.TProgressbar",
        troughcolor=S.BG_INPUT,
        background=S.ACCENT,
        bordercolor=S.BG_CARD,
        lightcolor=S.ACCENT,
        darkcolor=S.ACCENT,
    )
    pb = ttk.Progressbar(
        parent, style="Forensic.Horizontal.TProgressbar",
        orient=tk.HORIZONTAL, mode="determinate", maximum=max_val,
    )
    return pb


def separator(parent, color=S.BG_CARD):
    return tk.Frame(parent, bg=color, height=1)
