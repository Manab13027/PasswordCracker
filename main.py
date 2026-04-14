#!/usr/bin/env python3
from __future__ import annotations
"""
WD My Passport — Forensic Password Recovery Demo
=================================================
Educational tool for demonstrating password cracking techniques
on WD My Passport encrypted external drives.

Usage:
    python3 main.py             # simulation mode (no real drive needed)
    python3 main.py --live      # live mode (real WD drive + sudo recommended)

Author: Forensics Lab Demo
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox

# Make sure imports work from project root
sys.path.insert(0, os.path.dirname(__file__))

from ui import styles as S
from ui.drive_panel import DrivePanel
from ui.hash_panel import HashPanel
from ui.crack_panel import CrackPanel
from ui.edu_panel import EduPanel
from core.wd_security import SimulatedDrive, make_demo_drive


class App(tk.Tk):
    def __init__(self, demo_mode: bool = True):
        super().__init__()
        self.demo_mode = demo_mode
        self.selected_drive = None
        self.sim_drive: SimulatedDrive | None = None

        self._setup_window()
        self._build_header()
        self._build_tabs()
        self._build_footer()

        # Pre-load simulation drive
        if demo_mode:
            self.sim_drive = make_demo_drive("password123")

    # ── Window setup ─────────────────────────────────────────────────────────

    def _setup_window(self):
        self.title("WD My Passport — Forensic Password Recovery")
        self.configure(bg=S.BG_DARK)
        self.geometry("1200x800")
        self.minsize(900, 640)

        # Center window
        self.update_idletasks()
        w, h = 1200, 800
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self):
        header = tk.Frame(self, bg=S.BG_PANEL, height=64)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        left = tk.Frame(header, bg=S.BG_PANEL)
        left.pack(side=tk.LEFT, padx=S.PAD_LG, pady=S.PAD_SM)

        tk.Label(left, text="WD My Passport",
                 bg=S.BG_PANEL, fg=S.ACCENT, font=S.FONT_TITLE).pack(side=tk.LEFT)
        tk.Label(left, text=" — Forensic Password Recovery Demo",
                 bg=S.BG_PANEL, fg=S.FG_MUTED, font=("Helvetica Neue", 14)).pack(side=tk.LEFT)

        right = tk.Frame(header, bg=S.BG_PANEL)
        right.pack(side=tk.RIGHT, padx=S.PAD_LG)

        mode_text = "SIMULATION MODE" if self.demo_mode else "LIVE MODE"
        mode_color = S.FG_YELLOW if self.demo_mode else S.FG_GREEN
        tk.Label(right, text=f"● {mode_text}",
                 bg=S.BG_PANEL, fg=mode_color, font=S.FONT_LABEL_B).pack(side=tk.RIGHT)

        # Divider
        tk.Frame(self, bg=S.ACCENT, height=2).pack(fill=tk.X)

    # ── Tabs ──────────────────────────────────────────────────────────────────

    def _build_tabs(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Forensic.TNotebook",
                         background=S.BG_DARK,
                         tabmargins=[0, 0, 0, 0])
        style.configure("Forensic.TNotebook.Tab",
                         background=S.BG_PANEL,
                         foreground=S.FG_MUTED,
                         font=S.FONT_LABEL_B,
                         padding=[16, 6],
                         borderwidth=0)
        style.map("Forensic.TNotebook.Tab",
                  background=[("selected", S.BG_CARD)],
                  foreground=[("selected", S.ACCENT)])

        self.notebook = ttk.Notebook(self, style="Forensic.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # ── Tab 1: Drive Detection ────────────────────────────────────────
        self.drive_panel = DrivePanel(
            self.notebook,
            on_drive_selected=self._on_drive_selected,
            demo_mode=self.demo_mode,
        )
        self.notebook.add(self.drive_panel, text="  1. Drive Detection  ")

        # ── Tab 2: Hash / Challenge Extraction ───────────────────────────
        self.hash_panel = HashPanel(self.notebook, demo_mode=self.demo_mode)
        self.hash_panel.bind("<<WDECBReady>>", self._on_wd_ecb_ready)
        self.notebook.add(self.hash_panel, text="  2. Challenge Extraction  ")

        # ── Tab 3: Password Cracking ──────────────────────────────────────
        self.crack_panel = CrackPanel(self.notebook, demo_mode=self.demo_mode)
        if self.demo_mode and self.sim_drive:
            self.crack_panel.set_sim_drive(self.sim_drive)
        self.notebook.add(self.crack_panel, text="  3. Password Cracking  ")

        # ── Tab 4: Education Reference ────────────────────────────────────
        self.edu_panel = EduPanel(self.notebook)
        self.notebook.add(self.edu_panel, text="  4. Reference  ")

    # ── Footer ────────────────────────────────────────────────────────────────

    def _build_footer(self):
        tk.Frame(self, bg=S.BG_CARD, height=1).pack(fill=tk.X)
        footer = tk.Frame(self, bg=S.BG_PANEL, height=28)
        footer.pack(fill=tk.X)
        footer.pack_propagate(False)

        tk.Label(footer,
                 text="For authorized security testing and educational use only.",
                 bg=S.BG_PANEL, fg=S.FG_MUTED, font=S.FONT_UI_SM).pack(side=tk.LEFT, padx=S.PAD)

        tk.Label(footer,
                 text="Python 3  |  tkinter  |  hashlib  |  SCSI SPC-4",
                 bg=S.BG_PANEL, fg=S.FG_MUTED, font=S.FONT_UI_SM).pack(side=tk.RIGHT, padx=S.PAD)

    # ── Events ────────────────────────────────────────────────────────────────

    def _on_drive_selected(self, drive: dict):
        self.selected_drive = drive

        # Create or reuse sim drive
        if drive.get("_demo"):
            if self.sim_drive is None:
                self.sim_drive = make_demo_drive("password123")
        else:
            self.sim_drive = None

        self.hash_panel.set_drive(drive, self.sim_drive)
        if self.sim_drive:
            self.crack_panel.set_sim_drive(self.sim_drive)

        # Switch to extraction tab
        self.notebook.select(1)

        name = drive.get("media_name", drive.get("disk_id"))
        tag = " [simulation]" if drive.get("_demo") else ""
        self.title(f"WD My Passport — {name}{tag}")

    def _on_wd_ecb_ready(self, _event=None):
        """WD ECB challenge extracted — wire the WDECBDrive to the crack panel."""
        ecb_drive = self.hash_panel._wd_ecb_drive
        if ecb_drive is not None:
            self.crack_panel.set_live_drive(ecb_drive)
            self.notebook.select(2)   # jump to crack tab


def main():
    demo_mode = "--live" not in sys.argv

    if not demo_mode:
        _py = sys.executable
        _is_linux = sys.platform.startswith("linux")
        _is_root  = os.getuid() == 0

        try:
            import usb.core  # noqa
            _pyusb_ok = True
        except ImportError:
            _pyusb_ok = False

        import shutil
        _sgraw_ok = shutil.which("sg_raw") is not None

        print("=" * 60)
        print("  LIVE MODE")
        print(f"  Platform : {'Linux' if _is_linux else 'macOS/other'}")
        print(f"  Root     : {'yes' if _is_root else 'NO — some operations may fail'}")
        print(f"  pyusb    : {'OK' if _pyusb_ok else 'missing'}")
        print(f"  sg_raw   : {'OK' if _sgraw_ok else 'missing'}")
        print("=" * 60)

        if not _pyusb_ok and not _sgraw_ok:
            print()
            print("  Neither pyusb nor sg_raw found.")
            print(f"  Install one:")
            if _is_linux:
                print("    sudo apt install sg3-utils")
                print(f"    OR: {_py} -m pip install pyusb")
            else:
                print(f"    {_py} -m pip install pyusb --break-system-packages")
                print("    brew install libusb")
            print()
            print("  Falling back to SIMULATION MODE.")
            print("=" * 60)
            demo_mode = True
        elif not _is_root:
            print()
            if _is_linux:
                print("  TIP: Run with sudo for reliable USB access:")
                print(f"    sudo {_py} main.py --live")
                print()
                print("  Continuing in LIVE MODE anyway (may work with udev rules).")
            else:
                print("  macOS requires sudo for raw USB access.")
                print(f"    sudo {_py} main.py --live")
                print()
                print("  Continuing in LIVE MODE (use Manual Entry if auto fails).")
            print("=" * 60)

    app = App(demo_mode=demo_mode)

    if demo_mode:
        msg = (
            "SIMULATION MODE\n\n"
            "No real drive is required.\n\n"
            "Steps to follow:\n"
            "  1. Click 'Scan for Drives' on the Detection tab\n"
            "  2. Select the simulated WD drive\n"
            "  3. Go to Challenge Extraction and click 'Extract Challenge'\n"
            "  4. Go to Password Cracking and launch an attack\n\n"
            "Use Tab 4 (Reference) for educational background.\n\n"
            "To use a real drive: python3 main.py --live  (requires sudo)"
        )
        messagebox.showinfo("Forensic Password Recovery Demo", msg)

    app.mainloop()


if __name__ == "__main__":
    main()
