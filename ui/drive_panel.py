"""
Drive Detection Panel
Displays connected WD drives and allows the user to select one.
"""

import tkinter as tk
from tkinter import messagebox
import threading

from . import styles as S
from . import widgets as W
from core.drive_detector import detect_drives, DEMO_DRIVES
from core.wd_security import SimulatedDrive, probe_drive_usb


class DrivePanel(tk.Frame):
    def __init__(self, parent, on_drive_selected, demo_mode=True, **kwargs):
        super().__init__(parent, bg=S.BG_PANEL, **kwargs)
        self.on_drive_selected = on_drive_selected
        self.demo_mode = demo_mode
        self.drives = []
        self._build()

    def _build(self):
        # Title bar
        title_row = tk.Frame(self, bg=S.BG_PANEL)
        title_row.pack(fill=tk.X, padx=S.PAD, pady=(S.PAD, S.PAD_SM))
        tk.Label(title_row, text="DRIVE DETECTION", bg=S.BG_PANEL,
                 fg=S.ACCENT, font=S.FONT_LABEL_B).pack(side=tk.LEFT)

        mode_text = " [SIMULATION MODE] " if self.demo_mode else " [LIVE MODE] "
        mode_color = S.FG_YELLOW if self.demo_mode else S.FG_GREEN
        tk.Label(title_row, text=mode_text, bg=S.BG_PANEL,
                 fg=mode_color, font=S.FONT_MONO_SM).pack(side=tk.LEFT, padx=8)

        # Scan button
        btn_row = tk.Frame(self, bg=S.BG_PANEL)
        btn_row.pack(fill=tk.X, padx=S.PAD, pady=S.PAD_SM)
        W.btn(btn_row, "Scan for Drives", self._scan, width=16).pack(side=tk.LEFT)
        self.status_lbl = tk.Label(btn_row, text="", bg=S.BG_PANEL,
                                   fg=S.FG_MUTED, font=S.FONT_UI_SM)
        self.status_lbl.pack(side=tk.LEFT, padx=12)

        # Drive list
        list_frame = W.card(self)
        list_frame.pack(fill=tk.BOTH, padx=S.PAD, pady=S.PAD_SM, expand=True)

        header = tk.Frame(list_frame, bg=S.BG_CARD)
        header.pack(fill=tk.X, padx=S.PAD_SM, pady=(S.PAD_SM, 0))
        for col, w in [("Device", 12), ("Model", 28), ("Size", 8),
                        ("Protocol", 8), ("Status", 10)]:
            tk.Label(header, text=col, bg=S.BG_CARD, fg=S.FG_MUTED,
                     font=S.FONT_MONO_SM, width=w, anchor=tk.W).pack(side=tk.LEFT)

        W.separator(list_frame, S.BG_INPUT).pack(fill=tk.X, padx=S.PAD_SM)

        self.drive_list_frame = tk.Frame(list_frame, bg=S.BG_CARD)
        self.drive_list_frame.pack(fill=tk.BOTH, expand=True, padx=S.PAD_SM, pady=S.PAD_SM)

        # Forensic notes
        notes = tk.Frame(self, bg=S.BG_PANEL)
        notes.pack(fill=tk.X, padx=S.PAD, pady=S.PAD_SM)
        info = (
            "INFO  WD My Passport drives use AES-256 hardware encryption.\n"
            "INFO  The drive stores a PBKDF2-derived unlock key in its security block.\n"
            "INFO  Password recovery reads the salt/challenge via SCSI Security Protocol."
        )
        tk.Label(notes, text=info, bg=S.BG_PANEL, fg=S.FG_MUTED,
                 font=S.FONT_MONO_SM, justify=tk.LEFT).pack(anchor=tk.W)

    def _scan(self):
        self.status_lbl.config(text="Scanning...", fg=S.FG_YELLOW)
        for w in self.drive_list_frame.winfo_children():
            w.destroy()

        def worker():
            if self.demo_mode:
                drives = DEMO_DRIVES[:]
            else:
                drives = detect_drives(include_all_external=True)
                for d in drives:
                    status = probe_drive_usb(
                        d.get("usb_vid") or 0, d.get("usb_pid") or 0)
                    d["security_status"] = status

            self.drives = drives
            self.after(0, lambda: self._populate_drives(drives))

        threading.Thread(target=worker, daemon=True).start()

    def _populate_drives(self, drives):
        for w in self.drive_list_frame.winfo_children():
            w.destroy()

        if not drives:
            tk.Label(self.drive_list_frame, text="No WD drives detected.",
                     bg=S.BG_CARD, fg=S.FG_MUTED, font=S.FONT_MONO_SM).pack(
                pady=S.PAD, anchor=tk.W)
            self.status_lbl.config(text="0 drives found", fg=S.FG_RED)
            return

        self.status_lbl.config(text=f"{len(drives)} drive(s) found", fg=S.FG_GREEN)

        for drive in drives:
            row = tk.Frame(self.drive_list_frame, bg=S.BG_INPUT, cursor="hand2")
            row.pack(fill=tk.X, pady=1)
            row.bind("<Button-1>", lambda e, d=drive: self._select(d))

            locked = drive.get("locked", False)
            status_txt = "LOCKED" if locked else "UNLOCKED"
            status_color = S.FG_RED if locked else S.FG_GREEN

            is_demo = drive.get("_demo", False)
            demo_tag = " [SIM]" if is_demo else ""

            for text, w in [
                (drive["disk_id"] + demo_tag, 12),
                (drive["media_name"][:27], 28),
                (f"{drive['size_gb']} GB", 8),
                (drive["protocol"], 8),
                (status_txt, 10),
            ]:
                color = status_color if text == status_txt else S.FG_WHITE
                tk.Label(row, text=text, bg=S.BG_INPUT, fg=color,
                         font=S.FONT_MONO_SM, width=w, anchor=tk.W).pack(
                    side=tk.LEFT, padx=2, pady=4)

            for child in row.winfo_children():
                child.bind("<Button-1>", lambda e, d=drive: self._select(d))

    def _select(self, drive):
        self.on_drive_selected(drive)
