"""
Hash / Challenge Extraction Panel
Displays the drive's security challenge and teaches students what it means.

Extraction methods (in order of preference):
  1. Automatic via pyusb USB BOT  — works on Linux or macOS with compatible libusb
  2. Manual hex entry             — paste 40-byte challenge from any external tool
  3. Simulation                   — built-in demo drive (no real hardware needed)
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox
import binascii
import threading
import os

from . import styles as S
from . import widgets as W
from core.wd_security import (
    parse_challenge, SimulatedDrive, derive_wd_key,
    get_challenge_usb, get_usb_ids_for_disk,
    get_ata_security_status, try_ata_unlock_hdparm,
    get_wd_ecb_status, get_wd_ecb_challenge, WDECBDrive,
    _CIPHER_NAMES, _SEC_STATUS_NAMES,
)


EDUCATION_TEXT = """\
HOW WD MY PASSPORT PASSWORD PROTECTION WORKS
─────────────────────────────────────────────
1. ENCRYPTION LAYER
   The drive controller uses AES-256 to encrypt all data on the platters.
   The encryption key (DEK) is generated at manufacture and stored on-chip.

2. KEY ENCRYPTION KEY (KEK)
   Your password never encrypts data directly. Instead it is used to derive
   a Key Encryption Key (KEK) that wraps (encrypts) the DEK.

3. PBKDF2 KEY DERIVATION
   KEK = PBKDF2-HMAC-SHA256(password_UTF16LE, salt, iterations, dklen=32)
   • Salt    — 32 random bytes stored on the drive's security block
   • Iters   — typically 1000 (shown below after extraction)
   The salt prevents pre-computed (rainbow table) attacks.

4. CHALLENGE–RESPONSE UNLOCK
   When you plug in the drive:
     a) Host reads the salt + iteration count (SCSI Security Protocol IN)
     b) Host derives KEK from your typed password
     c) Host sends KEK to drive (SCSI Security Protocol OUT)
     d) Drive tries to decrypt DEK with KEK — if it works, drive unlocks

5. OFFLINE ATTACK SURFACE
   Because the salt is readable without authentication, an attacker can:
     • Extract the salt (as shown below)
     • Run PBKDF2 offline for each password candidate
     • Check if the resulting KEK decrypts the stored DEK header
   This is exactly what we demonstrate in the next tab.
"""

MACOS_NOTE = """\
macOS LIMITATION — WHY AUTO-EXTRACT MAY FAIL
─────────────────────────────────────────────
macOS 12+ uses DriverKit (IOUSBMassStorageClass.dext) to manage USB
mass storage devices. Unlike Linux, macOS does NOT allow user-space
programs to reclaim a USB interface from a kernel driver — even as root.

This is a macOS security policy, not a bug in this tool.

WORKAROUNDS (pick one):
  A) Kali Linux VM with USB passthrough
       Boot Kali in VirtualBox/Parallels, pass the WD drive through,
       run:  sg_raw -r 40 /dev/sdb A2 C1 00 0E 00 00 00 00 28 00 00 00
       Copy the 40-byte hex output → paste into "Manual Entry" below.

  B) Linux live USB
       Boot any Linux live USB, run wdpassport-utils or sg_raw,
       copy the challenge hex.

  C) Simulation mode
       Use the built-in simulated drive — all crypto is real,
       only the hardware is virtual (ideal for classroom demos).

Once you have the 40-byte hex, paste it into the Manual Entry section.
"""


WD_ECB_EDU = """\
WD PROPRIETARY ECB PROTOCOL (~2012 ERA DRIVES)
───────────────────────────────────────────────
This drive uses WD vendor-specific SCSI opcodes (NOT standard 0xA2).
Protocol reverse-engineered from wdpassport-utils (github.com/0-duke).

KEY DERIVATION ALGORITHM (SHA-256 iterated):
  1. Read 8-byte ASCII salt from Handy Store (opcode 0xD8, page 1)
  2. Decode salt: treat as UTF-16LE bytes → extract ASCII chars
  3. Combine:  key_input = (ascii_salt + password).encode("utf-16")[2:]
               (UTF-16 BOM stripped; salt prepended to password)
  4. Repeat:  key = SHA256(key_input);  repeat N times (iteration count)
  5. Result:  32-byte AES key sent to drive for verification

VS. NEWER WD DRIVES (SCSI Security Protocol 0xA2/0xC1):
  • Newer: PBKDF2-HMAC-SHA256, 32-byte salt, ~1000 iterations
  • This drive: iterated SHA-256, 8-byte salt, ~1000 iterations
  • Both: salt IS readable without authentication → offline cracking possible
  • This drive: ~10× FASTER to crack (SHA-256 vs PBKDF2 overhead)

OPCODES USED (WD vendor-specific, NOT standard SCSI):
  0xC0  — Get encryption status (locked/unlocked, cipher type)
  0xD8  — Read Handy Store page (salt, iterations, hint stored here)
  0xDA  — Write Handy Store page
  0xC1  — Security operation (subop 0xE1=unlock, 0xE2=change pw, 0xE3=erase)

OFFLINE CRACKING IS POSSIBLE because:
  The salt + iteration count are readable WITHOUT authentication (opcode 0xD8).
  You compute SHA256^N(salt+password) locally for each candidate,
  then send ONE unlock command with the matching key.
  Zero wrong attempts hit the drive if you crack offline first.

ATTEMPT COUNTER WARNING:
  Sending a wrong key via opcode 0xC1/0xE1 decrements the hardware counter.
  Status 0x06 = "Locked, unlock blocked" means counter expired.
  Recovery requires secure erase (all data lost).
  For this demo: use the wordlist with a known password so it matches quickly.
"""

ATA_SECURITY_EDU = """\
ATA SECURITY vs. SCSI SECURITY PROTOCOL — KEY DIFFERENCES
──────────────────────────────────────────────────────────
This drive (WD My Passport 0748) uses ATA SECURITY, not SCSI Security Protocol.

SCSI SECURITY PROTOCOL (e.g. WD 25E2, newer models):
  • Drive exposes a challenge block: iteration count + 32-byte salt
  • Attacker reads salt WITHOUT authentication
  • Runs PBKDF2 offline → pure CPU/GPU attack, no rate limiting
  • 10,000+ attempts/second possible on a modern laptop

ATA SECURITY (e.g. WD My Passport 0748, older models):
  • Password verified ENTIRELY on-device — no salt is exported
  • Each attempt requires a SCSI/ATA command to the physical drive
  • Drive enforces a hardware attempt counter (typically ~5 attempts)
  • After counter expires → drive is PERMANENTLY LOCKED
  • Only a destructive Security Erase (wipes all data) resets it

FORENSIC IMPLICATIONS:
  • ATA Security drives cannot be cracked with offline dictionary attacks
  • Live online attack is limited to ~5 tries before permanent lockout
  • Forensically, this means the data is unrecoverable without the password
  • In real engagements: check for password hints, known-password databases,
    or image the drive first then attempt (still limited by hardware counter)

CLASSROOM DEMO:
  Use the Simulation tab (Tab 3) to demonstrate the PBKDF2 cracking flow —
  the crypto is identical to real SCSI-protocol WD drives.
  Use "Test Password" below to demonstrate a single live ATA unlock attempt.
"""


class HashPanel(tk.Frame):
    def __init__(self, parent, demo_mode=True, **kwargs):
        super().__init__(parent, bg=S.BG_PANEL, **kwargs)
        self.demo_mode = demo_mode
        self.current_drive = None
        self.sim_drive: SimulatedDrive | None = None
        self._manual_challenge: bytes | None = None   # set by manual entry
        self._current_disk_id: str = ""
        self._wd_ecb_drive: "WDECBDrive | None" = None
        self._build()

    # ── Layout ───────────────────────────────────────────────────────────────

    def _build(self):
        cols = tk.Frame(self, bg=S.BG_PANEL)
        cols.pack(fill=tk.BOTH, expand=True, padx=S.PAD, pady=S.PAD)

        # ── Left: education ─────────────────────────────────────��─────────
        left = W.card(cols)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, S.PAD_SM))

        tk.Label(left, text="CRYPTOGRAPHIC BACKGROUND",
                 bg=S.BG_CARD, fg=S.ACCENT, font=S.FONT_LABEL_B).pack(
            anchor=tk.W, padx=S.PAD, pady=(S.PAD, S.PAD_SM))

        edu_frame = W.scrolled_text(left, height=16)
        edu_frame.pack(fill=tk.BOTH, expand=True, padx=S.PAD, pady=(0, S.PAD))
        edu_text = edu_frame._text
        edu_text.config(state=tk.NORMAL, fg=S.FG_CYAN)
        edu_text.insert(tk.END, EDUCATION_TEXT)
        edu_text.config(state=tk.DISABLED)

        # ── Right: extraction controls ────────────────────────────────────
        right = tk.Frame(cols, bg=S.BG_PANEL)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(S.PAD_SM, 0))

        right_scroll = tk.Frame(right, bg=S.BG_PANEL)
        right_scroll.pack(fill=tk.BOTH, expand=True)

        # ── Section 1: Auto extract ───────────────────────────────────────
        auto_card = W.card(right_scroll)
        auto_card.pack(fill=tk.X, pady=(0, S.PAD_SM))

        tk.Label(auto_card, text="METHOD 1 — AUTO EXTRACT (USB)",
                 bg=S.BG_CARD, fg=S.ACCENT, font=S.FONT_LABEL_B).pack(
            anchor=tk.W, padx=S.PAD, pady=(S.PAD, S.PAD_SM))

        drive_row = tk.Frame(auto_card, bg=S.BG_CARD)
        drive_row.pack(fill=tk.X, padx=S.PAD, pady=2)
        tk.Label(drive_row, text="Drive:", bg=S.BG_CARD,
                 fg=S.FG_MUTED, font=S.FONT_LABEL, width=8, anchor=tk.W).pack(side=tk.LEFT)
        self.drive_lbl = tk.Label(drive_row, text="(none selected)",
                                   bg=S.BG_CARD, fg=S.FG_YELLOW, font=S.FONT_MONO_SM)
        self.drive_lbl.pack(side=tk.LEFT, padx=4)

        btn_row = tk.Frame(auto_card, bg=S.BG_CARD)
        btn_row.pack(fill=tk.X, padx=S.PAD, pady=S.PAD_SM)
        W.btn(btn_row, "Extract Challenge", self._extract_auto, width=18).pack(side=tk.LEFT)
        self.auto_status = tk.Label(btn_row, text="", bg=S.BG_CARD,
                                     fg=S.FG_MUTED, font=S.FONT_MONO_SM)
        self.auto_status.pack(side=tk.LEFT, padx=8)

        # macOS note (live mode only)
        if not self.demo_mode:
            note_btn = tk.Button(auto_card,
                                 text="  ⓘ  macOS USB restriction — click to read",
                                 bg=S.BG_INPUT, fg=S.FG_YELLOW, font=S.FONT_MONO_SM,
                                 relief=tk.FLAT, bd=0, cursor="hand2", anchor=tk.W,
                                 command=self._show_macos_note)
            note_btn.pack(fill=tk.X, padx=S.PAD, pady=(0, S.PAD_SM))

        W.separator(auto_card, S.BG_INPUT).pack(fill=tk.X, padx=S.PAD, pady=S.PAD_SM)

        # Parsed fields
        self._field_vars = {}
        for label_text, attr in [
            ("Raw challenge (hex):", "raw_hex_lbl"),
            ("Iteration count:",     "iter_lbl"),
            ("Salt (hex):",          "salt_lbl"),
            ("Salt length:",         "saltlen_lbl"),
        ]:
            row = tk.Frame(auto_card, bg=S.BG_CARD)
            row.pack(fill=tk.X, padx=S.PAD, pady=2)
            tk.Label(row, text=label_text, bg=S.BG_CARD, fg=S.FG_MUTED,
                     font=S.FONT_LABEL, width=22, anchor=tk.W).pack(side=tk.LEFT)
            val = tk.Label(row, text="—", bg=S.BG_INPUT, fg=S.FG_GREEN,
                           font=S.FONT_MONO_SM, anchor=tk.W, padx=6)
            val.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self._field_vars[attr] = val

        # ── Section 2: Manual entry ───────────────────────────────────────
        manual_card = W.card(right_scroll)
        manual_card.pack(fill=tk.X, pady=(0, S.PAD_SM))

        tk.Label(manual_card, text="METHOD 2 — MANUAL CHALLENGE ENTRY",
                 bg=S.BG_CARD, fg=S.ACCENT, font=S.FONT_LABEL_B).pack(
            anchor=tk.W, padx=S.PAD, pady=(S.PAD, S.PAD_SM))

        tk.Label(manual_card,
                 text="Paste the 40-byte challenge hex from sg_raw / wdpassport-utils\n"
                      "(from a Linux machine or Kali VM with the drive attached):",
                 bg=S.BG_CARD, fg=S.FG_MUTED, font=S.FONT_MONO_SM,
                 justify=tk.LEFT).pack(anchor=tk.W, padx=S.PAD, pady=(0, 4))

        self.manual_entry = tk.Text(
            manual_card, height=3, bg=S.BG_INPUT, fg=S.FG_GREEN,
            font=S.FONT_MONO_SM, relief=tk.FLAT, insertbackground=S.FG_GREEN,
            wrap=tk.WORD)
        self.manual_entry.pack(fill=tk.X, padx=S.PAD, pady=(0, S.PAD_SM))

        # Placeholder
        placeholder = (
            "e.g.  000003E8 00000001 A3F1C2D4 E5B60781 92A3B4C5 "
            "D6E7F809 1A2B3C4D 5E6F7081 9293A4B5 C6D7E8F9"
        )
        self.manual_entry.insert("1.0", placeholder)
        self.manual_entry.config(fg=S.FG_MUTED)
        self.manual_entry.bind("<FocusIn>",  self._clear_placeholder)
        self.manual_entry.bind("<FocusOut>", self._restore_placeholder)
        self._placeholder = placeholder

        mb_row = tk.Frame(manual_card, bg=S.BG_CARD)
        mb_row.pack(fill=tk.X, padx=S.PAD, pady=(0, S.PAD_SM))
        W.btn(mb_row, "Parse & Use", self._parse_manual, width=14).pack(side=tk.LEFT)
        self.manual_status = tk.Label(mb_row, text="", bg=S.BG_CARD,
                                       fg=S.FG_MUTED, font=S.FONT_MONO_SM)
        self.manual_status.pack(side=tk.LEFT, padx=8)

        # Linux extraction command helper
        tk.Label(manual_card,
                 text="Linux command to get this hex (run as root on Linux):\n"
                      "  sg_raw -r 40 /dev/sda A2 C1 00 0E 00 00 00 00 00 28 00 00\n"
                      "  (replace /dev/sda with your WD drive device)\n"
                      "  NOTE: if sg_raw fails with 'Invalid command operation code',\n"
                      "  run:  sudo python3 test_live.py sda  to diagnose the protocol.",
                 bg=S.BG_CARD, fg=S.FG_CYAN, font=S.FONT_MONO_SM,
                 justify=tk.LEFT).pack(anchor=tk.W, padx=S.PAD, pady=(0, S.PAD))

        # ── Section 3: ATA Security panel (shown only when detected) ─────
        self.ata_card = W.card(right_scroll)
        # Hidden initially; shown when ATA Security is detected
        self.ata_card.pack_forget()

        tk.Label(self.ata_card, text="ATA SECURITY DETECTED",
                 bg=S.BG_CARD, fg=S.FG_YELLOW, font=S.FONT_LABEL_B).pack(
            anchor=tk.W, padx=S.PAD, pady=(S.PAD, S.PAD_SM))

        tk.Label(self.ata_card,
                 text="This drive uses ATA Security, NOT SCSI Security Protocol.\n"
                      "No salt can be extracted — offline cracking is impossible.\n"
                      "See educational text on the left for details.",
                 bg=S.BG_CARD, fg=S.FG_YELLOW, font=S.FONT_MONO_SM,
                 justify=tk.LEFT).pack(anchor=tk.W, padx=S.PAD, pady=(0, S.PAD_SM))

        W.separator(self.ata_card, S.BG_INPUT).pack(fill=tk.X, padx=S.PAD, pady=S.PAD_SM)

        # ATA status fields
        self._ata_field_vars = {}
        for label_text, attr in [
            ("Security supported:", "ata_supported"),
            ("Security enabled:",   "ata_enabled"),
            ("Drive locked:",       "ata_locked"),
            ("Drive frozen:",       "ata_frozen"),
            ("Count expired:",      "ata_count"),
        ]:
            row = tk.Frame(self.ata_card, bg=S.BG_CARD)
            row.pack(fill=tk.X, padx=S.PAD, pady=2)
            tk.Label(row, text=label_text, bg=S.BG_CARD, fg=S.FG_MUTED,
                     font=S.FONT_LABEL, width=22, anchor=tk.W).pack(side=tk.LEFT)
            val = tk.Label(row, text="—", bg=S.BG_INPUT, fg=S.FG_YELLOW,
                           font=S.FONT_MONO_SM, anchor=tk.W, padx=6)
            val.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self._ata_field_vars[attr] = val

        W.separator(self.ata_card, S.BG_INPUT).pack(fill=tk.X, padx=S.PAD, pady=S.PAD_SM)

        # Single unlock attempt (with warning)
        tk.Label(self.ata_card,
                 text="WARNING: Wrong attempts consume the hardware counter (~5 max).\n"
                      "After counter expires, drive is permanently locked.",
                 bg=S.BG_CARD, fg=S.FG_RED, font=S.FONT_MONO_SM,
                 justify=tk.LEFT).pack(anchor=tk.W, padx=S.PAD, pady=(0, 4))

        ata_pw_row = tk.Frame(self.ata_card, bg=S.BG_CARD)
        ata_pw_row.pack(fill=tk.X, padx=S.PAD, pady=(0, S.PAD_SM))
        tk.Label(ata_pw_row, text="Test password:", bg=S.BG_CARD,
                 fg=S.FG_MUTED, font=S.FONT_LABEL, width=14, anchor=tk.W).pack(side=tk.LEFT)
        self.ata_pw_entry = tk.Entry(ata_pw_row, bg=S.BG_INPUT, fg=S.FG_WHITE,
                                     font=S.FONT_MONO, insertbackground=S.FG_WHITE,
                                     relief=tk.FLAT, width=20)
        self.ata_pw_entry.pack(side=tk.LEFT, padx=8)
        W.btn(ata_pw_row, "Test Unlock", self._ata_test_unlock, width=12).pack(side=tk.LEFT)

        self.ata_unlock_result = tk.Label(self.ata_card, text="",
                                          bg=S.BG_CARD, fg=S.FG_GREEN, font=S.FONT_MONO_SM)
        self.ata_unlock_result.pack(anchor=tk.W, padx=S.PAD, pady=(0, S.PAD))

        # ── Section 4: Manual verify ──────────────────────────────────────
        verify_card = W.card(right_scroll)
        verify_card.pack(fill=tk.X)

        tk.Label(verify_card, text="MANUAL HASH VERIFICATION",
                 bg=S.BG_CARD, fg=S.ACCENT, font=S.FONT_LABEL_B).pack(
            anchor=tk.W, padx=S.PAD, pady=(S.PAD, S.PAD_SM))

        vrow = tk.Frame(verify_card, bg=S.BG_CARD)
        vrow.pack(fill=tk.X, padx=S.PAD, pady=S.PAD_SM)
        tk.Label(vrow, text="Test password:", bg=S.BG_CARD,
                 fg=S.FG_MUTED, font=S.FONT_LABEL, width=14, anchor=tk.W).pack(side=tk.LEFT)
        self.verify_entry = tk.Entry(vrow, bg=S.BG_INPUT, fg=S.FG_WHITE,
                                     font=S.FONT_MONO, insertbackground=S.FG_WHITE,
                                     relief=tk.FLAT, width=22)
        self.verify_entry.pack(side=tk.LEFT, padx=8)
        W.btn(vrow, "Verify", self._manual_verify, width=8).pack(side=tk.LEFT)

        self.verify_result = tk.Label(verify_card, text="",
                                       bg=S.BG_CARD, fg=S.FG_GREEN, font=S.FONT_MONO_SM)
        self.verify_result.pack(anchor=tk.W, padx=S.PAD, pady=S.PAD_SM)

    # ── Drive selection ───────────────────────────────────────────────────────

    def set_drive(self, drive: dict, sim_drive: SimulatedDrive | None = None):
        self.current_drive = drive
        self.sim_drive = sim_drive
        self._current_disk_id = drive.get("disk_id", "")
        name = drive.get("media_name", drive.get("disk_id", "?"))
        tag = " [SIM]" if drive.get("_demo") else ""
        self.drive_lbl.config(text=f"{name}{tag}", fg=S.FG_YELLOW)
        for v in self._field_vars.values():
            v.config(text="—")
        for v in self._ata_field_vars.values():
            v.config(text="—", fg=S.FG_YELLOW)
        self._manual_challenge = None
        self._wd_ecb_drive = None
        # Hide ATA panel and reset its labels for next use
        self.ata_card.pack_forget()
        self.ata_unlock_result.config(text="")
        self._reset_ata_card_labels()
        # Restore original SCSI education text
        self._switch_edu_text(EDUCATION_TEXT)

    def _reset_ata_card_labels(self):
        """Reset the ATA card header labels to their original 'ATA SECURITY' text."""
        for widget in self.ata_card.winfo_children():
            if isinstance(widget, tk.Label):
                text = widget.cget("text")
                if "PROPRIETARY" in text or "ATA SECURITY DETECTED" in text:
                    widget.config(text="ATA SECURITY DETECTED", fg=S.FG_YELLOW)
                elif "WD proprietary" in text or "This drive uses ATA Security" in text:
                    widget.config(
                        text="This drive uses ATA Security, NOT SCSI Security Protocol.\n"
                             "No salt can be extracted — offline cracking is impossible.\n"
                             "See educational text on the left for details.",
                        fg=S.FG_YELLOW)
                    break

    # ── Method 1: auto extract ────────────────────────────────────────────────

    def _extract_auto(self):
        if self.current_drive is None:
            messagebox.showwarning("No Drive", "Select a drive on the Detection tab first.")
            return

        if self.demo_mode or self.current_drive.get("_demo"):
            self._extract_simulated()
        else:
            self.auto_status.config(text="Extracting...", fg=S.FG_YELLOW)
            threading.Thread(target=self._extract_real, daemon=True).start()

    def _extract_simulated(self):
        if self.sim_drive is None:
            return
        challenge = self.sim_drive.challenge
        parsed = parse_challenge(challenge)
        self._update_fields(challenge, parsed)
        self.auto_status.config(text="OK (simulation)", fg=S.FG_GREEN)

    def _extract_real(self):
        vid = self.current_drive.get("usb_vid")
        pid = self.current_drive.get("usb_pid")
        disk_id = self.current_drive.get("disk_id", "")

        if not vid or not pid:
            vid, pid = get_usb_ids_for_disk(disk_id)

        if not vid or not pid:
            self.after(0, lambda: self._auto_fail(
                "Could not find USB VID/PID. Is the drive plugged in?"))
            return

        self.after(0, lambda: self.auto_status.config(
            text=f"Probing VID=0x{vid:04X} PID=0x{pid:04X}…", fg=S.FG_YELLOW))

        data, err = get_challenge_usb(vid, pid, disk_id=disk_id)

        if err == "ATA_SECURITY_DETECTED":
            self.after(0, lambda: self.auto_status.config(
                text="ATA Security detected — fetching status…", fg=S.FG_YELLOW))
            ata_status = get_ata_security_status(disk_id)
            self.after(0, lambda: self._show_ata_security(ata_status, disk_id))
            return

        if err in ("WD_ECB_DETECTED", "WD_PROPRIETARY_DETECTED"):
            self.after(0, lambda: self.auto_status.config(
                text="WD ECB drive — reading Handy Store…", fg=S.FG_YELLOW))
            # Read status + challenge in background thread (already in thread)
            wd_status, wd_err = get_wd_ecb_status(disk_id)
            if wd_err:
                self.after(0, lambda: self._auto_fail(
                    f"WD ECB status error: {wd_err}"))
                return
            challenge = get_wd_ecb_challenge(disk_id)
            if "error" in challenge:
                self.after(0, lambda: self._auto_fail(
                    f"WD ECB challenge error: {challenge['error']}"))
                return
            # Build live drive object
            ecb_drive = WDECBDrive(
                disk_id    = disk_id,
                iterations = challenge["iterations"],
                salt       = challenge["salt"],
                pw_length  = wd_status["pw_length"],
                cipher_id  = wd_status["cipher_id"],
                hint       = challenge.get("hint", ""),
            )
            self._wd_ecb_drive = ecb_drive
            self.after(0, lambda: self._show_wd_ecb_challenge(
                challenge, wd_status, ecb_drive))
            return

        if err:
            self.after(0, lambda: self._auto_fail(err))
            return

        parsed = parse_challenge(data)
        if "error" in parsed:
            self.after(0, lambda: self._auto_fail(parsed["error"]))
            return

        self.after(0, lambda: self._update_fields(data, parsed))
        self.after(0, lambda: self.auto_status.config(text="OK", fg=S.FG_GREEN))

    def _show_ata_security(self, status: dict, disk_id: str):
        """Show the ATA Security panel and update education text."""
        self.auto_status.config(text="ATA Security drive — see panel below", fg=S.FG_YELLOW)
        self._current_disk_id = disk_id

        # Swap education text to ATA-specific content
        try:
            edu_text = self.nametowidget(str(self.winfo_children()[0].winfo_children()[0]))
        except Exception:
            edu_text = None

        # Reveal the ATA card
        self.ata_card.pack(fill=tk.X, pady=(0, S.PAD_SM))

        def fmt(val):
            return ("YES" if val else "no") if isinstance(val, bool) else str(val)

        color_bool = lambda v: S.FG_RED if v else S.FG_GREEN
        self._ata_field_vars["ata_supported"].config(
            text=fmt(status.get("supported", False)),
            fg=color_bool(not status.get("supported", False)))
        self._ata_field_vars["ata_enabled"].config(
            text=fmt(status.get("enabled", False)),
            fg=S.FG_YELLOW if status.get("enabled") else S.FG_GREEN)
        self._ata_field_vars["ata_locked"].config(
            text=fmt(status.get("locked", False)),
            fg=S.FG_RED if status.get("locked") else S.FG_GREEN)
        self._ata_field_vars["ata_frozen"].config(
            text=fmt(status.get("frozen", False)),
            fg=S.FG_YELLOW if status.get("frozen") else S.FG_GREEN)
        self._ata_field_vars["ata_count"].config(
            text=fmt(status.get("count_expired", False)),
            fg=S.FG_RED if status.get("count_expired") else S.FG_GREEN)

        if status.get("error"):
            self.ata_unlock_result.config(
                text=f"hdparm: {status['error']}", fg=S.FG_MUTED)

        # Replace left-panel education text with ATA-specific content
        self._switch_edu_text(ATA_SECURITY_EDU)

    def _show_wd_ecb_challenge(self, challenge: dict, wd_status: dict,
                                ecb_drive: "WDECBDrive"):
        """
        Show the extracted WD ECB challenge parameters and wire up the crack panel.
        Repurposes the ATA card fields to display the ECB-specific data.
        """
        cipher_name = _CIPHER_NAMES.get(wd_status["cipher_id"],
                                        f"0x{wd_status['cipher_id']:02X}")
        sec_name = _SEC_STATUS_NAMES.get(wd_status["sec_status"], "unknown")

        self.auto_status.config(
            text=f"WD ECB — {cipher_name}  {sec_name}  Challenge extracted!",
            fg=S.FG_GREEN)

        # Reveal ATA card (repurposed for WD ECB info)
        self.ata_card.pack(fill=tk.X, pady=(0, S.PAD_SM))

        # Update header labels
        for widget in self.ata_card.winfo_children():
            if isinstance(widget, tk.Label):
                text = widget.cget("text")
                if "ATA SECURITY DETECTED" in text or "WD PROPRIETARY" in text:
                    widget.config(
                        text=f"WD ECB CHALLENGE EXTRACTED  ({cipher_name})",
                        fg=S.FG_GREEN)
                elif "ATA Security" in text or "WD proprietary" in text:
                    widget.config(
                        text="Salt + iterations read from Handy Store (opcode 0xD8).\n"
                             "Offline SHA-256 cracking now possible — see Tab 3.\n"
                             "Send ONE unlock command when password is found.",
                        fg=S.FG_GREEN)
                    break

        # Fill fields with WD ECB challenge data
        hint_txt = challenge.get("hint", "") or "(none)"
        for attr, val, color in [
            ("ata_supported", f"YES — opcode 0xC0/0xD8/0xC1", S.FG_GREEN),
            ("ata_enabled",   f"{sec_name}", S.FG_YELLOW),
            ("ata_locked",    f"YES  (pw_length={wd_status['pw_length']} bytes)",
             S.FG_RED),
            ("ata_frozen",    f"iterations: {challenge['iterations']}",
             S.FG_CYAN),
            ("ata_count",     f"salt: {challenge['salt_hex']}  hint: {hint_txt}",
             S.FG_CYAN),
        ]:
            self._ata_field_vars[attr].config(text=val, fg=color)

        # Also populate the SCSI challenge fields so they're visible
        hex_str = challenge["salt_hex"]
        self._field_vars["raw_hex_lbl"].config(
            text=f"(Handy Store)  salt={hex_str}  iters={challenge['iterations']}")
        self._field_vars["iter_lbl"].config(
            text=f"{challenge['iterations']} rounds  (iterated SHA-256, not PBKDF2)")
        self._field_vars["salt_lbl"].config(text=hex_str)
        self._field_vars["saltlen_lbl"].config(
            text=f"8 bytes (UTF-16LE encoded ASCII)")

        self.ata_unlock_result.config(
            text="Go to Tab 3 → Password Cracking  to run the dictionary attack.\n"
                 "Each candidate: SHA-256 × N(salt+pw) → sent to drive to verify.",
            fg=S.FG_GREEN)

        # Swap education text
        self._switch_edu_text(WD_ECB_EDU)

        # Fire event so main.py can wire ecb_drive to the crack panel
        self.event_generate("<<WDECBReady>>")

    def _switch_edu_text(self, new_text: str):
        """Replace the education panel text (left column)."""
        try:
            cols_frame = self.winfo_children()[0]          # outer cols frame
            left_card  = cols_frame.winfo_children()[0]    # left W.card
            # find the scrolled text widget inside
            for child in left_card.winfo_children():
                if hasattr(child, "_text"):
                    t = child._text
                    t.config(state=tk.NORMAL)
                    t.delete("1.0", tk.END)
                    t.insert(tk.END, new_text)
                    t.config(state=tk.DISABLED)
                    break
        except Exception:
            pass

    def _ata_test_unlock(self):
        """Attempt a single ATA SECURITY UNLOCK — requires confirmation."""
        password = self.ata_pw_entry.get().strip()
        if not password:
            self.ata_unlock_result.config(text="Enter a password first.", fg=S.FG_MUTED)
            return

        disk_id = getattr(self, "_current_disk_id", None)
        if not disk_id:
            self.ata_unlock_result.config(
                text="No drive disk ID available.", fg=S.FG_RED)
            return

        from tkinter import messagebox
        confirmed = messagebox.askyesno(
            "Confirm ATA Unlock Attempt",
            f"Send ATA SECURITY UNLOCK with password: '{password}'\n"
            f"to /dev/{disk_id}\n\n"
            f"WARNING: Wrong attempts decrement the hardware counter.\n"
            f"Typically ~5 wrong attempts will PERMANENTLY lock the drive.\n\n"
            f"Proceed?",
            icon="warning")
        if not confirmed:
            return

        self.ata_unlock_result.config(text="Sending unlock command…", fg=S.FG_YELLOW)
        self.update_idletasks()

        def _do_unlock():
            ok, msg = try_ata_unlock_hdparm(disk_id, password)
            def _show():
                if ok:
                    self.ata_unlock_result.config(
                        text=f"UNLOCKED — drive accepted password '{password}'",
                        fg=S.FG_GREEN)
                    self._ata_field_vars["ata_locked"].config(text="no", fg=S.FG_GREEN)
                else:
                    self.ata_unlock_result.config(
                        text=f"WRONG (or error): {msg[:120]}", fg=S.FG_RED)
            self.after(0, _show)

        threading.Thread(target=_do_unlock, daemon=True).start()

    def _auto_fail(self, err: str):
        self.auto_status.config(text="FAILED — see details", fg=S.FG_RED)
        ata_hint = ""
        if "Invalid command operation code" in err or "Illegal Request" in err:
            ata_hint = (
                "\n\nDIAGNOSIS: 'Invalid command operation code' means this drive\n"
                "does NOT support SCSI Security Protocol (opcode 0xA2).\n"
                "Your WD model may use ATA Security instead.\n\n"
                "Run the diagnostic tool on Ubuntu to confirm:\n"
                "  sudo python3 test_live.py sda\n\n"
                "If hdparm shows 'Security: enabled/locked', this drive uses\n"
                "ATA Security — a different extraction method is needed."
            )
        messagebox.showerror(
            "Auto-Extract Failed",
            f"{err}{ata_hint}\n\n"
            "WORKAROUNDS:\n"
            "  A) Run diagnostic: sudo python3 test_live.py sda\n"
            "  B) Manual Entry (Method 2) if you have the 40-byte hex\n"
            "  C) Use Simulation Mode for classroom demo (no hardware needed)")

    # ── Method 2: manual entry ────────────────────────────────────────────────

    def _clear_placeholder(self, _event):
        if self.manual_entry.get("1.0", tk.END).strip() == self._placeholder:
            self.manual_entry.delete("1.0", tk.END)
            self.manual_entry.config(fg=S.FG_GREEN)

    def _restore_placeholder(self, _event):
        if not self.manual_entry.get("1.0", tk.END).strip():
            self.manual_entry.insert("1.0", self._placeholder)
            self.manual_entry.config(fg=S.FG_MUTED)

    def _parse_manual(self):
        raw_text = self.manual_entry.get("1.0", tk.END).strip()
        if raw_text == self._placeholder or not raw_text:
            messagebox.showwarning("No Input", "Paste a 40-byte hex challenge first.")
            return

        # Strip spaces, colons, newlines
        hex_clean = "".join(c for c in raw_text if c in "0123456789abcdefABCDEF")

        if len(hex_clean) != 80:
            self.manual_status.config(
                text=f"Expected 80 hex chars (40 bytes), got {len(hex_clean)}",
                fg=S.FG_RED)
            return

        try:
            data = bytes.fromhex(hex_clean)
        except ValueError as e:
            self.manual_status.config(text=f"Invalid hex: {e}", fg=S.FG_RED)
            return

        parsed = parse_challenge(data)
        if "error" in parsed:
            self.manual_status.config(text=parsed["error"], fg=S.FG_RED)
            return

        self._manual_challenge = data
        self._update_fields(data, parsed)
        self.manual_status.config(text="Parsed OK — ready to crack", fg=S.FG_GREEN)

        # Wire the manual challenge into crack panel via parent callback
        self.event_generate("<<ChallengeReady>>")

    def get_challenge_data(self) -> bytes | None:
        """Return whichever challenge was successfully extracted (auto or manual)."""
        return self._manual_challenge

    # ── macOS note popup ──────────────────────────────────────────────────────

    def _show_macos_note(self):
        win = tk.Toplevel(self)
        win.title("macOS USB Restriction")
        win.configure(bg=S.BG_DARK)
        win.geometry("680x480")
        txt = tk.Text(win, bg=S.BG_DARK, fg=S.FG_YELLOW, font=S.FONT_MONO_SM,
                      relief=tk.FLAT, wrap=tk.WORD, padx=S.PAD, pady=S.PAD)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, MACOS_NOTE)
        txt.config(state=tk.DISABLED)
        W.btn(win, "Close", win.destroy, width=10).pack(pady=S.PAD_SM)

    # ── Shared field update ───────────────────────────────────────────────────

    def _update_fields(self, raw: bytes, parsed: dict):
        hex_str = binascii.hexlify(raw).decode().upper()
        groups  = [hex_str[i:i+8] for i in range(0, len(hex_str), 8)]
        self._field_vars["raw_hex_lbl"].config(text="  ".join(groups))
        self._field_vars["iter_lbl"].config(
            text=f"{parsed.get('iterations', '?')} rounds")
        self._field_vars["salt_lbl"].config(
            text=parsed.get("salt_hex", "?").upper())
        salt_len = len(parsed.get("salt", b""))
        self._field_vars["saltlen_lbl"].config(
            text=f"{salt_len} bytes ({salt_len * 8} bits)")

    # ── Manual verify ─────────────────────────────────────────────────────────

    def _manual_verify(self):
        candidate = self.verify_entry.get().strip()
        if not candidate:
            return

        if self.sim_drive:
            ok = self.sim_drive.try_password(candidate)
            if ok:
                self.verify_result.config(
                    text=f"MATCH  '{candidate}' unlocks the drive!", fg=S.FG_GREEN)
            else:
                self.verify_result.config(
                    text=f"NO MATCH  '{candidate}' is incorrect.", fg=S.FG_RED)

        elif self._manual_challenge:
            parsed = parse_challenge(self._manual_challenge)
            key = derive_wd_key(candidate, parsed["salt"], parsed["iterations"])
            # We can't verify against the real drive from here — show derived key
            self.verify_result.config(
                text=f"Derived KEK: {key.hex()[:32]}…\n"
                     "(send to drive to verify — or use cracking tab)",
                fg=S.FG_CYAN)
        else:
            self.verify_result.config(
                text="Extract a challenge first (Method 1 or 2)", fg=S.FG_MUTED)
