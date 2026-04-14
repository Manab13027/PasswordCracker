"""
Password Cracking Panel
Runs dictionary, brute-force, and hybrid attacks against the drive challenge.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox
import string
import os
import threading

from . import styles as S
from . import widgets as W
from core.cracker import Cracker, estimate_brute_count, format_rate, CrackResult
from core.wd_security import SimulatedDrive, WDECBDrive


ATTACK_MODES = ["Dictionary", "Brute Force", "Dictionary + Rules (Hybrid)"]

_SPECIAL = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
_COMMON_SPECIAL = "!@#$%^&*_-."

CHARSET_OPTIONS = {
    "Digits only (0-9)":                       string.digits,
    "Lowercase (a-z)":                         string.ascii_lowercase,
    "Uppercase (A-Z)":                         string.ascii_uppercase,
    "Lower + digits (a-z 0-9)":               string.ascii_lowercase + string.digits,
    "Upper + digits (A-Z 0-9)":               string.ascii_uppercase + string.digits,
    "Lower + Upper (a-z A-Z)":                string.ascii_letters,
    "Upper + Lower + digits (A-Z a-z 0-9)":   string.ascii_uppercase + string.ascii_lowercase + string.digits,
    "Lower + digits + common specials":        string.ascii_lowercase + string.digits + _COMMON_SPECIAL,
    "Upper + Lower + digits + common specials": string.ascii_uppercase + string.ascii_lowercase + string.digits + _COMMON_SPECIAL,
    "Full alphanumeric + all specials":        string.ascii_letters + string.digits + _SPECIAL,
    "Full printable (no space)":               string.printable.strip(),
}


class CrackPanel(tk.Frame):
    def __init__(self, parent, demo_mode=True, **kwargs):
        super().__init__(parent, bg=S.BG_PANEL, **kwargs)
        self.demo_mode = demo_mode
        self.sim_drive: SimulatedDrive | None = None
        self.cracker: Cracker | None = None
        self._build()

    def _build(self):
        main = tk.Frame(self, bg=S.BG_PANEL)
        main.pack(fill=tk.BOTH, expand=True, padx=S.PAD, pady=S.PAD)

        # ── Left: configuration ───────────────────────────────────────────
        left = W.card(main)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, S.PAD_SM))

        tk.Label(left, text="ATTACK CONFIGURATION",
                 bg=S.BG_CARD, fg=S.ACCENT, font=S.FONT_LABEL_B).pack(
            anchor=tk.W, padx=S.PAD, pady=(S.PAD, S.PAD_SM))

        # Attack mode
        tk.Label(left, text="Attack mode:", bg=S.BG_CARD,
                 fg=S.FG_MUTED, font=S.FONT_LABEL).pack(anchor=tk.W, padx=S.PAD)
        self.mode_var = tk.StringVar(value=ATTACK_MODES[0])
        mode_mb = tk.OptionMenu(left, self.mode_var, *ATTACK_MODES,
                                 command=self._on_mode_change)
        mode_mb.config(bg=S.BG_INPUT, fg=S.FG_WHITE, font=S.FONT_LABEL,
                       relief=tk.FLAT, activebackground=S.BG_INPUT,
                       activeforeground=S.FG_WHITE, highlightthickness=0, width=24)
        mode_mb["menu"].config(bg=S.BG_INPUT, fg=S.FG_WHITE, font=S.FONT_LABEL)
        mode_mb.pack(anchor=tk.W, padx=S.PAD, pady=(2, S.PAD))

        W.separator(left, S.BG_INPUT).pack(fill=tk.X, padx=S.PAD, pady=S.PAD_SM)

        # ── Dictionary settings ──────────────────────────────────────────
        self.dict_frame = tk.Frame(left, bg=S.BG_CARD)
        self.dict_frame.pack(fill=tk.X, padx=S.PAD)

        tk.Label(self.dict_frame, text="Wordlist file:", bg=S.BG_CARD,
                 fg=S.FG_MUTED, font=S.FONT_LABEL).pack(anchor=tk.W)

        wl_row = tk.Frame(self.dict_frame, bg=S.BG_CARD)
        wl_row.pack(fill=tk.X, pady=2)

        default_wl = os.path.join(os.path.dirname(__file__), "..", "wordlists", "common.txt")
        default_wl = os.path.normpath(default_wl)
        self.wordlist_var = tk.StringVar(value=default_wl)
        self.wl_entry = tk.Entry(wl_row, textvariable=self.wordlist_var,
                                  bg=S.BG_INPUT, fg=S.FG_WHITE, font=S.FONT_MONO_SM,
                                  relief=tk.FLAT, width=26)
        self.wl_entry.pack(side=tk.LEFT)
        W.btn(wl_row, "Browse", self._browse_wordlist, width=8).pack(side=tk.LEFT, padx=4)

        self.rules_var = tk.BooleanVar(value=False)
        tk.Checkbutton(self.dict_frame, text="Apply mutation rules",
                       variable=self.rules_var, bg=S.BG_CARD, fg=S.FG_WHITE,
                       selectcolor=S.BG_INPUT, activebackground=S.BG_CARD,
                       activeforeground=S.FG_WHITE, font=S.FONT_LABEL).pack(
            anchor=tk.W, pady=(S.PAD_SM, 0))

        # ── Brute force settings ─────────────────────────────────────────
        self.brute_frame = tk.Frame(left, bg=S.BG_CARD)

        tk.Label(self.brute_frame, text="Character set:", bg=S.BG_CARD,
                 fg=S.FG_MUTED, font=S.FONT_LABEL).pack(anchor=tk.W)
        self.charset_var = tk.StringVar(value="Lower + digits (a-z 0-9)")
        cs_mb = tk.OptionMenu(self.brute_frame, self.charset_var,
                               *CHARSET_OPTIONS.keys(), command=self._update_estimate)
        cs_mb.config(bg=S.BG_INPUT, fg=S.FG_WHITE, font=S.FONT_LABEL,
                     relief=tk.FLAT, activebackground=S.BG_INPUT,
                     activeforeground=S.FG_WHITE, highlightthickness=0, width=24)
        cs_mb["menu"].config(bg=S.BG_INPUT, fg=S.FG_WHITE, font=S.FONT_LABEL)
        cs_mb.pack(anchor=tk.W, pady=(2, S.PAD))

        len_row = tk.Frame(self.brute_frame, bg=S.BG_CARD)
        len_row.pack(fill=tk.X)
        for txt, default, attr in [("Min len:", "1", "min_len"), ("Max len:", "5", "max_len")]:
            tk.Label(len_row, text=txt, bg=S.BG_CARD, fg=S.FG_MUTED,
                     font=S.FONT_LABEL, width=8, anchor=tk.W).pack(side=tk.LEFT)
            var = tk.StringVar(value=default)
            setattr(self, attr + "_var", var)
            e = tk.Entry(len_row, textvariable=var, bg=S.BG_INPUT, fg=S.FG_WHITE,
                         font=S.FONT_MONO, relief=tk.FLAT, width=4)
            e.pack(side=tk.LEFT, padx=(0, S.PAD))
            e.bind("<KeyRelease>", lambda _e: self._update_estimate())

        self.estimate_lbl = tk.Label(self.brute_frame, text="",
                                      bg=S.BG_CARD, fg=S.FG_MUTED, font=S.FONT_MONO_SM)
        self.estimate_lbl.pack(anchor=tk.W, pady=S.PAD_SM)

        W.separator(left, S.BG_INPUT).pack(fill=tk.X, padx=S.PAD, pady=S.PAD)

        # Sim mode password override
        self.sim_card = tk.Frame(left, bg=S.BG_CARD)
        self.sim_card.pack(fill=tk.X, padx=S.PAD)
        tk.Label(self.sim_card, text="[SIM] Hidden password:",
                 bg=S.BG_CARD, fg=S.FG_YELLOW, font=S.FONT_LABEL).pack(anchor=tk.W)
        self.sim_pw_entry = tk.Entry(self.sim_card, bg=S.BG_INPUT, fg=S.FG_YELLOW,
                                      font=S.FONT_MONO, relief=tk.FLAT, width=20, show="*")
        self.sim_pw_entry.pack(anchor=tk.W, pady=2)
        self.sim_pw_entry.insert(0, "password123")
        reveal_btn = tk.Button(self.sim_card, text="Reveal (instructor only)",
                               bg=S.BG_CARD, fg=S.FG_MUTED, font=S.FONT_UI_SM,
                               relief=tk.FLAT, bd=0, cursor="hand2",
                               command=self._reveal_sim_pw)
        reveal_btn.pack(anchor=tk.W)
        W.btn(self.sim_card, "Apply Password", self._apply_sim_pw, width=16).pack(
            anchor=tk.W, pady=S.PAD_SM)

        W.separator(left, S.BG_INPUT).pack(fill=tk.X, padx=S.PAD, pady=S.PAD)

        # Start / stop buttons
        btn_row = tk.Frame(left, bg=S.BG_CARD)
        btn_row.pack(padx=S.PAD, pady=S.PAD)
        self.start_btn = W.btn(btn_row, "Start Attack", self._start, width=14)
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn = W.danger_btn(btn_row, "Stop", self._stop, width=8)
        self.stop_btn.pack(side=tk.LEFT, padx=S.PAD_SM)
        self.stop_btn.config(state=tk.DISABLED)

        self._on_mode_change(ATTACK_MODES[0])
        self._update_estimate()

        # ── Right: live output ────────────────────────────────────────────
        right = tk.Frame(main, bg=S.BG_PANEL)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Stats bar
        stats_card = W.card(right)
        stats_card.pack(fill=tk.X, pady=(0, S.PAD_SM))

        stats_row = tk.Frame(stats_card, bg=S.BG_CARD)
        stats_row.pack(fill=tk.X, padx=S.PAD, pady=S.PAD)

        self._stat_vars = {}
        for lbl in ["Attempts", "Rate", "Elapsed", "Status"]:
            col = tk.Frame(stats_row, bg=S.BG_CARD)
            col.pack(side=tk.LEFT, expand=True)
            tk.Label(col, text=lbl, bg=S.BG_CARD, fg=S.FG_MUTED,
                     font=S.FONT_UI_SM).pack()
            val = tk.Label(col, text="—", bg=S.BG_CARD, fg=S.FG_WHITE,
                           font=S.FONT_MONO_LG)
            val.pack()
            self._stat_vars[lbl] = val

        # Progress bar
        self.pbar = W.progress_bar(right, max_val=100)
        self.pbar.pack(fill=tk.X, pady=(0, S.PAD_SM))
        self.pbar.config(mode="indeterminate")

        # ── Current attempt typewriter display ────────────────────────────
        attempt_card = W.card(right)
        attempt_card.pack(fill=tk.X, pady=(0, S.PAD_SM))

        hdr_row = tk.Frame(attempt_card, bg=S.BG_CARD)
        hdr_row.pack(fill=tk.X, padx=S.PAD, pady=(S.PAD_SM, 2))
        tk.Label(hdr_row, text="CURRENT ATTEMPT",
                 bg=S.BG_CARD, fg=S.ACCENT, font=S.FONT_LABEL_B).pack(side=tk.LEFT)
        self._anim_chars_lbl = tk.Label(hdr_row, text="",
                                         bg=S.BG_CARD, fg=S.FG_MUTED, font=S.FONT_UI_SM)
        self._anim_chars_lbl.pack(side=tk.RIGHT)

        self._anim_lbl = tk.Label(attempt_card, text="",
                                   bg=S.BG_CARD, fg=S.FG_GREEN,
                                   font=("Courier New", 22, "bold"),
                                   anchor=tk.W, padx=S.PAD)
        self._anim_lbl.pack(fill=tk.X, pady=(0, S.PAD_SM))

        # Animation state
        self._anim_target: str = ""
        self._anim_pos: int = 0
        self._anim_job = None

        # Log output
        log_card = W.card(right)
        log_card.pack(fill=tk.BOTH, expand=True)
        tk.Label(log_card, text="ATTACK LOG", bg=S.BG_CARD,
                 fg=S.ACCENT, font=S.FONT_LABEL_B).pack(
            anchor=tk.W, padx=S.PAD, pady=(S.PAD, S.PAD_SM))

        log_frame = W.scrolled_text(log_card, height=20)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=S.PAD, pady=(0, S.PAD))
        self.log = log_frame._text

        self.log.tag_config("header",  foreground=S.ACCENT)
        self.log.tag_config("success", foreground=S.SUCCESS)
        self.log.tag_config("fail",    foreground=S.DANGER)
        self.log.tag_config("info",    foreground=S.FG_MUTED)
        self.log.tag_config("try",     foreground=S.FG_WHITE)
        self.log.tag_config("warn",    foreground=S.FG_YELLOW)

        # Result banner
        self.result_banner = tk.Label(right, text="", bg=S.BG_PANEL,
                                       fg=S.FG_GREEN, font=S.FONT_MONO_LG)
        self.result_banner.pack(pady=S.PAD_SM)

    # ── Typewriter animation ──────────────────────────────────────────────────

    def _start_anim(self, word: str):
        """Begin revealing `word` one character at a time."""
        self._cancel_anim()
        self._anim_target = word
        self._anim_pos = 0
        self._tick_anim()

    def _tick_anim(self):
        target = self._anim_target
        pos = self._anim_pos
        if not target:
            return
        revealed = target[:pos]
        hidden   = "·" * (len(target) - pos)
        # Colour: revealed chars bright green, hidden chars dim
        display  = revealed + hidden
        self._anim_lbl.config(text=display)
        self._anim_chars_lbl.config(
            text=f"{pos}/{len(target)} chars")
        if pos < len(target):
            self._anim_pos += 1
            self._anim_job = self.after(80, self._tick_anim)
        else:
            self._anim_job = None

    def _cancel_anim(self):
        if self._anim_job is not None:
            self.after_cancel(self._anim_job)
            self._anim_job = None

    def _clear_anim(self):
        self._cancel_anim()
        self._anim_target = ""
        self._anim_pos = 0
        self._anim_lbl.config(text="")
        self._anim_chars_lbl.config(text="")

    def _flash_found(self, password: str):
        """Flash the found password in alternating colors."""
        self._cancel_anim()
        self._anim_lbl.config(text=password)
        self._anim_chars_lbl.config(text="MATCH!")
        colors = [S.FG_GREEN, S.SUCCESS, "#ffffff"]
        self._flash_cycle(password, colors, 0, 6)

    def _flash_cycle(self, password: str, colors: list, color_idx: int, remaining: int):
        if remaining <= 0:
            self._anim_lbl.config(fg=S.SUCCESS, text=f"  {password}  ")
            return
        self._anim_lbl.config(fg=colors[color_idx % len(colors)])
        self._anim_job = self.after(
            150, lambda: self._flash_cycle(password, colors, color_idx + 1, remaining - 1))

    # ── Mode switching ────────────────────────────────────────────────────────

    def _on_mode_change(self, mode):
        self.dict_frame.pack_forget()
        self.brute_frame.pack_forget()
        if mode == "Brute Force":
            self.brute_frame.pack(fill=tk.X, padx=S.PAD)
            self._update_estimate()
        else:
            self.dict_frame.pack(fill=tk.X, padx=S.PAD)

    def _update_estimate(self, *_):
        try:
            cs = CHARSET_OPTIONS[self.charset_var.get()]
            mn = max(1, int(self.min_len_var.get() or 1))
            mx = max(mn, int(self.max_len_var.get() or 1))
            total = estimate_brute_count(len(cs), mn, mx)
            if total >= 1_000_000_000:
                s = f"~{total/1e9:.1f}B candidates"
            elif total >= 1_000_000:
                s = f"~{total/1e6:.1f}M candidates"
            elif total >= 1_000:
                s = f"~{total/1e3:.1f}K candidates"
            else:
                s = f"{total} candidates"
            self.estimate_lbl.config(text=s)
        except Exception:
            self.estimate_lbl.config(text="")

    # ── Simulation password ───────────────────────────────────────────────────

    def set_sim_drive(self, drive: SimulatedDrive):
        self.sim_drive = drive

    def set_live_drive(self, drive: WDECBDrive):
        """Set a live WD ECB drive as the cracking target."""
        self.sim_drive = drive   # WDECBDrive has same try_password() interface
        self._log(
            f"[LIVE] WD ECB drive loaded: /dev/{drive.disk_id}\n"
            f"[LIVE] Cipher    : {drive.cipher_name}\n"
            f"[LIVE] Iterations: {drive.iterations}\n"
            f"[LIVE] Salt      : {drive.salt_hex}\n"
            f"[LIVE] Hint      : {drive.hint or '(none)'}\n",
            "warn")
        self._log(
            "[!] LIVE MODE: each wrong attempt hits the real drive.\n"
            "[!] Hardware counter limits wrong attempts (~5 max).\n"
            "[!] Set a password you KNOW is in the wordlist before demo.\n\n",
            "fail")

    def _reveal_sim_pw(self):
        cur = self.sim_pw_entry.cget("show")
        self.sim_pw_entry.config(show="" if cur == "*" else "*")

    def _apply_sim_pw(self):
        pw = self.sim_pw_entry.get().strip()
        if not pw:
            return
        from core.wd_security import make_demo_drive
        self.sim_drive = make_demo_drive(pw)
        self._log(f"[SIM] Drive password set to: {'*' * len(pw)} ({len(pw)} chars)\n", "warn")
        self._log(f"[SIM] Salt: {self.sim_drive.salt.hex().upper()}\n", "info")

    # ── Attack control ────────────────────────────────────────────────────────

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(
            title="Select Wordlist",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.wordlist_var.set(path)

    def _start(self):
        if self.sim_drive is None and self.demo_mode:
            from core.wd_security import make_demo_drive
            self.sim_drive = make_demo_drive("password123")
            self._log("[SIM] No drive configured — using default demo drive\n", "warn")

        self.log.config(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.result_banner.config(text="")
        self._clear_anim()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.pbar.config(mode="indeterminate")
        self.pbar.start(10)

        mode = self.mode_var.get()

        if self.sim_drive:
            verify_fn = self.sim_drive.try_password
        else:
            messagebox.showerror("No Drive", "No drive or simulation configured.")
            self._reset_buttons()
            return

        self.cracker = Cracker(verify_fn)

        if mode == "Brute Force":
            cs = CHARSET_OPTIONS[self.charset_var.get()]
            try:
                mn = max(1, int(self.min_len_var.get()))
                mx = max(mn, int(self.max_len_var.get()))
            except ValueError:
                mn, mx = 1, 4
            self._log(f"[*] Starting brute force: charset={self.charset_var.get()}, "
                      f"len={mn}-{mx}\n", "header")
            self.cracker.brute_force_attack(
                charset=cs, min_len=mn, max_len=mx,
                progress_cb=self._on_progress, done_cb=self._on_done)
        else:
            wl = self.wordlist_var.get()
            use_rules = self.rules_var.get() or (mode == "Dictionary + Rules (Hybrid)")
            lines = sum(1 for _ in open(wl, errors="ignore")) if os.path.isfile(wl) else 0
            multiplier = " × ~14 (with rules)" if use_rules else ""
            self._log(f"[*] Dictionary attack: {os.path.basename(wl)} "
                      f"({lines} words{multiplier})\n", "header")
            self.cracker.dictionary_attack(
                wordlist_path=wl, use_rules=use_rules,
                progress_cb=self._on_progress, done_cb=self._on_done)

    def _stop(self):
        if self.cracker:
            self.cracker.stop()
        self._reset_buttons()
        self._log("\n[!] Attack stopped by user.\n", "warn")

    def _reset_buttons(self):
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.pbar.stop()
        self.pbar.config(mode="determinate", value=0)
        self._clear_anim()

    # ── Callbacks ─────────────────────────────────────────────────────────────

    _prev_log_word = ""

    def _on_progress(self, attempts: int, current: str, elapsed: float):
        rate = format_rate(attempts, elapsed)
        self.after(0, lambda: self._update_stats(attempts, rate, elapsed, "Running..."))
        # Typewriter: animate every candidate
        word = current
        self.after(0, lambda: self._start_anim(word))
        # Only log every ~500 attempts to avoid flooding
        if attempts % 500 == 1 or attempts <= 10:
            self.after(0, lambda: self._log(
                f"  [{attempts:>8}] Trying: {current!r:<24}  rate={rate}\n", "try"))

    def _on_done(self, result: CrackResult):
        self.after(0, lambda: self._finish(result))

    def _finish(self, result: CrackResult):
        self.pbar.stop()
        self.pbar.config(mode="determinate")
        self._reset_buttons()
        rate = format_rate(result.attempts, result.elapsed)

        if result.found:
            self.pbar.config(value=100)
            self._flash_found(result.password)
            self._log(f"\n{'='*60}\n", "success")
            self._log(f"  PASSWORD FOUND: {result.password!r}\n", "success")
            self._log(f"{'='*60}\n", "success")
            self._log(f"  Attempts : {result.attempts:,}\n", "info")
            self._log(f"  Elapsed  : {result.elapsed:.2f}s\n", "info")
            self._log(f"  Rate     : {rate}\n", "info")
            self._log(f"{'='*60}\n\n", "success")
            self._update_stats(result.attempts, rate, result.elapsed, "CRACKED")
            self._stat_vars["Status"].config(fg=S.SUCCESS)
            self.result_banner.config(
                text=f"  PASSWORD: {result.password}  ", fg=S.FG_GREEN,
                bg=S.BG_CARD, relief=tk.SOLID, bd=1)
            # Reveal characters one by one in the log so audience can follow
            self._reveal_chars_in_log(result.password)

            # For live WD ECB drives: the unlock already happened inside try_password.
            # Log wrong attempts so instructor can see the counter impact.
            if isinstance(self.sim_drive, WDECBDrive):
                wrong = self.sim_drive.wrong_count
                self._log(
                    f"[LIVE] Drive unlocked!  Wrong attempts used: {wrong}\n"
                    f"[LIVE] Run 'sudo wdpassport-utils.py --device "
                    f"/dev/{self.sim_drive.disk_id} --mount' to mount.\n",
                    "success")
        elif result.stopped:
            self._update_stats(result.attempts, rate, result.elapsed, "STOPPED")
            self._stat_vars["Status"].config(fg=S.FG_YELLOW)
        else:
            self._log("\n[X] Password NOT found in wordlist/charset.\n", "fail")
            self._update_stats(result.attempts, rate, result.elapsed, "NOT FOUND")
            self._stat_vars["Status"].config(fg=S.DANGER)

    def _reveal_chars_in_log(self, password: str):
        """Log each character of the found password one by one with a delay."""
        ordinals = ["1st", "2nd", "3rd"] + [f"{i}th" for i in range(4, len(password) + 1)]
        self._log("\n[*] Character-by-character reveal:\n", "header")
        for i, ch in enumerate(password):
            delay_ms = 350 * (i + 1)
            label = ordinals[i] if i < len(ordinals) else f"{i+1}th"
            # Build the log line: show chars revealed so far + remaining as dots
            revealed = password[:i + 1]
            hidden   = "·" * (len(password) - i - 1)
            display  = revealed + hidden

            def _log_char(lbl=label, c=ch, disp=display):
                self._log(f"    {lbl:>4} character → ", "info")
                self._log(f"'{c}'", "success")
                self._log(f"   {disp}\n", "try")

            self.after(delay_ms, _log_char)

        # Final confirmation after all chars shown
        final_delay = 350 * (len(password) + 2)
        pw = password
        self.after(final_delay, lambda: self._log(
            f"\n  ✓ Full password confirmed: {pw!r}\n\n", "success"))

    def _update_stats(self, attempts, rate, elapsed, status):
        self._stat_vars["Attempts"].config(text=f"{attempts:,}")
        self._stat_vars["Rate"].config(text=rate)
        self._stat_vars["Elapsed"].config(text=f"{elapsed:.1f}s")
        self._stat_vars["Status"].config(text=status, fg=S.FG_WHITE)

    def _log(self, msg: str, tag: str = ""):
        self.log.config(state=tk.NORMAL)
        if tag:
            self.log.insert(tk.END, msg, tag)
        else:
            self.log.insert(tk.END, msg)
        self.log.see(tk.END)
        self.log.config(state=tk.DISABLED)
