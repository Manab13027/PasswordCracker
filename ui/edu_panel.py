"""
Educational Reference Panel — shown as a tab in the main window.
Static reference material for students.
"""

import tkinter as tk
from . import styles as S
from . import widgets as W


TOPICS = {
    "ATA / Drive Security": """\
ATA SECURITY (ATA-3 Standard)
══════════════════════════════
The ATA Security feature set defines how hard drives can be locked.
WD My Passport implements a variant of this over USB using SCSI.

SECURITY LEVELS
  • Security Enabled  — drive locks on power-off
  • Security Locked   — currently locked, read/write blocked
  • Security Frozen   — security commands temporarily disabled (BIOS protection)
  • Security Not Supported — older or NAS drives

KEY COMMANDS (SCSI equivalents)
  SECURITY SET PASSWORD   → Store an unlock key on-disk
  SECURITY UNLOCK         → Attempt to unlock with a key
  SECURITY ERASE PREPARE  → Required before erase commands
  SECURITY ERASE UNIT     → Crypto-erase: regenerates DEK

FORENSIC NOTE
  If a drive is in "frozen" state, a forensic analyst can power-cycle
  the drive (hot-unplug/replug) to reset to "locked" state, then
  attempt password recovery.
""",

    "PBKDF2 Key Derivation": """\
PBKDF2 — PASSWORD-BASED KEY DERIVATION FUNCTION 2 (RFC 2898)
═════════════════════════════════════════════════════════════
PBKDF2 is used to stretch a password into a cryptographic key.

FORMULA
  DK = PBKDF2(PRF, Password, Salt, c, dkLen)
  Where:
    PRF      = Pseudo-random function (WD uses HMAC-SHA256)
    Password = User's password (UTF-16LE encoded by WD)
    Salt     = Random bytes stored on drive (32 bytes)
    c        = Iteration count (typically 1000 for WD)
    dkLen    = Desired key length (32 bytes → 256-bit key)

WHY ITERATIONS MATTER
  Each password candidate requires c hash computations.
  At 1000 iterations on modern hardware (~10M PBKDF2/s):
    • A 6-digit PIN (10^6 possibilities) ≈ 0.1 seconds
    • All 8-char lowercase (26^8 ≈ 209B) ≈ several years
    • Common wordlist (10M words) ≈ 1 second

COMPARISON TO SIMPLE SHA-256
  Simple: H = SHA256(salt + password)
    → GPU can compute 10 BILLION per second
    → Any 8-char password cracked in seconds
  PBKDF2 with 1000 iters: 10M/s (GPU), 1M/s (CPU)
    → 1000× harder to crack = much better protection
""",

    "SCSI Security Protocol": """\
SCSI SECURITY PROTOCOL (SPC-4)
════════════════════════════════
WD My Passport uses SCSI security commands over USB bulk transfer.

COMMANDS
  SECURITY PROTOCOL IN  (opcode 0xA2) — read from drive
  SECURITY PROTOCOL OUT (opcode 0xB5) — write to drive

CDB STRUCTURE (12 bytes)
  Byte 0:    Opcode (0xA2 or 0xB5)
  Byte 1:    Security Protocol ID
  Bytes 2-3: Security Protocol Specific (page code)
  Byte 4:    INC_512 flag
  Byte 5:    Reserved
  Bytes 6-9: Allocation Length (big-endian)
  Byte 10:   Reserved
  Byte 11:   Control

WD PROTOCOL IDs
  0x00  — Security Protocol Information (list supported protocols)
  0xC1  — WD vendor-specific unlock protocol
    Page 0x00 → security capability info
    Page 0x06 → security status (locked/unlocked)
    Page 0x0E → challenge block (salt + iteration count)

EXTRACTION WITH sg_raw (Linux/macOS with sg3_utils)
  # Get supported protocols (40 bytes)
  sg_raw -r 40 /dev/sdb A2 00 00 00 00 00 00 00 28 00 00 00

  # Get WD challenge block (40 bytes)
  sg_raw -r 40 /dev/sdb A2 C1 00 00 0E 00 00 00 28 00 00 00

  # Send unlock response (40 bytes of derived key)
  sg_raw /dev/sdb B5 C1 00 00 0E 00 00 00 28 00 00 00 [40 bytes]
""",

    "Attack Strategies": """\
PASSWORD ATTACK STRATEGIES
═══════════════════════════

1. DICTIONARY ATTACK
   Try passwords from a pre-compiled wordlist.
   Best against: human-chosen passwords
   Speed: 1M–10M words/s (CPU), fast for short lists
   Tools: hashcat, john, this demo app

2. RULE-BASED / MANGLING
   Apply mutations to dictionary words:
     summer → Summer, summer1, summer!, 5ummer, SUMMER
   Catches: simple substitutions and appended numbers
   Multiplier: 10-50× the raw wordlist size

3. BRUTE FORCE
   Try every combination of characters up to length N.
   Best against: short unknown passwords
   Feasible lengths:
     • ≤4 digits: instant
     • ≤6 lowercase: seconds to minutes
     • ≤8 lowercase+digits: hours to days on CPU
     • ≤8 full charset: months on GPU cluster

4. HYBRID ATTACK
   Combine wordlist + brute force:
     e.g., dictionary word + 2-digit suffix
     "summer" + "23" → "summer23"

5. SMART / MARKOV ATTACKS (Hashcat -a 6/7)
   Use statistical models of password patterns.
   Prioritises likely character sequences.

PRIORITISATION ADVICE
   For forensic work: always try dictionary + rules first.
   Only fall back to brute force for short PINs or if dictionary fails.
   GPU acceleration (hashcat) offers 100-1000× speedup over CPU.

PBKDF2 IMPACT ON SPEED
   WD uses 1000 PBKDF2 iterations, which slows attacks significantly.
   Compare: MD5 on GPU = 60 GH/s vs PBKDF2(1000,SHA256) = ~100 KH/s
   This makes GPU cracking far less effective than against simple hashes.
""",

    "Forensic Best Practices": """\
FORENSIC ACQUISITION BEST PRACTICES
══════════════════════════════════════

CHAIN OF CUSTODY
  • Document every action taken on the evidence drive
  • Record drive serial number, model, firmware version
  • Use write-blockers for all read operations
  • Create forensic image (dd, dcfldd, FTK Imager) before any analysis

WRITE BLOCKER USAGE
  Hardware write-blockers are preferred (Tableau, FastBloc).
  Software write-blockers: Windows registry, Linux hdparm -r1
  Never mount a suspect drive read-write.

HASH VERIFICATION
  Always create an MD5 + SHA256 hash of the original drive:
    dd if=/dev/sdX | tee evidence.img | sha256sum
  Verify the image hash matches before and after analysis.

ENCRYPTED DRIVE HANDLING
  If drive is locked:
    1. Do NOT attempt passwords on the physical drive (attempt counter!)
    2. Extract the challenge/salt block non-destructively
    3. Run offline password recovery against extracted hash
    4. If password found: unlock only on a verified copy/image

WD MY PASSPORT SPECIFIC
  • Some models enforce a retry counter (typically 5 attempts → erase)
  • Always verify if retry locking is active before online attempts
  • The SCSI Security Status page (0x06) shows the attempt counter
  • Safest approach: forensic image first, crack the image's key material

TOOLS USED IN PROFESSIONAL FORENSICS
  • Passware Kit Forensic (commercial, supports WD drives)
  • Elcomsoft Forensic Disk Decryptor (commercial)
  • hashcat (open source, GPU accelerated)
  • John the Ripper (open source, CPU based)
  • wdpassport-utils (open source, Linux)
""",
}


class EduPanel(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=S.BG_PANEL, **kwargs)
        self._build()

    def _build(self):
        pane = tk.PanedWindow(self, orient=tk.HORIZONTAL,
                              bg=S.BG_PANEL, sashwidth=4, sashrelief=tk.FLAT)
        pane.pack(fill=tk.BOTH, expand=True, padx=S.PAD, pady=S.PAD)

        # Topic list
        left = W.card(pane)
        pane.add(left, minsize=180)

        tk.Label(left, text="TOPICS", bg=S.BG_CARD, fg=S.ACCENT,
                 font=S.FONT_LABEL_B).pack(anchor=tk.W, padx=S.PAD, pady=(S.PAD, S.PAD_SM))

        self.topic_lb = tk.Listbox(
            left, bg=S.BG_INPUT, fg=S.FG_WHITE, font=S.FONT_LABEL,
            relief=tk.FLAT, bd=0, selectbackground=S.ACCENT,
            selectforeground=S.BG_DARK, activestyle="none", width=22)
        self.topic_lb.pack(fill=tk.BOTH, expand=True, padx=S.PAD_SM, pady=S.PAD_SM)

        for topic in TOPICS:
            self.topic_lb.insert(tk.END, f"  {topic}")

        self.topic_lb.bind("<<ListboxSelect>>", self._on_select)
        self.topic_lb.selection_set(0)

        # Content area
        right = W.card(pane)
        pane.add(right, minsize=400)

        self.content_text = tk.Text(
            right, bg=S.BG_INPUT, fg=S.FG_CYAN,
            font=S.FONT_MONO_SM, relief=tk.FLAT, bd=0,
            wrap=tk.WORD, state=tk.DISABLED, padx=S.PAD, pady=S.PAD)
        scroll = tk.Scrollbar(right, command=self.content_text.yview, bg=S.BG_CARD)
        self.content_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.content_text.pack(fill=tk.BOTH, expand=True)

        self._show_topic(list(TOPICS.keys())[0])

    def _on_select(self, event):
        sel = self.topic_lb.curselection()
        if not sel:
            return
        topic = list(TOPICS.keys())[sel[0]]
        self._show_topic(topic)

    def _show_topic(self, topic):
        self.content_text.config(state=tk.NORMAL)
        self.content_text.delete("1.0", tk.END)
        self.content_text.insert(tk.END, TOPICS[topic])
        self.content_text.config(state=tk.DISABLED)
