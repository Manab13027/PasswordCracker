"""
Password Cracker Engine
=======================
Supports three attack modes:
  1. Dictionary attack  — try passwords from a wordlist file
  2. Brute force        — exhaustive character-space enumeration
  3. Rule-based         — apply common mutation rules to a wordlist

Each mode runs in a background thread and reports progress via a callback.
"""

import threading
import itertools
import string
import time
import os
from typing import Callable, Optional


# ── Rule engine ─────────────────────────────────────────────────────────────

def _apply_rules(word: str):
    """Yield the original word plus common mutations."""
    yield word
    yield word.lower()
    yield word.upper()
    yield word.capitalize()
    # Append common suffixes
    for suffix in ("1", "123", "!", "1234", "@", "2024", "2023", "01", "12"):
        yield word + suffix
        yield word.lower() + suffix
        yield word.capitalize() + suffix
    # Prepend common prefixes
    for prefix in ("!", "1", "my", "the"):
        yield prefix + word
        yield prefix + word.capitalize()
    # Leet speak substitutions
    leet = word.lower().replace("a", "@").replace("e", "3").replace("i", "1") \
                       .replace("o", "0").replace("s", "$")
    if leet != word.lower():
        yield leet
        yield leet.capitalize()
        yield leet + "1"
        yield leet + "!"


# ── Cracker ─────────────────────────────────────────────────────────────────

class CrackResult:
    def __init__(self):
        self.found = False
        self.password: Optional[str] = None
        self.attempts = 0
        self.elapsed = 0.0
        self.stopped = False


class Cracker:
    """
    Generic password cracker that accepts a verification callable.

    verify_fn(candidate: str) -> bool
        Must return True if the candidate is the correct password.
    """

    def __init__(self, verify_fn: Callable[[str], bool]):
        self.verify_fn = verify_fn
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.result = CrackResult()

    def stop(self):
        self._stop_event.set()

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Dictionary attack ────────────────────────────────────────────────────

    def dictionary_attack(
        self,
        wordlist_path: str,
        use_rules: bool = False,
        progress_cb: Optional[Callable[[int, str, float], None]] = None,
        done_cb: Optional[Callable[[CrackResult], None]] = None,
    ):
        """
        Launch dictionary attack in a background thread.

        progress_cb(attempts, current_word, elapsed_seconds)
        done_cb(result)
        """
        self._stop_event.clear()
        self.result = CrackResult()
        self._thread = threading.Thread(
            target=self._dict_worker,
            args=(wordlist_path, use_rules, progress_cb, done_cb),
            daemon=True,
        )
        self._thread.start()

    def _dict_worker(self, wordlist_path, use_rules, progress_cb, done_cb):
        start = time.time()
        attempts = 0
        last_report = 0

        if not os.path.isfile(wordlist_path):
            self.result.stopped = True
            if done_cb:
                done_cb(self.result)
            return

        with open(wordlist_path, "r", errors="ignore") as f:
            for line in f:
                if self._stop_event.is_set():
                    self.result.stopped = True
                    break

                word = line.rstrip("\n\r")
                candidates = list(_apply_rules(word)) if use_rules else [word]

                for candidate in candidates:
                    if self._stop_event.is_set():
                        self.result.stopped = True
                        break
                    attempts += 1
                    now = time.time()

                    if now - last_report >= 0.05 and progress_cb:
                        progress_cb(attempts, candidate, now - start)
                        last_report = now

                    if self.verify_fn(candidate):
                        self.result.found = True
                        self.result.password = candidate
                        self.result.attempts = attempts
                        self.result.elapsed = time.time() - start
                        if progress_cb:
                            progress_cb(attempts, candidate, self.result.elapsed)
                        if done_cb:
                            done_cb(self.result)
                        return

        self.result.attempts = attempts
        self.result.elapsed = time.time() - start
        if done_cb:
            done_cb(self.result)

    # ── Brute force attack ───────────────────────────────────────────────────

    def brute_force_attack(
        self,
        charset: str = string.digits + string.ascii_lowercase,
        min_len: int = 1,
        max_len: int = 6,
        progress_cb: Optional[Callable[[int, str, float], None]] = None,
        done_cb: Optional[Callable[[CrackResult], None]] = None,
    ):
        """
        Exhaustive brute force over charset from min_len to max_len.
        """
        self._stop_event.clear()
        self.result = CrackResult()
        self._thread = threading.Thread(
            target=self._brute_worker,
            args=(charset, min_len, max_len, progress_cb, done_cb),
            daemon=True,
        )
        self._thread.start()

    def _brute_worker(self, charset, min_len, max_len, progress_cb, done_cb):
        start = time.time()
        attempts = 0
        last_report = 0

        for length in range(min_len, max_len + 1):
            if self._stop_event.is_set():
                self.result.stopped = True
                break
            for combo in itertools.product(charset, repeat=length):
                if self._stop_event.is_set():
                    self.result.stopped = True
                    break

                candidate = "".join(combo)
                attempts += 1
                now = time.time()

                if now - last_report >= 0.05 and progress_cb:
                    progress_cb(attempts, candidate, now - start)
                    last_report = now

                if self.verify_fn(candidate):
                    self.result.found = True
                    self.result.password = candidate
                    self.result.attempts = attempts
                    self.result.elapsed = time.time() - start
                    if progress_cb:
                        progress_cb(attempts, candidate, self.result.elapsed)
                    if done_cb:
                        done_cb(self.result)
                    return

        self.result.attempts = attempts
        self.result.elapsed = time.time() - start
        if done_cb:
            done_cb(self.result)

    # ── Hybrid attack ────────────────────────────────────────────────────────

    def hybrid_attack(
        self,
        wordlist_path: str,
        append_charset: str = string.digits,
        append_len: int = 2,
        progress_cb=None,
        done_cb=None,
    ):
        """
        Hybrid: word + N appended characters from charset.
        e.g., "summer" + "23" → "summer23"
        """
        self._stop_event.clear()
        self.result = CrackResult()
        self._thread = threading.Thread(
            target=self._hybrid_worker,
            args=(wordlist_path, append_charset, append_len, progress_cb, done_cb),
            daemon=True,
        )
        self._thread.start()

    def _hybrid_worker(self, wordlist_path, append_charset, append_len, progress_cb, done_cb):
        start = time.time()
        attempts = 0
        last_report = 0

        if not os.path.isfile(wordlist_path):
            self.result.stopped = True
            if done_cb:
                done_cb(self.result)
            return

        with open(wordlist_path, "r", errors="ignore") as f:
            words = [line.rstrip("\n\r") for line in f]

        for word in words:
            if self._stop_event.is_set():
                self.result.stopped = True
                break
            for suffix_combo in itertools.product(append_charset, repeat=append_len):
                if self._stop_event.is_set():
                    self.result.stopped = True
                    break
                candidate = word + "".join(suffix_combo)
                attempts += 1
                now = time.time()
                if now - last_report >= 0.05 and progress_cb:
                    progress_cb(attempts, candidate, now - start)
                    last_report = now
                if self.verify_fn(candidate):
                    self.result.found = True
                    self.result.password = candidate
                    self.result.attempts = attempts
                    self.result.elapsed = time.time() - start
                    if progress_cb:
                        progress_cb(attempts, candidate, self.result.elapsed)
                    if done_cb:
                        done_cb(self.result)
                    return

        self.result.attempts = attempts
        self.result.elapsed = time.time() - start
        if done_cb:
            done_cb(self.result)


# ── Utility ──────────────────────────────────────────────────────────────────

def estimate_brute_count(charset_len: int, min_len: int, max_len: int) -> int:
    total = 0
    for n in range(min_len, max_len + 1):
        total += charset_len ** n
    return total


def format_rate(attempts: int, elapsed: float) -> str:
    if elapsed < 0.001:
        return "N/A"
    rate = attempts / elapsed
    if rate >= 1_000_000:
        return f"{rate/1_000_000:.1f}M/s"
    if rate >= 1_000:
        return f"{rate/1_000:.1f}K/s"
    return f"{rate:.0f}/s"
