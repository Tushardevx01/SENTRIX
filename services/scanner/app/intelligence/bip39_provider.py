"""
BIP-39 Wordlist Intelligence Provider
Provides O(1) in-memory lookups for the standard BIP-39 English mnemonic wordlist.
Used to identify and corroborate cryptocurrency seed-phrase collection forms.
"""

import os
import hashlib
import threading
from pathlib import Path
from typing import Set, Optional, Dict, Any, Iterable

# Path to the bundled 2,048-word English list
DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "bip39"
DEFAULT_BIP39_FILE = DATA_DIR / "english.txt"

# Expected SHA-256 for the standard 2,048-word BIP-39 English wordlist
EXPECTED_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

# Fallback canary words from BIP-39 in case of missing or corrupted data file
BUNDLED_CANARY_WORDS = frozenset({
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "wallet", "token", "crypto", "exchange", "phrase", "seed", "mnemonic", "private",
    "secret", "recovery", "verify", "restore", "import", "backup", "connect", "network",
})


class BIP39Provider:
    """Thread-safe, in-memory BIP-39 English mnemonic vocabulary provider."""

    _instance: Optional["BIP39Provider"] = None
    _lock = threading.Lock()

    def __init__(self, file_path: Optional[Path] = None):
        self.file_path = file_path or DEFAULT_BIP39_FILE
        self._words: frozenset[str] = frozenset()
        self._sha256: str = ""
        self._is_degraded: bool = False
        self._reload_lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        """Loads and parses the BIP-39 wordlist into an immutable frozenset."""
        if not self.file_path.exists():
            self._words = BUNDLED_CANARY_WORDS
            self._is_degraded = True
            return

        try:
            with open(self.file_path, "rb") as f:
                content = f.read()

            sha256 = hashlib.sha256(content).hexdigest()
            text = content.decode("utf-8")
            words = [line.strip().lower() for line in text.splitlines() if line.strip()]

            if len(words) != 2048:
                # Corrupted or incomplete
                self._words = BUNDLED_CANARY_WORDS
                self._is_degraded = True
                return

            self._words = frozenset(words)
            self._sha256 = sha256
            self._is_degraded = False

        except Exception:
            self._words = BUNDLED_CANARY_WORDS
            self._is_degraded = True

    def reload(self) -> None:
        """Thread-safe zero-downtime reload of the wordlist."""
        with self._reload_lock:
            self._load()

    def is_bip39_word(self, word: str) -> bool:
        """O(1) check if a word is in the BIP-39 vocabulary."""
        return word.strip().lower() in self._words

    def count_bip39_words(self, words: Iterable[str]) -> int:
        """Counts how many words in the given iterable are valid BIP-39 words."""
        count = 0
        for w in words:
            cleaned = w.strip().lower()
            if cleaned and cleaned in self._words:
                count += 1
        return count

    def is_valid_mnemonic_candidate(self, words: Iterable[str]) -> bool:
        """
        Determines whether a sequence of words looks like a BIP-39 mnemonic candidate.
        Standard lengths: 12, 15, 18, 21, or 24 words where a significant majority
        belong to the BIP-39 vocabulary.
        """
        word_list = [w.strip().lower() for w in words if w.strip()]
        count = len(word_list)
        if count not in (12, 15, 18, 21, 24):
            return False

        bip39_count = sum(1 for w in word_list if w in self._words)
        # At least 75% of words must match BIP-39 vocabulary
        return (bip39_count / count) >= 0.75

    @property
    def words(self) -> frozenset[str]:
        return self._words

    @property
    def is_degraded(self) -> bool:
        return self._is_degraded

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "totalWords": len(self._words),
            "sha256": self._sha256,
            "isDegraded": self._is_degraded,
            "filePath": str(self.file_path),
        }


def get_bip39_provider() -> BIP39Provider:
    """Singleton accessor for BIP39Provider."""
    if BIP39Provider._instance is None:
        with BIP39Provider._lock:
            if BIP39Provider._instance is None:
                BIP39Provider._instance = BIP39Provider()
    return BIP39Provider._instance
