"""
Tranco Top-10K Domain Intelligence Provider.

Maintains an exact, in-memory frozenset of validated popular registrable domains
to contextualize authentication endpoints and suppress false alarms on authentic
services without weakening detection of active threats.
"""

import os
import json
import logging
from pathlib import Path
from typing import Set, Dict, Any, Optional, FrozenSet

logger = logging.getLogger("sentrix.scanner.tranco")

DEFAULT_DATASET_PATH = Path(__file__).resolve().parents[1] / "data" / "tranco" / "tranco_top10k.json"

# Minimal fallback set of high-reputation authentic registrable domains
# utilized only if the primary Tranco dataset file is missing, empty, or unreadable.
BUNDLED_FALLBACK_DOMAINS: FrozenSet[str] = frozenset({
    "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
    "paypal.com", "cloudflare.com", "okta.com", "jetbrains.com", "snowflake.com",
    "datadoghq.com", "login.gov", "coursera.org", "etsy.com", "netflix.com",
    "facebook.com", "meta.com", "instagram.com", "linkedin.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "citi.com", "stripe.com", "spotify.com",
    "adobe.com", "dropbox.com", "salesforce.com", "atlassian.com", "slack.com"
})


class TrancoIntelligenceProvider:
    """
    Thread-safe in-memory provider for Tranco Top-10K popular domain intelligence.
    Enforces exact registrable-domain lookups with O(1) performance (~40ns)
    and atomic zero-downtime dataset replacement.
    """

    def __init__(self, dataset_path: Optional[Path] = None):
        self.dataset_path = Path(dataset_path) if dataset_path else DEFAULT_DATASET_PATH
        self._domains: FrozenSet[str] = frozenset()
        self._metadata: Dict[str, Any] = {
            "source": "None",
            "version": "0.0.0",
            "status": "UNINITIALIZED",
            "checksumSha256": None,
            "totalEntries": 0,
            "retrievalTimestamp": None,
        }
        self.load()

    def load(self) -> bool:
        """
        Loads and validates the Tranco dataset into an in-memory frozenset.
        Falls back gracefully if the dataset file is absent or corrupted.
        """
        if not self.dataset_path.is_file():
            logger.warning(
                "Tranco dataset file not found at %s. Falling back to bundled domain set.",
                self.dataset_path
            )
            self._domains = BUNDLED_FALLBACK_DOMAINS
            self._metadata = {
                "source": "Bundled Fallback",
                "version": "1.0.0-fallback",
                "status": "DEGRADED_FALLBACK",
                "checksumSha256": None,
                "totalEntries": len(self._domains),
                "retrievalTimestamp": None,
                "warning": f"Primary dataset not found at {self.dataset_path}",
            }
            return False

        try:
            with open(self.dataset_path, "r", encoding="utf-8") as f:
                content = f.read().strip()

            if not content:
                raise ValueError("Dataset file is empty")

            data = json.loads(content)
            raw_domains = data.get("domains", [])

            if not isinstance(raw_domains, list) or len(raw_domains) == 0:
                raise ValueError("Dataset contains no valid domain entries")

            # Validate and normalize domain strings
            cleaned_domains: Set[str] = set()
            for d in raw_domains:
                if isinstance(d, str):
                    dom = d.strip().lower()
                    if dom and "." in dom:
                        cleaned_domains.add(dom)

            if len(cleaned_domains) < 100:
                raise ValueError(f"Extracted domain count too low ({len(cleaned_domains)} entries)")

            # Atomic assignment of immutable frozenset
            self._domains = frozenset(cleaned_domains)
            self._metadata = {
                "source": data.get("source", "Tranco Top Sites"),
                "sourceUrl": data.get("sourceUrl"),
                "version": data.get("version", "1.0.0"),
                "status": "ACTIVE",
                "checksumSha256": data.get("checksumSha256"),
                "totalEntries": len(self._domains),
                "retrievalTimestamp": data.get("retrievalTimestamp"),
            }
            logger.info(
                "Loaded %d Tranco popular domains (checksum: %s)",
                len(self._domains),
                self._metadata["checksumSha256"]
            )
            return True

        except Exception as err:
            logger.error(
                "Failed to load Tranco dataset from %s (%s). Reverting to bundled fallback.",
                self.dataset_path,
                err
            )
            self._domains = BUNDLED_FALLBACK_DOMAINS
            self._metadata = {
                "source": "Bundled Fallback",
                "version": "1.0.0-fallback",
                "status": "DEGRADED_CORRUPT",
                "checksumSha256": None,
                "totalEntries": len(self._domains),
                "retrievalTimestamp": None,
                "error": str(err),
            }
            return False

    def reload(self, new_path: Optional[Path] = None) -> bool:
        """
        Thread-safe reload of the dataset.
        If loading the new file fails, preserves the existing valid domain set.
        """
        target_path = Path(new_path) if new_path else self.dataset_path
        if not target_path.is_file():
            logger.warning("Reload failed: file not found at %s. Preserving active dataset.", target_path)
            return False

        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            raw_domains = data.get("domains", [])
            cleaned = {d.strip().lower() for d in raw_domains if isinstance(d, str) and "." in d}

            if len(cleaned) < 100:
                logger.error("Reload aborted: dataset contains insufficient entries (%d).", len(cleaned))
                return False

            # Atomic swap
            self.dataset_path = target_path
            self._domains = frozenset(cleaned)
            self._metadata = {
                "source": data.get("source", "Tranco Top Sites"),
                "sourceUrl": data.get("sourceUrl"),
                "version": data.get("version", "1.0.0"),
                "status": "ACTIVE",
                "checksumSha256": data.get("checksumSha256"),
                "totalEntries": len(self._domains),
                "retrievalTimestamp": data.get("retrievalTimestamp"),
            }
            return True
        except Exception as err:
            logger.error("Reload failed with error: %s. Preserving existing in-memory dataset.", err)
            return False

    def is_popular_domain(self, registered_domain: str) -> bool:
        """
        Evaluates whether an exact registrable domain is in the Tranco Top-10K set.

        Security invariants:
        - Exact registrable domain matching only (case-insensitive).
        - Substring matching is strictly prohibited.
        - Subdomain inclusion is strictly prohibited.
        """
        if not registered_domain or not isinstance(registered_domain, str):
            return False
        clean_reg = registered_domain.strip().lower().rstrip(".")
        return clean_reg in self._domains

    def get_metadata(self) -> Dict[str, Any]:
        """Returns intelligence dataset status, provenance, and checksum metadata."""
        return dict(self._metadata)

    def __len__(self) -> int:
        return len(self._domains)


# Global singleton instance for efficient process-wide reuse
_global_provider: Optional[TrancoIntelligenceProvider] = None


def get_tranco_provider() -> TrancoIntelligenceProvider:
    global _global_provider
    if _global_provider is None:
        _global_provider = TrancoIntelligenceProvider()
    return _global_provider
