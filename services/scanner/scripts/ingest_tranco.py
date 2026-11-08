"""
Controlled ingestion utility for the Tranco Top-10K Domain Intelligence dataset.

Downloads or reads the official Tranco list, normalizes domains using IDNA and Public
Suffix List (PSL) extraction, rejects malformed entries/public suffixes, deduplicates,
computes a SHA-256 integrity checksum, and atomically writes the dataset.
"""

import os
import sys
import json
import zipfile
import io
import re
import argparse
import hashlib
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set, Dict, Any, Optional
import tldextract


DEFAULT_TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
DEFAULT_OUTPUT_PATH = Path(__file__).resolve().parents[1] / "app" / "data" / "tranco" / "tranco_top10k.json"
DOMAIN_SYNTAX_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def normalize_and_extract_registrable_domain(
    raw_domain: str,
    extractor: tldextract.TLDExtract
) -> Optional[str]:
    """
    Normalizes domain via IDNA and extracts exact registrable domain using PSL.
    Rejects IP literals, bare public suffixes, and malformed hostnames.
    """
    if not raw_domain or not isinstance(raw_domain, str):
        return None

    cleaned = raw_domain.strip().lower().rstrip(".")
    if not cleaned or len(cleaned) > 253:
        return None

    # Reject IP addresses
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cleaned) or ":" in cleaned:
        return None

    # IDNA encoding/decoding check
    try:
        idna_domain = cleaned.encode("idna").decode("ascii")
    except Exception:
        return None

    # Extract Public Suffix List parts
    ext = extractor(idna_domain)
    domain_part = ext.domain.lower() if ext.domain else ""
    suffix_part = ext.suffix.lower() if ext.suffix else ""

    # Reject bare public suffixes without a registrable domain (e.g. 'co.uk' or 'com')
    if not domain_part or not suffix_part:
        return None

    registered_domain = f"{domain_part}.{suffix_part}"

    # Syntax validation on the registrable domain
    if not DOMAIN_SYNTAX_REGEX.match(registered_domain):
        return None

    return registered_domain


def download_tranco_zip(url: str, timeout: int = 30) -> bytes:
    """Retrieves the Tranco top-1m zip archive from the official endpoint."""
    headers = {"User-Agent": "SENTRIX-Tranco-Ingest/1.0 (+https://github.com/Tushardevx01/SENTRIX)"}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Failed to download Tranco list. HTTP status: {resp.status}")
        return resp.read()


def parse_tranco_csv(csv_content: str, target_count: int = 10000) -> List[str]:
    """
    Parses Tranco CSV records ('rank,domain'), extracting and deduplicating
    valid registrable domains up to target_count.
    """
    extractor = tldextract.TLDExtract(cache_dir=None)
    seen_domains: Set[str] = set()
    result_domains: List[str] = []

    for line in csv_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(",", 1)
        if len(parts) == 2:
            raw_domain = parts[1].strip()
        else:
            raw_domain = parts[0].strip()

        reg_domain = normalize_and_extract_registrable_domain(raw_domain, extractor)
        if reg_domain and reg_domain not in seen_domains:
            seen_domains.add(reg_domain)
            result_domains.append(reg_domain)
            if len(result_domains) >= target_count:
                break

    return result_domains


def ingest_tranco(
    source_url: str = DEFAULT_TRANCO_URL,
    local_file: Optional[str] = None,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    target_count: int = 10000
) -> Dict[str, Any]:
    """
    Executes controlled Tranco ingestion with atomic file replacement and SHA-256 verification.
    """
    print(f"Starting Tranco ingestion (target: {target_count} registrable domains)...")

    if local_file and os.path.isfile(local_file):
        print(f"Reading from local file: {local_file}")
        with open(local_file, "rb") as f:
            raw_data = f.read()
    else:
        print(f"Downloading official archive from: {source_url}")
        raw_data = download_tranco_zip(source_url)

    # Decompress zip or parse raw csv
    if raw_data.startswith(b"PK\x03\x04"):
        with zipfile.ZipFile(io.BytesIO(raw_data)) as z:
            csv_filename = next((name for name in z.namelist() if name.endswith(".csv")), z.namelist()[0])
            with z.open(csv_filename) as f:
                csv_text = f.read().decode("utf-8", errors="replace")
    else:
        csv_text = raw_data.decode("utf-8", errors="replace")

    domains = parse_tranco_csv(csv_text, target_count=target_count)

    if len(domains) < target_count:
        raise ValueError(
            f"Insufficient valid domains extracted: got {len(domains)}, required {target_count}. Aborting."
        )

    # Sanity check: ensure fundamental high-reputation domains are present
    critical_canaries = [
        "google.com", "microsoft.com", "apple.com", "github.com",
        "cloudflare.com", "amazon.com", "okta.com", "jetbrains.com",
        "snowflake.com", "datadoghq.com", "login.gov", "coursera.org", "etsy.com"
    ]
    missing_canaries = [c for c in critical_canaries if c not in domains]
    if missing_canaries:
        raise ValueError(f"Ingestion sanity check failed: missing expected domains: {missing_canaries}")

    # Compute deterministic SHA-256 checksum over newline-joined domains
    domain_payload = "\n".join(domains).encode("utf-8")
    checksum = hashlib.sha256(domain_payload).hexdigest()

    dataset_payload: Dict[str, Any] = {
        "source": "Tranco Top Sites",
        "sourceUrl": source_url if not local_file else f"file://{local_file}",
        "retrievalTimestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
        "checksumSha256": checksum,
        "totalEntries": len(domains),
        "domains": domains,
    }

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Atomic file write using temporary file in same directory
    temp_file = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(output_path.parent),
        delete=False
    )
    try:
        json.dump(dataset_payload, temp_file, indent=2)
        temp_file.flush()
        os.fsync(temp_file.fileno())
        temp_file.close()

        # Atomic replacement
        os.replace(temp_file.name, str(output_path))
        print(f"Successfully wrote {len(domains)} validated domains to {output_path}")
        print(f"SHA-256 Checksum: {checksum}")
    except Exception as e:
        if os.path.exists(temp_file.name):
            os.remove(temp_file.name)
        raise RuntimeError(f"Atomic dataset replacement failed: {e}") from e

    return dataset_payload


def main():
    parser = argparse.ArgumentParser(description="Ingest and validate Tranco Top-10K domains.")
    parser.add_argument("--url", default=DEFAULT_TRANCO_URL, help="Tranco zip URL")
    parser.add_argument("--file", default=None, help="Local Tranco CSV or zip file")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH), help="Output JSON path")
    parser.add_argument("--count", type=int, default=10000, help="Number of registrable domains")
    args = parser.parse_args()

    try:
        ingest_tranco(
            source_url=args.url,
            local_file=args.file,
            output_path=Path(args.output),
            target_count=args.count
        )
    except Exception as e:
        print(f"ERROR: Tranco ingestion failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
