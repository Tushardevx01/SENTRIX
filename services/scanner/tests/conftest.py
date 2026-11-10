import os
import pytest

# Ensure testing environment variables are present even in clean offline sandboxes
os.environ.setdefault("SCANNER_API_SECRET", "sentrix-test-scanner-secret-min16chars!")
os.environ.setdefault("PORT", "8001")
os.environ.setdefault("URLHAUS_ENABLED", "false")
