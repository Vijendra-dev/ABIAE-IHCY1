"""
Stage 1 — Official Domain Check.

Maintains a curated map of brand → set of official apex domains.
If the queried domain exactly matches an official domain, we short-circuit
the pipeline with a verified_official_domain risk reducer and LOW risk.

This is the primary guard that prevents the system from ever classifying
'paypal.com' as malicious simply because a brand was detected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Curated official domains registry
# Keyed by brand name (lowercase), values are lowercase apex domains.
# ---------------------------------------------------------------------------
OFFICIAL_DOMAINS: dict[str, set[str]] = {
    "paypal": {
        "paypal.com", "paypal.me", "paypal.co.uk", "paypal.de",
        "paypal.fr", "paypal.com.au", "paypalobjects.com",
    },
    "google": {
        "google.com", "google.co.uk", "google.de", "google.fr",
        "google.co.in", "google.com.au", "google.ca", "google.co.jp",
        "google.es", "google.it", "google.com.br", "google.ru",
        "gmail.com", "youtube.com", "googleusercontent.com",
        "googleapis.com", "gstatic.com", "googlevideo.com",
        "google.org", "withgoogle.com", "chrome.com",
    },
    "microsoft": {
        "microsoft.com", "office.com", "outlook.com", "live.com",
        "hotmail.com", "azure.com", "bing.com", "msn.com",
        "xbox.com", "github.com", "linkedin.com", "skype.com",
        "onenote.com", "sharepoint.com", "onedrive.com",
        "microsoftonline.com", "windows.com", "visualstudio.com",
        "azurewebsites.net", "msftauth.net",
    },
    "apple": {
        "apple.com", "icloud.com", "me.com", "mac.com",
        "apple.co", "appleid.apple.com", "itunes.com",
        "appstore.com", "mzstatic.com", "aaplimg.com",
    },
    "netflix": {
        "netflix.com", "nflxext.com", "nflximg.net",
        "nflxsearch.net", "nflxso.net", "netflix.net",
    },
    "amazon": {
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
        "amazon.co.jp", "amazon.in", "amazon.com.au", "amazon.ca",
        "amazon.es", "amazon.it", "amazon.com.br", "amzn.to",
        "amazonwebservices.com", "aws.amazon.com", "awsstatic.com",
        "amazonaws.com", "cloudfront.net",
    },
    "facebook": {
        "facebook.com", "fb.com", "meta.com", "instagram.com",
        "whatsapp.com", "messenger.com", "fbcdn.net",
        "cdninstagram.com", "threads.net",
    },
    "instagram": {
        "instagram.com", "cdninstagram.com",
    },
    "twitter": {
        "twitter.com", "x.com", "t.co", "twimg.com",
    },
    "chase": {
        "chase.com", "jpmorganchase.com", "jpmorgan.com",
    },
    "bankofamerica": {
        "bankofamerica.com", "bac.com",
    },
    "wellsfargo": {
        "wellsfargo.com",
    },
    "ebay": {
        "ebay.com", "ebay.co.uk", "ebay.de", "ebaystatic.com",
        "ebayimg.com",
    },
    "dropbox": {
        "dropbox.com", "dropboxstatic.com",
    },
    "adobe": {
        "adobe.com", "adobecc.com", "typekit.com", "adobeaemcloud.com",
    },
    "linkedin": {
        "linkedin.com", "licdn.com",
    },
    "github": {
        "github.com", "githubusercontent.com", "githubassets.com",
        "github.io",
    },
    "cloudflare": {
        "cloudflare.com", "cloudflareinsights.com", "cf-ipfs.com",
        "cdnjs.cloudflare.com",
    },
    "stripe": {
        "stripe.com", "stripecdn.com", "stripe.network",
    },
    "shopify": {
        "shopify.com", "myshopify.com", "shopifycdn.com",
    },
    "zoom": {
        "zoom.us", "zoom.com",
    },
    "salesforce": {
        "salesforce.com", "force.com", "salesforceliveagent.com",
    },
    "docusign": {
        "docusign.com", "docusign.net",
    },
}

# ---------------------------------------------------------------------------
# Known authorized partner / CDN suffix patterns per brand
# (substrings of apex domain — not full domain match required)
# ---------------------------------------------------------------------------
AUTHORIZED_PARTNER_SUFFIXES: dict[str, set[str]] = {
    "paypal": {"paypal-prepaid.com", "venmo.com", "braintreepayments.com", "zettle.com"},
    "google": {"googledrive.com", "google.maps", "waze.com"},
    "microsoft": {"microsoft365.com", "msecnd.net"},
    "apple": {"beats.com"},
    "amazon": {"aws.com"},
    "facebook": {"oculus.com", "workplace.com"},
}

# ---------------------------------------------------------------------------
# Known news / tech press domains (brand mentions, not impersonation)
# ---------------------------------------------------------------------------
NEWS_DOMAINS: set[str] = {
    "techcrunch.com", "theverge.com", "wired.com", "arstechnica.com",
    "engadget.com", "zdnet.com", "cnet.com", "bbc.com", "bbc.co.uk",
    "reuters.com", "bloomberg.com", "wsj.com", "nytimes.com",
    "forbes.com", "businessinsider.com", "cnbc.com", "ft.com",
    "guardian.com", "theguardian.com", "mashable.com", "gizmodo.com",
    "venturebeat.com", "pcmag.com", "tomsguide.com", "9to5mac.com",
    "macrumors.com", "androidpolice.com", "xda-developers.com",
    "stackoverflow.com", "reddit.com", "medium.com", "substack.com",
    "hackernews.com", "news.ycombinator.com", "wikipedia.org",
}


@dataclass
class OfficialCheckResult:
    domain: str                          # apex domain checked e.g. "paypal.com"
    brand: str                           # brand being checked against
    is_official: bool = False            # True → exact match in OFFICIAL_DOMAINS
    is_news_domain: bool = False         # True → known press/news site
    is_authorized_partner: bool = False  # True → suffix match in AUTHORIZED_PARTNER_SUFFIXES
    official_brand: Optional[str] = None # which brand owns this domain (may differ from queried brand)
    reducers: list[str] = field(default_factory=list)


def extract_apex(domain: str) -> str:
    """Returns 'example.co.uk' from 'sub.example.co.uk'."""
    import tldextract
    ext = tldextract.extract(domain)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return domain.lower()


def run(domain: str, brand: str) -> OfficialCheckResult:
    """
    Check whether *domain* is an official, news, or partner domain.

    Parameters
    ----------
    domain : str  The full domain string (may include subdomains), e.g. 'www.paypal.com'
    brand  : str  The brand name detected, e.g. 'paypal'

    Returns
    -------
    OfficialCheckResult
    """
    apex = extract_apex(domain)
    result = OfficialCheckResult(domain=apex, brand=brand.lower())

    # 1. Check all brands' official domains (not just the detected brand)
    for b, domains in OFFICIAL_DOMAINS.items():
        if apex in domains:
            result.is_official = True
            result.official_brand = b
            result.reducers.append("verified_official_domain")
            break

    # 2. Check news domains
    if apex in NEWS_DOMAINS:
        result.is_news_domain = True
        result.reducers.append("news_or_info_page")

    # 3. Check authorized partner suffixes for detected brand
    if brand.lower() in AUTHORIZED_PARTNER_SUFFIXES:
        for partner_suffix in AUTHORIZED_PARTNER_SUFFIXES[brand.lower()]:
            if apex == partner_suffix or apex.endswith(f".{partner_suffix}"):
                result.is_authorized_partner = True
                result.reducers.append("authorized_partner")
                break

    return result
