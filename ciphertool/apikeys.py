"""
API Key / Secret / Credential Pattern Tespiti.

Bilinen SaaS ve cloud servislerinin API anahtarlarini, tokenlarini
ve credential formatlarini regex tabanli olarak tanir.

Bu tespit NE OLDUGUNU soyler - keyi kullanmaz, validate etmez.
Security analysts, SOC, pentest ve CTF ortamlarinda veri siniflandirma icin kullanilir.
"""
import re
from dataclasses import dataclass
from typing import List


@dataclass
class ApiKeyMatch:
    service: str
    pattern_name: str
    confidence: float
    note: str
    severity: str
    masked: str


def _mask(s: str, show: int = 6) -> str:
    if len(s) <= show * 2:
        return s[:3] + "..." + s[-3:] if len(s) > 6 else "***"
    return s[:show] + "..." + s[-show:]


_PATTERNS = [
    # GitHub
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token (PAT)", "github_pat_ghp", 98, "ghp_ prefix + 36 alfanumerik", "HIGH"),
    (r"github_pat_[A-Za-z0-9_]{82}", "GitHub Personal Access Token (yeni format)", "github_pat_new", 98, "github_pat_ prefix - 2022+ format", "HIGH"),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub Actions Secret Token", "github_actions_ghs", 97, "ghs_ prefix", "HIGH"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", "github_oauth_gho", 97, "gho_ prefix", "HIGH"),
    (r"ghu_[A-Za-z0-9]{36}", "GitHub User-to-Server Token", "github_u2s_ghu", 97, "ghu_ prefix", "HIGH"),
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "aws_access_key", 99, "AKIA prefix + 16 buyuk alfanumerik - kesin AWS format", "HIGH"),
    (r"ABIA[0-9A-Z]{16}", "AWS STS Temporary Access Key", "aws_sts_abia", 95, "ABIA prefix", "HIGH"),
    (r"AROA[0-9A-Z]{16}", "AWS IAM Role ID", "aws_role_id", 90, "AROA prefix - IAM Role ID", "MEDIUM"),
    # Google
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", "google_api_key", 97, "AIza prefix + 35 karakter", "HIGH"),
    (r"ya29[.][0-9A-Za-z_-]{50,}", "Google OAuth2 Access Token", "google_oauth2", 95, "ya29. prefix", "HIGH"),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key (Live)", "stripe_secret_live", 99, "sk_live_ prefix - SON DERECE hassas", "HIGH"),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Secret Key (Test)", "stripe_secret_test", 97, "sk_test_ prefix", "MEDIUM"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Publishable Key (Live)", "stripe_pk_live", 95, "pk_live_ prefix", "LOW"),
    (r"pk_test_[0-9a-zA-Z]{24,}", "Stripe Publishable Key (Test)", "stripe_pk_test", 90, "pk_test_ prefix", "LOW"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key (Live)", "stripe_rk_live", 95, "rk_live_ prefix", "HIGH"),
    # Slack
    (r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+", "Slack Bot Token", "slack_bot_xoxb", 97, "xoxb- prefix", "HIGH"),
    (r"xoxp-[0-9A-Za-z-]+", "Slack User OAuth Token", "slack_user_xoxp", 92, "xoxp- prefix", "HIGH"),
    (r"xoxs-[0-9A-Za-z-]+", "Slack Socket Token", "slack_socket_xoxs", 88, "xoxs- prefix", "HIGH"),
    # SendGrid
    (r"SG[.][A-Za-z0-9._-]{22}[.][A-Za-z0-9._-]{43}", "SendGrid API Key", "sendgrid_api", 99, "SG. format - kesin", "HIGH"),
    # Twilio
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key SID", "twilio_api_sid", 90, "SK + 32 hex", "HIGH"),
    # Mailchimp
    (r"[0-9a-f]{32}-us[0-9]{1,2}", "Mailchimp API Key", "mailchimp_api", 97, "32 hex + -usN suffix", "HIGH"),
    # Firebase
    (r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "Firebase Cloud Messaging Key", "firebase_fcm", 97, "AAAA prefix + 140 char", "HIGH"),
    # OpenAI
    (r"sk-[A-Za-z0-9]{48}", "OpenAI API Key (legacy)", "openai_legacy", 90, "sk- prefix + 48 char", "HIGH"),
    (r"sk-proj-[A-Za-z0-9_-]{50,}", "OpenAI Project API Key", "openai_project", 95, "sk-proj- prefix", "HIGH"),
    # Anthropic
    (r"sk-ant-api[0-9]+-[A-Za-z0-9_-]{93}", "Anthropic API Key", "anthropic_api", 98, "sk-ant-api prefix", "HIGH"),
    # HuggingFace
    (r"hf_[A-Za-z0-9]{34}", "Hugging Face API Token", "huggingface_hf", 97, "hf_ prefix + 34 char", "HIGH"),
    # npm
    (r"npm_[A-Za-z0-9]{36}", "npm Access Token", "npm_token", 97, "npm_ prefix + 36 char", "HIGH"),
    # Docker Hub
    (r"dckr_pat_[A-Za-z0-9_-]{27}", "Docker Hub Personal Access Token", "dockerhub_pat", 97, "dckr_pat_ prefix", "HIGH"),
    # GitLab
    (r"glpat-[A-Za-z0-9_-]{20}", "GitLab Personal Access Token", "gitlab_pat", 97, "glpat- prefix", "HIGH"),
    (r"gldt-[A-Za-z0-9_-]{20}", "GitLab Deploy Token", "gitlab_deploy", 95, "gldt- prefix", "HIGH"),
    # Atlassian
    (r"ATATT3xFfGF0[A-Za-z0-9_=-]{100,}", "Atlassian API Token", "atlassian_api", 95, "ATATT3xFfGF0 prefix", "HIGH"),
    # HashiCorp Vault
    (r"hvs[.][A-Za-z0-9_-]{24,}", "HashiCorp Vault Service Token", "vault_hvs", 97, "hvs. prefix", "HIGH"),
    (r"hvb[.][A-Za-z0-9_-]{24,}", "HashiCorp Vault Batch Token", "vault_hvb", 95, "hvb. prefix", "HIGH"),
    # Shopify
    (r"shpss_[A-Za-z0-9]{32}", "Shopify Shared Secret", "shopify_secret", 97, "shpss_ prefix", "HIGH"),
    (r"shpat_[A-Za-z0-9]{32}", "Shopify Access Token", "shopify_access", 97, "shpat_ prefix", "HIGH"),
    # SSH
    (r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key", "ssh_openssh_private", 100, "OpenSSH yeni format private key", "HIGH"),
    (r"-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key (PKCS#1)", "ssh_rsa_private", 100, "RSA ozel anahtar", "HIGH"),
    (r"-----BEGIN EC PRIVATE KEY-----", "EC Private Key", "ssh_ec_private", 100, "EC ozel anahtar", "HIGH"),
    (r"ssh-rsa AAAA[A-Za-z0-9+/=]+", "SSH RSA Public Key", "ssh_rsa_public", 99, "ssh-rsa prefix", "MEDIUM"),
    (r"ssh-ed25519 AAAA[A-Za-z0-9+/=]+", "SSH Ed25519 Public Key", "ssh_ed25519_public", 99, "ssh-ed25519 prefix", "MEDIUM"),
    (r"ecdsa-sha2-nistp[0-9]+ AAAA[A-Za-z0-9+/=]+", "SSH ECDSA Public Key", "ssh_ecdsa_public", 99, "ecdsa-sha2- prefix", "MEDIUM"),
    # Generic
    (r"Bearer [A-Za-z0-9_.-]{30,}", "Bearer Token (genel)", "bearer_token", 75, "HTTP Authorization Bearer", "MEDIUM"),
    (r"Basic [A-Za-z0-9+/=]{20,}", "HTTP Basic Auth (Base64)", "http_basic_auth", 80, "HTTP Authorization Basic - Base64 credentials", "MEDIUM"),
    (r"eyJ[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+", "JWT (JSON Web Token)", "jwt_generic", 92, "eyJ prefix + 3 nokta-ayirli kisim", "MEDIUM"),
]

_COMPILED = [(re.compile(pat), svc, pname, conf, note, sev) for pat, svc, pname, conf, note, sev in _PATTERNS]


def detect_api_keys(text: str) -> List[ApiKeyMatch]:
    """Metinde bilinen API key/secret/credential formatlarini arar."""
    text = text.strip()
    if not text:
        return []
    results = []
    seen = set()
    for regex, service, pname, confidence, note, severity in _COMPILED:
        m = regex.search(text)
        if m and pname not in seen:
            matched = m.group(0)
            results.append(ApiKeyMatch(
                service=service, pattern_name=pname, confidence=confidence,
                note=note, severity=severity, masked=_mask(matched)
            ))
            seen.add(pname)
    _order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    results.sort(key=lambda x: (_order.get(x.severity, 3), -x.confidence))
    return results


def format_api_key_report(matches: List[ApiKeyMatch]) -> List[str]:
    """detect_api_keys() sonuclarini insan-okunabilir satir listesine cevirir."""
    if not matches:
        return []
    lines = []
    for m in matches:
        sev_icon = {"HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}.get(m.severity, "[?]")
        lines.append(f"{sev_icon} {m.service} (guven: {m.confidence:.0f}%) -- {m.note}")
    return lines
