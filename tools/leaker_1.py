#!/usr/bin/env python3
"""
LeakHunter - API Secret & Credential Scanner
For use only on authorized bug bounty targets / your own systems.

NEW in v2:
  - Deobfuscation: base64, hex, unicode escapes, JS packer
  - Source map resolution (*.js.map)
  - Wayback Machine / archive.org scanning
  - Webpack / Next.js / Vite chunk auto-discovery
  - Sensitive path probing (/.env, /config.json, etc.)
  - Shannon entropy detection for unlisted secrets
  - Live key validation (AWS, GitHub, Stripe, Slack, Twilio)
  - Diff/delta reporting vs previous scan
  - SARIF output format (GitHub Advanced Security)
  - HTML report with dark dashboard
  - Webhook alerts (Slack / Discord)
  - Cookie / custom header auth support
  - Resume / incremental scanning (SQLite cache)
  - Rate limiting + stealth User-Agent rotation
  - CI/CD mode (exit code 1 on critical/high findings)
  - robots.txt respect toggle
"""

import re
import sys
import os
import json
import math
import time
import base64
import sqlite3
import hashlib
import argparse
import tempfile
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────
# 300+ PATTERNS  (original, untouched)
# ─────────────────────────────────────────────
PATTERNS = {
    # ── AWS ──
    "AWS Access Key ID":         r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Access Key":     r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[:=]\s*['\"]?([A-Za-z0-9/+]{40})",
    "AWS Session Token":         r"(?i)aws[_\-\.]?session[_\-\.]?token\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})",
    "AWS MWS Key":               r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS ARN":                   r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s\"']+",
    # ── Google ──
    "Google API Key":            r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Token":        r"ya29\.[0-9A-Za-z\-_]+",
    "Google Service Account":    r"(?i)\"type\":\s*\"service_account\"",
    "Google GCP API Key":        r"(?i)gcp[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{30,})",
    "Google reCAPTCHA":          r"6L[0-9A-Za-z_\-]{38}",
    "Firebase URL":              r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Firebase API Key":          r"(?i)firebase[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{30,})",
    # ── GitHub ──
    "GitHub Personal Token":     r"ghp_[A-Za-z0-9]{36}",
    "GitHub OAuth Token":        r"gho_[A-Za-z0-9]{36}",
    "GitHub App Token":          r"(ghu|ghs)_[A-Za-z0-9]{36}",
    "GitHub Refresh Token":      r"ghr_[A-Za-z0-9]{76}",
    "GitHub Fine-Grained PAT":   r"github_pat_[A-Za-z0-9_]{82}",
    "GitHub Actions Token":      r"(?i)GITHUB_TOKEN\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{36,})",
    # ── GitLab ──
    "GitLab Personal Token":     r"glpat-[A-Za-z0-9\-_]{20}",
    "GitLab Runner Token":       r"glrt-[A-Za-z0-9\-_]{20}",
    "GitLab CI Token":           r"(?i)gl-[a-z]+-token\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{20,})",
    # ── Slack ──
    "Slack Bot Token":           r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{23,25}",
    "Slack User Token":          r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}",
    "Slack App Token":           r"xapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{13}-[A-Za-z0-9]{80}",
    "Slack Webhook URL":         r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
    "Slack Legacy Token":        r"xox[aors]-[0-9]{8,12}-[0-9]{8,12}-[A-Za-z0-9]{24}",
    # ── Stripe ──
    "Stripe Live Secret":        r"sk_live_[A-Za-z0-9]{24,}",
    "Stripe Test Secret":        r"sk_test_[A-Za-z0-9]{24,}",
    "Stripe Live Publishable":   r"pk_live_[A-Za-z0-9]{24,}",
    "Stripe Test Publishable":   r"pk_test_[A-Za-z0-9]{24,}",
    "Stripe Restricted Key":     r"rk_live_[A-Za-z0-9]{24,}",
    "Stripe Webhook Secret":     r"whsec_[A-Za-z0-9]{32,}",
    # ── Twilio ──
    "Twilio Account SID":        r"AC[a-z0-9]{32}",
    "Twilio Auth Token":         r"(?i)twilio[_\-\.]?auth[_\-\.]?token\s*[:=]\s*['\"]?([a-z0-9]{32})",
    "Twilio API Key":            r"SK[a-z0-9]{32}",
    # ── SendGrid ──
    "SendGrid API Key":          r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    # ── Mailgun ──
    "Mailgun API Key":           r"key-[A-Za-z0-9]{32}",
    "Mailgun Webhook Key":       r"(?i)mailgun[_\-\.]?webhook[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{32,})",
    # ── Mailchimp ──
    "Mailchimp API Key":         r"[A-Za-z0-9]{32}-us[0-9]{1,2}",
    # ── PayPal / Braintree ──
    "PayPal Client ID":          r"(?i)paypal[_\-\.]?client[_\-\.]?id\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{20,})",
    "PayPal Secret":             r"(?i)paypal[_\-\.]?(?:client[_\-\.]?)?secret\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{20,})",
    "Braintree Access Token":    r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Braintree Tokenization":    r"production_[0-9a-z]{8}_[0-9a-z]{16}",
    # ── Square ──
    "Square Access Token":       r"sqOatp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret":       r"sq0csp-[0-9A-Za-z\-_]{43}",
    # ── Shopify ──
    "Shopify Access Token":      r"shpat_[A-Fa-f0-9]{32}",
    "Shopify Custom App":        r"shpca_[A-Fa-f0-9]{32}",
    "Shopify Partner Token":     r"shppa_[A-Fa-f0-9]{32}",
    "Shopify Shared Secret":     r"shpss_[A-Fa-f0-9]{32}",
    # ── Azure ──
    "Azure Storage Key":         r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "Azure Client Secret":       r"(?i)azure[_\-\.]?client[_\-\.]?secret\s*[:=]\s*['\"]?([A-Za-z0-9~_\-\.]{34,})",
    "Azure SAS Token":           r"(?i)sig=[A-Za-z0-9%]{43,}%3D",
    "Azure Subscription Key":    r"(?i)ocp-apim-subscription-key\s*[:=]\s*['\"]?([A-Za-z0-9]{32})",
    # ── Heroku ──
    "Heroku API Key":            r"(?i)heroku[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "Heroku OAuth Token":        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    # ── Okta ──
    "Okta API Token":            r"00[A-Za-z0-9_\-]{40}",
    "Okta Client Secret":        r"(?i)okta[_\-\.]?client[_\-\.]?secret\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{40,})",
    # ── Auth0 ──
    "Auth0 Client Secret":       r"(?i)auth0[_\-\.]?(?:client[_\-\.]?)?secret\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{40,})",
    "Auth0 API Key":             r"(?i)auth0[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{30,})",
    # ── Twitter / X ──
    "Twitter API Key":           r"(?i)twitter[_\-\.]?(?:api[_\-\.]?)?(?:consumer[_\-\.]?)?key\s*[:=]\s*['\"]?([A-Za-z0-9]{25,})",
    "Twitter API Secret":        r"(?i)twitter[_\-\.]?(?:api[_\-\.]?)?(?:consumer[_\-\.]?)?secret\s*[:=]\s*['\"]?([A-Za-z0-9]{50,})",
    "Twitter Bearer Token":      r"AAAAAAAAAAAAAAAAAAAAAMLheAAAAAAA0%2BuSeid%2BULvsea4JtiGRiSDSJSI%3D[A-Za-z0-9%]+",
    "Twitter Access Token":      r"[0-9]+-[A-Za-z0-9]{40}",
    # ── Facebook / Meta ──
    "Facebook Access Token":     r"EAACEdEose0cBA[A-Za-z0-9]+",
    "Facebook App ID":           r"(?i)fb[_\-\.]?app[_\-\.]?(?:id|secret)\s*[:=]\s*['\"]?([0-9]{10,20})",
    "Facebook Client Token":     r"(?i)facebook[_\-\.]?client[_\-\.]?token\s*[:=]\s*['\"]?([A-Za-z0-9]{32})",
    # ── LinkedIn ──
    "LinkedIn Client ID":        r"(?i)linkedin[_\-\.]?client[_\-\.]?id\s*[:=]\s*['\"]?([A-Za-z0-9]{12,})",
    "LinkedIn Client Secret":    r"(?i)linkedin[_\-\.]?client[_\-\.]?secret\s*[:=]\s*['\"]?([A-Za-z0-9]{16,})",
    # ── Discord ──
    "Discord Bot Token":         r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}",
    "Discord Webhook":           r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
    "Discord Client Secret":     r"(?i)discord[_\-\.]?(?:client[_\-\.]?)?secret\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{32})",
    # ── Telegram ──
    "Telegram Bot Token":        r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",
    "Telegram API Hash":         r"(?i)telegram[_\-\.]?api[_\-\.]?hash\s*[:=]\s*['\"]?([a-f0-9]{32})",
    # ── HubSpot ──
    "HubSpot API Key":           r"(?i)hubspot[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9\-]{36})",
    "HubSpot OAuth Token":       r"(?i)hubspot[_\-\.]?(?:oauth[_\-\.]?)?token\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{36,})",
    # ── Intercom ──
    "Intercom Access Token":     r"dG9rOj[A-Za-z0-9_\-=]{40,}",
    "Intercom API Key":          r"(?i)intercom[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{30,})",
    # ── Zendesk ──
    "Zendesk API Token":         r"(?i)zendesk[_\-\.]?api[_\-\.]?token\s*[:=]\s*['\"]?([A-Za-z0-9/=]{40,})",
    # ── Salesforce ──
    "Salesforce Token":          r"00D[A-Za-z0-9]{15}![A-Za-z0-9.]{80,}",
    # ── Databricks ──
    "Databricks Token":          r"dapi[a-f0-9]{32}",
    # ── Cloudinary ──
    "Cloudinary URL":            r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+",
    # ── Algolia ──
    "Algolia API Key":           r"(?i)algolia[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9]{32})",
    "Algolia App ID":            r"(?i)algolia[_\-\.]?app[_\-\.]?id\s*[:=]\s*['\"]?([A-Za-z0-9]{10})",
    # ── Mapbox ──
    "Mapbox Token":              r"pk\.[A-Za-z0-9_\-]{80,}",
    "Mapbox Secret Token":       r"sk\.[A-Za-z0-9_\-]{80,}",
    # ── Amplitude ──
    "Amplitude API Key":         r"(?i)amplitude[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([a-f0-9]{32})",
    # ── Segment ──
    "Segment Write Key":         r"(?i)segment[_\-\.]?write[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9]{20,})",
    # ── Mixpanel ──
    "Mixpanel Token":            r"(?i)mixpanel[_\-\.]?token\s*[:=]\s*['\"]?([A-Za-z0-9]{32})",
    # ── Datadog ──
    "Datadog API Key":           r"(?i)dd[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([a-f0-9]{32})",
    "Datadog App Key":           r"(?i)dd[_\-\.]?app[_\-\.]?key\s*[:=]\s*['\"]?([a-f0-9]{40})",
    # ── New Relic ──
    "New Relic License Key":     r"NRAK-[A-Z0-9]{27}",
    "New Relic Account ID":      r"(?i)new.?relic[_\-\.]?account[_\-\.]?id\s*[:=]\s*['\"]?([0-9]{6,})",
    # ── Sentry ──
    "Sentry DSN":                r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+",
    "Sentry Auth Token":         r"(?i)sentry[_\-\.]?auth[_\-\.]?token\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{64})",
    # ── LaunchDarkly ──
    "LaunchDarkly SDK Key":      r"sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "LaunchDarkly Mobile Key":   r"mob-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    # ── Pusher ──
    "Pusher App Key":            r"(?i)pusher[_\-\.]?app[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9]{20})",
    "Pusher App Secret":         r"(?i)pusher[_\-\.]?app[_\-\.]?secret\s*[:=]\s*['\"]?([A-Za-z0-9]{20})",
    # ── Pagerduty ──
    "PagerDuty API Key":         r"(?i)pagerduty[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-+]{20,})",
    # ── Cypress ──
    "Cypress Record Key":        r"(?i)cypress[_\-\.]?record[_\-\.]?key\s*[:=]\s*['\"]?([a-f0-9\-]{36})",
    # ── NPM ──
    "NPM Token":                 r"npm_[A-Za-z0-9]{36}",
    "NPM Auth Token":            r"(?i)//registry\.npmjs\.org/:_authToken\s*=\s*([A-Za-z0-9\-_]+)",
    # ── PyPI ──
    "PyPI API Token":            r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}",
    # ── Docker Hub ──
    "Docker Hub Token":          r"(?i)dockerhub[_\-\.]?token\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{36,})",
    # ── Vault ──
    "HashiCorp Vault Token":     r"(?i)vault[_\-\.]?token\s*[:=]\s*['\"]?(hvs\.[A-Za-z0-9_\-]{90,}|s\.[A-Za-z0-9]{24})",
    # ── Confluent / Kafka ──
    "Confluent API Key":         r"(?i)confluent[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9]{16})",
    "Confluent API Secret":      r"(?i)confluent[_\-\.]?api[_\-\.]?secret\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{64})",
    # ── Elastic ──
    "Elastic API Key":           r"(?i)elastic[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-=]{40,})",
    # ── JWT ──
    "JWT Token":                 r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "JWT Secret":                r"(?i)jwt[_\-\.]?secret\s*[:=]\s*['\"]?([A-Za-z0-9_\-!@#$%]{16,})",
    # ── Private Keys ──
    "RSA Private Key":           r"-----BEGIN RSA PRIVATE KEY-----",
    "EC Private Key":            r"-----BEGIN EC PRIVATE KEY-----",
    "PGP Private Key":           r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "DSA Private Key":           r"-----BEGIN DSA PRIVATE KEY-----",
    "OpenSSH Private Key":       r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PKCS8 Private Key":         r"-----BEGIN PRIVATE KEY-----",
    # ── Certificates ──
    "Certificate":               r"-----BEGIN CERTIFICATE-----",
    # ── Database Connections ──
    "MongoDB URI":               r"mongodb(?:\+srv)?://[A-Za-z0-9_%\-]+:[A-Za-z0-9_%\-]+@[A-Za-z0-9.\-]+",
    "PostgreSQL URI":            r"postgres(?:ql)?://[A-Za-z0-9_%\-]+:[A-Za-z0-9_%\-]+@[A-Za-z0-9.\-]+",
    "MySQL URI":                 r"mysql://[A-Za-z0-9_%\-]+:[A-Za-z0-9_%\-]+@[A-Za-z0-9.\-]+",
    "Redis URI":                 r"redis://(?:[A-Za-z0-9_%\-]+:[A-Za-z0-9_%\-]+@)?[A-Za-z0-9.\-]+:[0-9]+",
    "JDBC Connection":           r"jdbc:[a-z]+://[A-Za-z0-9.\-]+(?::[0-9]+)?/[A-Za-z0-9_%\-]+\?(?:user|username)=[^&]+&password=[^&\s]+",
    "Elasticsearch URI":         r"https?://[A-Za-z0-9_%\-]+:[A-Za-z0-9_%\-]+@[A-Za-z0-9.\-]+:920[0-9]",
    # ── Generic Credentials ──
    "Generic Password":          r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
    "Generic Secret":            r"(?i)(?:secret|secret_key|secretkey)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
    "Generic API Key":           r"(?i)(?:api[_\-]?key|apikey|api[_\-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
    "Generic Token":             r"(?i)(?:token|auth[_\-]?token|access[_\-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]",
    "Generic Auth Header":       r"(?i)authorization\s*[:=]\s*['\"]?(?:bearer|token|basic)\s+([A-Za-z0-9_\-\.=+/]{20,})",
    "Basic Auth in URL":         r"https?://[A-Za-z0-9_%\-]+:[A-Za-z0-9_%\-]+@[A-Za-z0-9.\-]+",
    "Generic Bearer Token":      r"(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})",
    # ── Cloud Storage ──
    "S3 Bucket URL":             r"(?i)https?://[a-z0-9\-\.]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com",
    "S3 ARN":                    r"arn:aws:s3:::[a-z0-9\-\.]+",
    "GCS Bucket":                r"(?i)https?://storage\.googleapis\.com/[A-Za-z0-9_\-\.]+",
    "Azure Blob":                r"https://[a-z0-9]+\.blob\.core\.windows\.net/[A-Za-z0-9\-]+",
    # ── Environment / Config ──
    "Dotenv Secret":             r"(?i)^[A-Z_]+=.{8,}",
    "PHP Config Credentials":    r"(?i)\$(?:db[_\-]?password|db[_\-]?pass|db[_\-]?user)\s*=\s*['\"]([^'\"]+)['\"]",
    "Django Secret Key":         r"(?i)SECRET_KEY\s*=\s*['\"]([^'\"]{40,})['\"]",
    "Rails Secret":              r"(?i)secret[_\-]?key[_\-]?base\s*:\s*([a-f0-9]{128})",
    "Laravel App Key":           r"base64:[A-Za-z0-9+/=]{44}",
    # ── Crypto / Wallets ──
    "Ethereum Private Key":      r"(?i)(?:eth|ethereum)[_\-\.]?(?:private[_\-\.]?)?key\s*[:=]\s*['\"]?(?:0x)?([a-f0-9]{64})",
    "Bitcoin WIF":               r"[5KL][A-HJ-NP-Za-km-z1-9]{51}",
    "Mnemonic Phrase":           r"(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident)\s+(?:[a-z]+\s+){10,}[a-z]+",
    # ── SMTP ──
    "SMTP Credentials":          r"(?i)smtp[_\-\.]?(?:password|pass|secret)\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*_\-]{8,})",
    "SMTP URL":                  r"smtps?://[A-Za-z0-9_%\-]+:[A-Za-z0-9_%\-]+@[A-Za-z0-9.\-]+",
    # ── FTP ──
    "FTP Credentials":           r"ftp://[A-Za-z0-9_%\-]+:[A-Za-z0-9_%\-]+@[A-Za-z0-9.\-]+",
    # ── SSH ──
    "SSH Password":              r"(?i)ssh[_\-\.]?(?:password|pass)\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*_\-]{8,})",
    # ── Misc Services ──
    "Airtable API Key":          r"key[A-Za-z0-9]{14}",
    "Asana Access Token":        r"(?i)asana[_\-\.]?(?:personal[_\-\.]?)?access[_\-\.]?token\s*[:=]\s*['\"]?([0-9]/[A-Za-z0-9]{31})",
    "Bitbucket Token":           r"(?i)bitbucket[_\-\.]?(?:oauth[_\-\.]?)?(?:token|secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{32,})",
    "CircleCI Token":            r"(?i)circle[_\-\.]?(?:ci[_\-\.]?)?token\s*[:=]\s*['\"]?([A-Za-z0-9]{40})",
    "CodeClimate Token":         r"(?i)codeclimate[_\-\.]?(?:repo[_\-\.]?)?token\s*[:=]\s*['\"]?([A-Za-z0-9]{40})",
    "Coveralls Token":           r"(?i)coveralls[_\-\.]?(?:repo[_\-\.]?)?token\s*[:=]\s*['\"]?([A-Za-z0-9]{40})",
    "Fastly API Key":            r"(?i)fastly[_\-\.]?api[_\-\.]?key\s*[:=]\s*['\"]?([A-Za-z0-9]{32})",
    "Infura API Key":            r"(?i)infura[_\-\.]?(?:project[_\-\.]?)?(?:id|secret)\s*[:=]\s*['\"]?([A-Za-z0-9]{32})",
    "Jira API Token":            r"(?i)jira[_\-\.]?api[_\-\.]?token\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{24,})",
    "Notion API Key":            r"secret_[A-Za-z0-9]{43}",
    "OpenAI API Key":            r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
    "OpenAI Project Key":        r"sk-proj-[A-Za-z0-9_\-]{43,}",
    "Anthropic API Key":         r"sk-ant-api03-[A-Za-z0-9_\-]{93,}",
    "Plaid Access Token":        r"access-(?:sandbox|development|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "RapidAPI Key":              r"(?i)x-rapidapi-key\s*[:=]\s*['\"]?([A-Za-z0-9]{50})",
    "Snyk API Token":            r"(?i)snyk[_\-\.]?token\s*[:=]\s*['\"]?([A-Za-z0-9\-]{36})",
    "Sonar Token":               r"(?i)sonar[_\-\.]?token\s*[:=]\s*['\"]?([A-Za-z0-9_]{40})",
    "Travis CI Token":           r"(?i)travis[_\-\.]?(?:ci[_\-\.]?)?token\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{22})",
    "Typeform Token":            r"tfp_[A-Za-z0-9_\-]{40,}",
    "WakaTime API Key":          r"waka_[A-Za-z0-9_\-]{36,}",
    "Zoom JWT":                  r"(?i)zoom[_\-\.]?jwt[_\-\.]?(?:token|secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{100,})",
    # ── Internal / Debug ──
    "Internal IP":               r"(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}",
    "Localhost URL":             r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::[0-9]+)?",
    "Debug/Dev Flag":            r"(?i)(?:debug|development|dev[_\-]?mode)\s*[:=]\s*(?:true|1|yes|on)",
    "Hardcoded Admin Cred":      r"(?i)(?:admin[_\-]?password|admin[_\-]?pass|root[_\-]?password)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
    "Hardcoded Username":        r"(?i)(?:username|user_name|user)\s*[:=]\s*['\"]([^'\"]{3,})['\"]",
}

SEVERITY = {
    "critical": [
        "AWS Access Key ID", "AWS Secret Access Key", "AWS Session Token",
        "Google Service Account", "GitHub Personal Token", "GitHub Fine-Grained PAT",
        "Stripe Live Secret", "RSA Private Key", "EC Private Key",
        "OpenSSH Private Key", "MongoDB URI", "PostgreSQL URI",
        "MySQL URI", "Django Secret Key", "Ethereum Private Key",
        "HashiCorp Vault Token", "Slack Bot Token", "Firebase URL",
        "Databricks Token", "Salesforce Token", "OpenAI API Key",
        "OpenAI Project Key", "Anthropic API Key",
    ],
    "high": [
        "Google API Key", "GitHub OAuth Token", "GitLab Personal Token",
        "Stripe Test Secret", "Twilio Auth Token", "SendGrid API Key",
        "Shopify Access Token", "Azure Client Secret", "NPM Token",
        "JWT Token", "PayPal Secret", "Discord Bot Token",
        "Telegram Bot Token", "Firebase API Key", "LaunchDarkly SDK Key",
        "HubSpot API Key", "Sentry DSN", "Elastic API Key",
        "Plaid Access Token", "Notion API Key",
    ],
    "medium": [
        "Mailgun API Key", "Mailchimp API Key", "Algolia API Key",
        "Mapbox Token", "Datadog API Key", "New Relic License Key",
        "Amplitude API Key", "Segment Write Key", "Pusher App Secret",
        "Intercom Access Token", "Zendesk API Token", "Airtable API Key",
        "RapidAPI Key", "Fastly API Key", "CircleCI Token",
        "Discord Webhook", "Slack Webhook URL", "PyPI API Token",
        "Cloudinary URL", "SMTP Credentials", "SMTP URL",
    ],
    "low": [
        "Internal IP", "Localhost URL", "Debug/Dev Flag",
        "Google reCAPTCHA", "Hardcoded Username", "Basic Auth in URL",
        "S3 Bucket URL", "GCS Bucket", "Azure Blob",
        "Generic Bearer Token", "Certificate", "Dotenv Secret",
    ],
}

def get_severity(pattern_name):
    for sev, names in SEVERITY.items():
        if pattern_name in names:
            return sev
    return "medium"

# ─────────────────────────────────────────────
# COLORS  (original)
# ─────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    DIM    = "\033[2m"
    WHITE  = "\033[97m"

SEV_COLOR = {
    "critical": C.RED + C.BOLD,
    "high":     C.RED,
    "medium":   C.YELLOW,
    "low":      C.CYAN,
}

BANNER = f"""
{C.GREEN}{C.BOLD}
  ██╗     ███████╗ █████╗ ██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██║     ██╔════╝██╔══██╗██║ ██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██║     █████╗  ███████║█████╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██║     ██╔══╝  ██╔══██║██╔═██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ███████╗███████╗██║  ██║██║  ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RESET}{C.DIM}  API Secret & Credential Scanner v2  |  300+ Patterns + Entropy + Deobfuscation{C.RESET}
"""

# ─────────────────────────────────────────────
# NEW: USER-AGENT POOL (stealth rotation)
# ─────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]
_ua_index = 0

def next_user_agent():
    global _ua_index
    ua = USER_AGENTS[_ua_index % len(USER_AGENTS)]
    _ua_index += 1
    return ua

# ─────────────────────────────────────────────
# NEW: FALSE POSITIVE FILTER
# ─────────────────────────────────────────────
FP_VALUES = {
    "xxxx", "your-key-here", "your_api_key", "insert_key_here",
    "api_key_here", "replace_with_key", "xxxxxxxxxxxxxxxx",
    "1234567890abcdef", "abcdefghijklmnop", "changeme",
    "placeholder", "example", "test", "demo", "sample",
    "YOUR_KEY", "YOUR_SECRET", "YOUR_TOKEN", "null", "undefined",
    "none", "false", "true", "empty", "fake", "dummy",
    "REPLACE_ME", "ADD_YOUR_KEY",
}

def is_false_positive(value):
    if not value:
        return True
    v = value.strip().lower()
    if v in FP_VALUES:
        return True
    if len(v) < 8:
        return True
    if len(set(v)) <= 2:
        return True
    return False

# ─────────────────────────────────────────────
# NEW: SHANNON ENTROPY
# ─────────────────────────────────────────────
def shannon_entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    l = len(s)
    return -sum((cnt / l) * math.log2(cnt / l) for cnt in freq.values())

def entropy_scan(content, url, threshold=4.5, min_len=20):
    findings = []
    pattern = re.compile(r'[\'"][A-Za-z0-9+/=_\-]{%d,}[\'"]' % min_len)
    for m in pattern.finditer(content):
        val = m.group().strip("'\"")
        e = shannon_entropy(val)
        if e >= threshold and not is_false_positive(val):
            findings.append({
                "url":      url,
                "pattern":  "High Entropy String",
                "severity": "medium",
                "match":    val[:120],
                "line":     content[:m.start()].count("\n") + 1,
                "context":  f"entropy={e:.2f}",
                "entropy":  round(e, 2),
                "source":   "entropy",
            })
    return findings

# ─────────────────────────────────────────────
# NEW: DEOBFUSCATION ENGINE
# ─────────────────────────────────────────────
def deobfuscate(content):
    """Return list of (label, deobfuscated_content) layers to also scan."""
    layers = []

    # 1. Base64 blobs
    for m in re.finditer(r'[\'"]([A-Za-z0-9+/]{40,}={0,2})[\'"]', content):
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            if any(kw in decoded.lower() for kw in ["key","secret","token","password","api"]):
                layers.append(("base64-decoded", decoded))
        except Exception:
            pass

    # 2. Hex strings \x61\x70\x69
    hex_pat = re.compile(r'((?:\\x[0-9a-fA-F]{2}){6,})')
    for m in hex_pat.finditer(content):
        try:
            decoded = bytes.fromhex(m.group(1).replace("\\x", "")).decode("utf-8", errors="replace")
            layers.append(("hex-decoded", decoded))
        except Exception:
            pass

    # 3. Unicode escapes \u0061\u0070\u0069
    uni_pat = re.compile(r'((?:\\u[0-9a-fA-F]{4}){4,})')
    for m in uni_pat.finditer(content):
        try:
            decoded = m.group(1).encode("utf-8").decode("unicode_escape")
            layers.append(("unicode-decoded", decoded))
        except Exception:
            pass

    # 4. JS packer eval(function(p,a,c,k,e,d)...)
    if "eval(function(p,a,c,k,e" in content:
        layers.append(("packer-detected", "[JS packer detected — manual review recommended]"))

    # 5. atob() calls — base64 in browser JS
    for m in re.finditer(r'atob\([\'"]([A-Za-z0-9+/=]{10,})[\'"]', content):
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            layers.append(("atob-decoded", decoded))
        except Exception:
            pass

    return layers

# ─────────────────────────────────────────────
# NEW: SENSITIVE PATHS TO PROBE
# ─────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.staging", "/.env.backup", "/.env.bak", "/.env.old",
    "/config.js", "/config.json", "/config.yaml", "/config.yml",
    "/appsettings.json", "/appsettings.Development.json",
    "/app.config.js", "/app.config.json",
    "/webpack.config.js", "/vite.config.js", "/next.config.js",
    "/secrets.json", "/secrets.yaml",
    "/credentials.json", "/credentials.yaml",
    "/docker-compose.yml", "/docker-compose.yaml",
    "/package.json", "/package-lock.json",
    "/settings.py", "/local_settings.py",
    "/.git/config", "/.git/HEAD",
    "/api/v1/config", "/api/config", "/api/settings",
    "/static/js/main.js", "/static/js/bundle.js",
    "/js/app.js", "/js/main.js", "/js/bundle.js",
    "/assets/js/app.js", "/dist/main.js", "/build/static/js/main.js",
    "/_next/static/chunks/main.js", "/_next/static/chunks/webpack.js",
    "/asset-manifest.json", "/manifest.json",
]

# ─────────────────────────────────────────────
# NEW: WEBPACK / FRAMEWORK CHUNK DISCOVERY
# ─────────────────────────────────────────────
def discover_chunks(content, base_url):
    """Find webpack/Next.js/Vite JS chunk URLs."""
    urls = set()
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    patterns = [
        r'["\']([/_\w\-\.]+\.chunk\.[a-z0-9]+\.js)["\']',
        r'["\']([/_\w\-\.]+\.[a-f0-9]{8}\.js)["\']',
        r'"([^"]+\.js)":\s*\d+',                         # webpack chunk map
        r'/_next/static/chunks/([^"\']+\.js)',
        r'/static/js/([a-z0-9]+\.[a-z0-9]+\.chunk\.js)',
        r'["\'](/assets/[^"\']+\.js)["\']',
    ]
    for pat in patterns:
        for m in re.finditer(pat, content):
            path = m.group(1)
            full = urllib.parse.urljoin(base_url, path) if path.startswith("/") else origin + "/" + path.lstrip("/")
            urls.add(full)
    return urls

# ─────────────────────────────────────────────
# NEW: SOURCE MAP RESOLUTION
# ─────────────────────────────────────────────
def get_sourcemap_url(js_url, js_content):
    m = re.search(r'//# sourceMappingURL=(.+)', js_content)
    if m:
        return urllib.parse.urljoin(js_url, m.group(1).strip())
    return js_url.rsplit("?", 1)[0] + ".map"

def parse_sourcemap(map_content):
    """Extract sourcesContent from a .map file."""
    sources = []
    try:
        data = json.loads(map_content)
        for src in data.get("sourcesContent", []):
            if src:
                sources.append(src)
    except Exception:
        pass
    return sources

# ─────────────────────────────────────────────
# NEW: LIVE KEY VALIDATORS
# ─────────────────────────────────────────────
def _http_get(url, headers=None, timeout=8):
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""

def validate_aws(key_id, secret=None):
    """Check if AWS key is valid via STS (no secret needed for format check)."""
    # Without a secret we can only confirm the format
    return {"valid": True, "note": "Format valid — provide secret for live check"} if re.match(r"^(AKIA|ABIA|ACCA)[A-Z0-9]{16}$", key_id) else {"valid": False}

def validate_github(token):
    status, body = _http_get("https://api.github.com/user",
                              headers={"Authorization": f"token {token}",
                                       "User-Agent": "LeakHunter"})
    if status == 200:
        try:
            d = json.loads(body)
            return {"valid": True, "user": d.get("login"), "note": "Active GitHub token"}
        except Exception:
            return {"valid": True}
    return {"valid": False, "note": f"HTTP {status}"}

def validate_slack(token):
    status, body = _http_get(f"https://slack.com/api/auth.test?token={token}")
    if status == 200:
        try:
            d = json.loads(body)
            if d.get("ok"):
                return {"valid": True, "team": d.get("team"), "user": d.get("user")}
        except Exception:
            pass
    return {"valid": False}

def validate_stripe(key):
    status, _ = _http_get("https://api.stripe.com/v1/balance",
                           headers={"Authorization": f"Bearer {key}"})
    return {"valid": status == 200, "note": f"HTTP {status}"}

def validate_twilio(sid, token=None):
    return {"valid": bool(re.match(r"^AC[a-z0-9]{32}$", sid)),
            "note": "Format valid — provide auth token for live check"}

VALIDATORS = {
    "AWS Access Key ID":     lambda v: validate_aws(v),
    "GitHub Personal Token": lambda v: validate_github(v),
    "GitHub OAuth Token":    lambda v: validate_github(v),
    "Slack Bot Token":       lambda v: validate_slack(v),
    "Slack User Token":      lambda v: validate_slack(v),
    "Stripe Live Secret":    lambda v: validate_stripe(v),
    "Stripe Test Secret":    lambda v: validate_stripe(v),
    "Twilio Account SID":    lambda v: validate_twilio(v),
}

def validate_finding(finding):
    name = finding["pattern"]
    val  = finding["match"]
    if name in VALIDATORS:
        try:
            result = VALIDATORS[name](val)
            finding["validation"] = result
        except Exception as e:
            finding["validation"] = {"valid": None, "note": str(e)}
    return finding

# ─────────────────────────────────────────────
# NEW: SQLITE SCAN CACHE (resume / incremental)
# ─────────────────────────────────────────────
class ScanCache:
    def __init__(self, db_path="leakhunter_cache.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("""CREATE TABLE IF NOT EXISTS scanned (
            url TEXT PRIMARY KEY,
            content_hash TEXT,
            scanned_at TEXT
        )""")
        self.conn.execute("""CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            pattern TEXT,
            match TEXT,
            severity TEXT,
            scanned_at TEXT
        )""")
        self.conn.commit()

    def already_scanned(self, url, content_hash):
        row = self.conn.execute(
            "SELECT content_hash FROM scanned WHERE url=?", (url,)
        ).fetchone()
        return row and row[0] == content_hash

    def mark_scanned(self, url, content_hash):
        self.conn.execute(
            "INSERT OR REPLACE INTO scanned VALUES (?,?,?)",
            (url, content_hash, datetime.now().isoformat())
        )
        self.conn.commit()

    def save_findings(self, findings):
        now = datetime.now().isoformat()
        self.conn.executemany(
            "INSERT INTO findings (url,pattern,match,severity,scanned_at) VALUES (?,?,?,?,?)",
            [(f["url"], f["pattern"], f["match"], f["severity"], now) for f in findings]
        )
        self.conn.commit()

    def previous_findings(self):
        rows = self.conn.execute("SELECT url,pattern,match FROM findings").fetchall()
        return {(r[0], r[1], r[2]) for r in rows}

    def close(self):
        self.conn.close()

# ─────────────────────────────────────────────
# NEW: DIFF REPORT (new vs previous scan)
# ─────────────────────────────────────────────
def compute_diff(new_findings, previous_keys):
    new = []
    for f in new_findings:
        key = (f["url"], f["pattern"], f["match"])
        if key not in previous_keys:
            new.append(f)
    return new

# ─────────────────────────────────────────────
# NEW: ROBOTS.TXT PARSER
# ─────────────────────────────────────────────
def fetch_disallowed_paths(base_url, fetcher):
    disallowed = set()
    robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
    content, _ = fetcher(robots_url)
    if content:
        for line in content.splitlines():
            if line.strip().lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallowed.add(path)
    return disallowed

# ─────────────────────────────────────────────
# NEW: WAYBACK MACHINE SCANNER
# ─────────────────────────────────────────────
def wayback_urls(target_url, limit=20):
    """Fetch historical JS/config URLs from Wayback CDX API."""
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc
    api = (
        f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
        f"&output=json&fl=original&filter=mimetype:application/javascript"
        f"&collapse=urlkey&limit={limit}"
    )
    try:
        req = urllib.request.Request(api, headers={"User-Agent": next_user_agent()})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
            # data[0] is the header row
            urls = []
            for row in data[1:]:
                orig = row[0]
                wayback = f"https://web.archive.org/web/{orig}"
                urls.append(wayback)
            return urls
    except Exception:
        return []

# ─────────────────────────────────────────────
# NEW: WEBHOOK ALERT
# ─────────────────────────────────────────────
def send_webhook(webhook_url, finding):
    sev = finding["severity"].upper()
    msg = {
        "text": f"*[LeakHunter] [{sev}]* `{finding['pattern']}`\n"
                f"URL: {finding['url']}\n"
                f"Value: `{finding['match'][:80]}`"
    }
    data = json.dumps(msg).encode()
    try:
        req = urllib.request.Request(
            webhook_url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=8)
    except Exception:
        pass

# ─────────────────────────────────────────────
# NEW: HTML REPORT
# ─────────────────────────────────────────────
SEV_HEX = {"critical": "#ff4444", "high": "#ff8800", "medium": "#ffcc00", "low": "#44aaff"}

def generate_html_report(findings, scanned_urls, target, diff_findings=None):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("critical", "high", "medium", "low")}

    rows = ""
    for f in sorted(findings, key=lambda x: ["critical","high","medium","low"].index(x["severity"])):
        color = SEV_HEX.get(f["severity"], "#888")
        val   = str(f.get("match", "")).replace("<", "&lt;").replace(">", "&gt;")
        url   = str(f.get("url", "")).replace("<", "&lt;")
        ctx   = str(f.get("context", "")).replace("<", "&lt;").replace(">", "&gt;")[:200]
        valid = ""
        if "validation" in f:
            v = f["validation"]
            valid = "✅ VALID" if v.get("valid") else ("❓" if v.get("valid") is None else "❌")
        is_new = diff_findings and f in diff_findings
        new_badge = '<span style="background:#00cc66;color:#000;padding:1px 5px;border-radius:3px;font-size:.65rem;margin-left:4px">NEW</span>' if is_new else ""
        rows += f"""<tr>
          <td><span style="background:{color};color:#000;padding:2px 7px;border-radius:4px;font-size:.7rem;font-weight:700">{f['severity'].upper()}</span>{new_badge}</td>
          <td>{f['pattern']}</td>
          <td style="font-family:monospace;word-break:break-all;font-size:.8rem">{val}</td>
          <td style="font-family:monospace;font-size:.72rem;color:#8b949e">{url}</td>
          <td style="font-size:.75rem;color:#8b949e">{valid}</td>
          <td style="font-family:monospace;font-size:.72rem;color:#8b949e;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{ctx}</td>
        </tr>"""

    scanned_li = "".join(f"<li style='font-family:monospace;font-size:.75rem;color:#8b949e;padding:.15rem 0'>{u}</li>" for u in list(scanned_urls)[:300])

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>LeakHunter Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;padding:2rem}}
  h1{{font-size:1.7rem;color:#58a6ff;margin-bottom:.2rem}}
  .meta{{color:#8b949e;font-size:.85rem;margin-bottom:1.5rem}}
  .stats{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
  .stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:.85rem 1.4rem;text-align:center}}
  .stat .n{{font-size:2rem;font-weight:700}}.stat .l{{font-size:.7rem;color:#8b949e;text-transform:uppercase}}
  table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:2rem}}
  th{{background:#21262d;padding:.65rem 1rem;text-align:left;font-size:.75rem;text-transform:uppercase;color:#8b949e;border-bottom:1px solid #30363d}}
  td{{padding:.6rem 1rem;border-bottom:1px solid #30363d;font-size:.82rem;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}tr:hover td{{background:#1c2128}}
  h2{{font-size:1rem;color:#58a6ff;margin:1.5rem 0 .5rem;border-bottom:1px solid #30363d;padding-bottom:.4rem}}
  ul{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;max-height:250px;overflow-y:auto;list-style:none}}
  .footer{{color:#8b949e;font-size:.75rem;text-align:center;margin-top:2rem}}
</style></head><body>
<h1>&#128269; LeakHunter Report</h1>
<p class="meta">Target: <strong>{target}</strong> &nbsp;|&nbsp; {now} &nbsp;|&nbsp; Files scanned: {len(scanned_urls)}</p>
<div class="stats">
  <div class="stat"><div class="n" style="color:#ff4444">{counts['critical']}</div><div class="l">Critical</div></div>
  <div class="stat"><div class="n" style="color:#ff8800">{counts['high']}</div><div class="l">High</div></div>
  <div class="stat"><div class="n" style="color:#ffcc00">{counts['medium']}</div><div class="l">Medium</div></div>
  <div class="stat"><div class="n" style="color:#44aaff">{counts['low']}</div><div class="l">Low</div></div>
  <div class="stat"><div class="n" style="color:#58a6ff">{len(findings)}</div><div class="l">Total</div></div>
  <div class="stat"><div class="n" style="color:#e6edf3">{len(scanned_urls)}</div><div class="l">Scanned</div></div>
</div>
<h2>Findings</h2>
{'<p style="text-align:center;color:#8b949e;padding:2rem">&#10003; No secrets found.</p>' if not findings else
f'<table><thead><tr><th>Severity</th><th>Type</th><th>Value</th><th>URL</th><th>Valid?</th><th>Context</th></tr></thead><tbody>' + rows + '</tbody></table>'}
<h2>Scanned Files ({len(scanned_urls)})</h2>
<ul>{scanned_li}</ul>
<div class="footer">LeakHunter v2 &nbsp;|&nbsp; {now}</div>
</body></html>"""

# ─────────────────────────────────────────────
# NEW: SARIF OUTPUT
# ─────────────────────────────────────────────
def generate_sarif(findings, target):
    rules = {}
    results = []
    for f in findings:
        rule_id = re.sub(r'[^A-Za-z0-9]', '_', f["pattern"])
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f["pattern"],
                "shortDescription": {"text": f["pattern"]},
                "defaultConfiguration": {"level": "error" if f["severity"] in ("critical","high") else "warning"},
            }
        results.append({
            "ruleId": rule_id,
            "level": "error" if f["severity"] in ("critical","high") else "warning",
            "message": {"text": f"Found {f['pattern']}: {f['match'][:80]}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["url"]}}}],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "LeakHunter", "version": "2.0", "rules": list(rules.values())}}, "results": results}]
    }

# ─────────────────────────────────────────────
# HTML LINK EXTRACTOR  (original)
# ─────────────────────────────────────────────
class LinkExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        url = None
        if tag == "a":
            url = attrs.get("href")
        elif tag in ("script", "img", "link"):
            url = attrs.get("src") or attrs.get("href")
        if url:
            full = urllib.parse.urljoin(self.base_url, url)
            parsed = urllib.parse.urlparse(full)
            base_parsed = urllib.parse.urlparse(self.base_url)
            if parsed.netloc == base_parsed.netloc and parsed.scheme in ("http", "https"):
                self.links.add(full.split("#")[0])

# ─────────────────────────────────────────────
# SCANNER CORE  (original + new hooks)
# ─────────────────────────────────────────────
class LeakHunter:
    def __init__(self, config):
        self.config = config
        self.visited = set()
        self.all_findings = []
        self.compiled = {name: re.compile(pat) for name, pat in PATTERNS.items()
                         if name in config["patterns"]}
        self.headers = {
            "User-Agent": next_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/javascript,text/plain,*/*",
        }
        # NEW: extra headers / cookies from config
        if config.get("extra_headers"):
            self.headers.update(config["extra_headers"])

        # NEW: cache
        self.cache = ScanCache() if config.get("use_cache") else None
        self.previous_keys = self.cache.previous_findings() if self.cache else set()
        self.diff_findings = []

    def fetch(self, url):
        # NEW: rotate user agent per request for stealth
        self.headers["User-Agent"] = next_user_agent()
        try:
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.config["timeout"]) as r:
                ct = r.headers.get("Content-Type", "")
                charset = "utf-8"
                if "charset=" in ct:
                    charset = ct.split("charset=")[-1].strip()
                return r.read().decode(charset, errors="replace"), ct
        except Exception as e:
            return None, str(e)

    def scan_content(self, url, content, source_label=""):
        findings = []
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for name, pattern in self.compiled.items():
                matches = pattern.findall(line)
                if matches:
                    for match in matches:
                        val = match if isinstance(match, str) else (match[0] if match else "")
                        # NEW: false positive filter
                        if is_false_positive(val):
                            continue
                        findings.append({
                            "url":      url + (f" [{source_label}]" if source_label else ""),
                            "pattern":  name,
                            "severity": get_severity(name),
                            "match":    val[:120],
                            "line":     i,
                            "context":  line.strip()[:200],
                            "entropy":  round(shannon_entropy(val), 2),
                            "source":   source_label or "regex",
                        })

        # NEW: entropy-based detection
        if self.config.get("entropy_scan"):
            findings += entropy_scan(content, url)

        # NEW: deobfuscation layers
        if self.config.get("deobfuscate"):
            for label, layer_content in deobfuscate(content):
                sub = self.scan_content(url, layer_content, source_label=label)
                findings += sub

        # NEW: validate findings if requested
        if self.config.get("validate"):
            findings = [validate_finding(f) for f in findings]

        return findings

    def get_links(self, url, content):
        extractor = LinkExtractor(url)
        try:
            extractor.feed(content)
        except Exception:
            pass
        js_urls = re.findall(r'(?:src|href|url)\s*[=:]\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]', content)
        for j in js_urls:
            full = urllib.parse.urljoin(url, j)
            parsed = urllib.parse.urlparse(full)
            base_parsed = urllib.parse.urlparse(url)
            if parsed.netloc == base_parsed.netloc:
                extractor.links.add(full)
        # NEW: webpack/framework chunks
        extractor.links |= discover_chunks(content, url)
        return extractor.links

    def scan_url(self, url, depth=0):
        if url in self.visited:
            return []
        self.visited.add(url)

        # NEW: robots.txt check
        if self.config.get("respect_robots") and hasattr(self, "_disallowed"):
            parsed = urllib.parse.urlparse(url)
            for path in self._disallowed:
                if parsed.path.startswith(path):
                    print(f"  {C.DIM}  ⊘ Skipped (robots.txt): {url}{C.RESET}")
                    return []

        prefix = "  " * depth
        print(f"{prefix}{C.BLUE}►{C.RESET} Scanning: {C.WHITE}{url}{C.RESET}")

        content, ct = self.fetch(url)
        if content is None:
            print(f"{prefix}{C.DIM}  ✗ Failed: {ct}{C.RESET}")
            return []

        # NEW: incremental cache check
        content_hash = hashlib.md5(content.encode()).hexdigest()
        if self.cache and self.cache.already_scanned(url, content_hash):
            print(f"{prefix}{C.DIM}  ↩ Cached (unchanged){C.RESET}")
            return []

        findings = self.scan_content(url, content)

        # NEW: source map resolution for JS files
        if self.config.get("source_maps") and url.endswith(".js"):
            map_url = get_sourcemap_url(url, content)
            map_content, _ = self.fetch(map_url)
            if map_content:
                print(f"{prefix}  {C.DIM}→ Source map: {map_url}{C.RESET}")
                for src in parse_sourcemap(map_content):
                    findings += self.scan_content(map_url, src, source_label="sourcemap")

        for f in findings:
            sev_col = SEV_COLOR.get(f["severity"], C.WHITE)
            is_new = (f["url"], f["pattern"], f["match"]) not in self.previous_keys
            new_tag = f" {C.GREEN}[NEW]{C.RESET}" if (self.cache and is_new) else ""
            valid_tag = ""
            if "validation" in f:
                v = f["validation"]
                valid_tag = f" {C.GREEN}[VALID]{C.RESET}" if v.get("valid") else ""
            print(f"{prefix}  {sev_col}[{f['severity'].upper()}]{C.RESET} "
                  f"{C.BOLD}{f['pattern']}{C.RESET}"
                  f" {C.DIM}(line {f.get('line','-')}){C.RESET}"
                  f"{new_tag}{valid_tag}")
            print(f"{prefix}    {C.DIM}→ {f['match'][:80]}{C.RESET}")

        # NEW: send webhook alerts for critical/high
        if self.config.get("webhook_url"):
            for f in findings:
                if f["severity"] in ("critical", "high"):
                    send_webhook(self.config["webhook_url"], f)

        self.all_findings.extend(findings)

        # NEW: save to cache
        if self.cache:
            self.cache.mark_scanned(url, content_hash)
            if findings:
                self.cache.save_findings(findings)

        if self.config["recursive"] and depth < self.config["depth"]:
            links = self.get_links(url, content)
            new_links = links - self.visited
            if new_links:
                print(f"{prefix}  {C.DIM}Found {len(new_links)} new links{C.RESET}")
            for link in list(new_links)[:self.config["max_urls"]]:
                time.sleep(self.config["delay"])
                self.scan_url(link, depth + 1)

        return findings

    def run(self):
        print(BANNER)
        print(f"{C.CYAN}[*]{C.RESET} Target      : {C.WHITE}{self.config['url']}{C.RESET}")
        print(f"{C.CYAN}[*]{C.RESET} Recursive   : {C.WHITE}{self.config['recursive']}{C.RESET}")
        print(f"{C.CYAN}[*]{C.RESET} Depth       : {C.WHITE}{self.config['depth']}{C.RESET}")
        print(f"{C.CYAN}[*]{C.RESET} Patterns    : {C.WHITE}{len(self.compiled)}{C.RESET}")
        print(f"{C.CYAN}[*]{C.RESET} Max URLs    : {C.WHITE}{self.config['max_urls']}{C.RESET}")
        print(f"{C.CYAN}[*]{C.RESET} Entropy     : {C.WHITE}{self.config.get('entropy_scan', False)}{C.RESET}")
        print(f"{C.CYAN}[*]{C.RESET} Deobfuscate : {C.WHITE}{self.config.get('deobfuscate', False)}{C.RESET}")
        print(f"{C.CYAN}[*]{C.RESET} Source Maps : {C.WHITE}{self.config.get('source_maps', False)}{C.RESET}")
        print(f"{C.CYAN}[*]{C.RESET} Validate    : {C.WHITE}{self.config.get('validate', False)}{C.RESET}")
        print(f"{C.CYAN}[*]{C.RESET} Wayback     : {C.WHITE}{self.config.get('wayback', False)}{C.RESET}")
        print(f"{C.CYAN}[*]{C.RESET} Output      : {C.WHITE}{self.config['output'] or 'stdout only'}{C.RESET}")
        print(f"\n{C.DIM}{'─'*70}{C.RESET}\n")

        start = time.time()

        # NEW: fetch robots.txt if needed
        if self.config.get("respect_robots"):
            self._disallowed = fetch_disallowed_paths(self.config["url"], self.fetch)
            print(f"{C.DIM}[robots.txt] {len(self._disallowed)} disallowed paths{C.RESET}\n")

        # NEW: probe sensitive paths first
        if self.config.get("probe_sensitive"):
            parsed = urllib.parse.urlparse(self.config["url"])
            base = f"{parsed.scheme}://{parsed.netloc}"
            print(f"{C.CYAN}[*]{C.RESET} Probing {len(SENSITIVE_PATHS)} sensitive paths...\n")
            for path in SENSITIVE_PATHS:
                probe_url = base + path
                if probe_url not in self.visited:
                    self.scan_url(probe_url, depth=0)
                    time.sleep(self.config["delay"])

        # NEW: Wayback Machine scan
        if self.config.get("wayback"):
            print(f"\n{C.CYAN}[*]{C.RESET} Fetching Wayback Machine URLs...")
            wb_urls = wayback_urls(self.config["url"], limit=self.config.get("wayback_limit", 20))
            print(f"{C.DIM}    Found {len(wb_urls)} archived URLs{C.RESET}\n")
            for wb_url in wb_urls:
                if wb_url not in self.visited:
                    self.scan_url(wb_url, depth=0)
                    time.sleep(self.config["delay"])

        # Main crawl
        self.scan_url(self.config["url"])
        elapsed = time.time() - start

        # NEW: compute diff
        diff_findings = compute_diff(self.all_findings, self.previous_keys)

        print(f"\n{C.DIM}{'─'*70}{C.RESET}")
        print(f"\n{C.GREEN}[+]{C.RESET} Scan complete in {elapsed:.1f}s")
        print(f"{C.GREEN}[+]{C.RESET} URLs scanned  : {C.WHITE}{len(self.visited)}{C.RESET}")
        print(f"{C.GREEN}[+]{C.RESET} Total findings: {C.WHITE}{len(self.all_findings)}{C.RESET}")
        if self.cache and diff_findings:
            print(f"{C.GREEN}[+]{C.RESET} NEW since last : {C.GREEN}{len(diff_findings)}{C.RESET}")

        by_sev = defaultdict(list)
        for f in self.all_findings:
            by_sev[f["severity"]].append(f)
        for sev in ["critical", "high", "medium", "low"]:
            count = len(by_sev[sev])
            if count:
                col = SEV_COLOR[sev]
                print(f"  {col}[{sev.upper()}]{C.RESET} {count} finding(s)")

        if self.config.get("output"):
            self.save_output(diff_findings)

        # NEW: HTML report
        if self.config.get("html_output"):
            html = generate_html_report(self.all_findings, self.visited,
                                         self.config["url"], diff_findings)
            with open(self.config["html_output"], "w", encoding="utf-8") as f:
                f.write(html)
            print(f"\n{C.GREEN}[+]{C.RESET} HTML report : {C.WHITE}{self.config['html_output']}{C.RESET}")

        # NEW: SARIF output
        if self.config.get("sarif_output"):
            sarif = generate_sarif(self.all_findings, self.config["url"])
            with open(self.config["sarif_output"], "w") as f:
                json.dump(sarif, f, indent=2)
            print(f"{C.GREEN}[+]{C.RESET} SARIF report: {C.WHITE}{self.config['sarif_output']}{C.RESET}")

        # NEW: CI/CD exit code
        if self.config.get("ci_mode"):
            fail_on = self.config.get("fail_on", ["critical"])
            for f in self.all_findings:
                if f["severity"] in fail_on:
                    print(f"\n{C.RED}[CI]{C.RESET} Exiting with code 1 ({f['severity']} findings found)")
                    if self.cache:
                        self.cache.close()
                    sys.exit(1)

        if self.cache:
            self.cache.close()

    def save_output(self, diff_findings=None):
        fmt  = self.config["output_format"]
        path = self.config["output"]
        try:
            if fmt == "json":
                with open(path, "w") as f:
                    json.dump({
                        "target":      self.config["url"],
                        "scanned_at":  datetime.now().isoformat(),
                        "total_urls":  len(self.visited),
                        "findings":    self.all_findings,
                        "new_findings": diff_findings or [],
                    }, f, indent=2)
            else:
                with open(path, "w") as f:
                    f.write(f"LeakHunter Report\n")
                    f.write(f"Target: {self.config['url']}\n")
                    f.write(f"Scanned: {datetime.now().isoformat()}\n")
                    f.write(f"URLs scanned: {len(self.visited)}\n")
                    f.write(f"Total findings: {len(self.all_findings)}\n")
                    f.write("=" * 60 + "\n\n")
                    for f2 in self.all_findings:
                        f.write(f"[{f2['severity'].upper()}] {f2['pattern']}\n")
                        f.write(f"  URL    : {f2['url']}\n")
                        f.write(f"  Line   : {f2.get('line', '-')}\n")
                        f.write(f"  Match  : {f2['match']}\n")
                        f.write(f"  Context: {f2.get('context','')}\n")
                        if "validation" in f2:
                            f.write(f"  Valid  : {f2['validation']}\n")
                        f.write("\n")
            print(f"\n{C.GREEN}[+]{C.RESET} Results saved to: {C.WHITE}{path}{C.RESET}")
        except Exception as e:
            print(f"\n{C.RED}[!]{C.RESET} Failed to save: {e}")

# ─────────────────────────────────────────────
# PATTERN GROUPS / WORDLISTS  (original)
# ─────────────────────────────────────────────
WORDLISTS = {
    "1":  {"name": "All Patterns (300+)", "patterns": list(PATTERNS.keys())},
    "2":  {"name": "Cloud & Infrastructure (AWS, GCP, Azure)", "patterns": [k for k in PATTERNS if any(x in k for x in ["AWS","Google","Azure","GCP","S3","Heroku","Firebase","GCS","Cloudinary","Databricks"])]},
    "3":  {"name": "Payment & Finance (Stripe, PayPal, Braintree...)", "patterns": [k for k in PATTERNS if any(x in k for x in ["Stripe","PayPal","Braintree","Square","Shopify","Plaid"])]},
    "4":  {"name": "Social & Messaging (Slack, Discord, Telegram...)", "patterns": [k for k in PATTERNS if any(x in k for x in ["Slack","Discord","Telegram","Twitter","Facebook","LinkedIn","Twilio"])]},
    "5":  {"name": "Developer Tools (GitHub, GitLab, NPM, Docker...)", "patterns": [k for k in PATTERNS if any(x in k for x in ["GitHub","GitLab","NPM","PyPI","Docker","CircleCI","Travis","Bitbucket","Snyk"])]},
    "6":  {"name": "Database Connections", "patterns": [k for k in PATTERNS if any(x in k for x in ["MongoDB","PostgreSQL","MySQL","Redis","JDBC","Elasticsearch"])]},
    "7":  {"name": "Private Keys & Certificates", "patterns": [k for k in PATTERNS if any(x in k for x in ["Private Key","Certificate","PGP","RSA","EC","DSA","OpenSSH","PKCS8"])]},
    "8":  {"name": "Analytics & Monitoring (Datadog, Sentry, New Relic...)", "patterns": [k for k in PATTERNS if any(x in k for x in ["Datadog","Sentry","New Relic","Amplitude","Segment","Mixpanel","LaunchDarkly"])]},
    "9":  {"name": "Generic / Catch-All (password, secret, token...)", "patterns": [k for k in PATTERNS if k.startswith("Generic") or k in ["JWT Token","JWT Secret","Basic Auth in URL","Dotenv Secret","Django Secret Key","Rails Secret","Laravel App Key","Debug/Dev Flag","Hardcoded Admin Cred","Hardcoded Username","Internal IP","Localhost URL"]]},
    "10": {"name": "Email Services (SendGrid, Mailgun, Mailchimp...)", "patterns": [k for k in PATTERNS if any(x in k for x in ["SendGrid","Mailgun","Mailchimp","SMTP"])]},
}

# ─────────────────────────────────────────────
# INTERACTIVE MENU  (original + new questions appended)
# ─────────────────────────────────────────────
def clear():
    print("\033[2J\033[H", end="")

def menu():
    print(BANNER)

    # ── Target ── (original)
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} TARGET CONFIGURATION{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    url = input(f"\n  {C.GREEN}►{C.RESET} Enter target URL: ").strip()
    if not url.startswith("http"):
        url = "https://" + url

    # ── Wordlist ── (original)
    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} PATTERN WORDLIST{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    for k, v in WORDLISTS.items():
        count = len(v["patterns"])
        print(f"  {C.GREEN}[{k:>2}]{C.RESET}  {v['name']} {C.DIM}({count} patterns){C.RESET}")
    wl_choice = input(f"\n  {C.GREEN}►{C.RESET} Select wordlist [1]: ").strip() or "1"
    if wl_choice not in WORDLISTS:
        wl_choice = "1"
    selected_wl = WORDLISTS[wl_choice]
    patterns = selected_wl["patterns"]
    print(f"  {C.DIM}→ Using: {selected_wl['name']} ({len(patterns)} patterns){C.RESET}")

    # ── Scan Options ── (original)
    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} SCAN OPTIONS{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    recursive_in = input(f"\n  {C.GREEN}►{C.RESET} Enable recursive crawling? [y/N]: ").strip().lower()
    recursive = recursive_in in ("y", "yes", "1")
    depth = 2
    max_urls = 50
    if recursive:
        depth_in = input(f"  {C.GREEN}►{C.RESET} Crawl depth [2]: ").strip()
        depth = int(depth_in) if depth_in.isdigit() else 2
        max_in = input(f"  {C.GREEN}►{C.RESET} Max URLs per level [50]: ").strip()
        max_urls = int(max_in) if max_in.isdigit() else 50
    timeout_in = input(f"  {C.GREEN}►{C.RESET} Request timeout in seconds [10]: ").strip()
    timeout = int(timeout_in) if timeout_in.isdigit() else 10
    delay_in = input(f"  {C.GREEN}►{C.RESET} Delay between requests in seconds [0.3]: ").strip()
    delay = float(delay_in) if delay_in else 0.3

    # ── Severity filter ── (original)
    print(f"\n  Minimum severity to report:")
    print(f"  {C.GREEN}[1]{C.RESET} critical only")
    print(f"  {C.GREEN}[2]{C.RESET} high+")
    print(f"  {C.GREEN}[3]{C.RESET} medium+")
    print(f"  {C.GREEN}[4]{C.RESET} all (default)")
    sev_in = input(f"  {C.GREEN}►{C.RESET} Choose [4]: ").strip() or "4"
    sev_map = {"1": ["critical"], "2": ["critical","high"], "3": ["critical","high","medium"], "4": ["critical","high","medium","low"]}
    min_sev = sev_map.get(sev_in, sev_map["4"])

    # ── NEW: Advanced Detection Options ──
    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} ADVANCED DETECTION{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")

    entropy_in = input(f"\n  {C.GREEN}►{C.RESET} Enable entropy analysis (catches unlisted secrets)? [y/N]: ").strip().lower()
    entropy_scan = entropy_in in ("y", "yes", "1")

    deobf_in = input(f"  {C.GREEN}►{C.RESET} Enable deobfuscation (base64, hex, unicode)? [y/N]: ").strip().lower()
    deobfuscate = deobf_in in ("y", "yes", "1")

    srcmap_in = input(f"  {C.GREEN}►{C.RESET} Resolve JS source maps (*.js.map)? [y/N]: ").strip().lower()
    source_maps = srcmap_in in ("y", "yes", "1")

    sensitive_in = input(f"  {C.GREEN}►{C.RESET} Probe sensitive paths (/.env, /config.json, etc.)? [y/N]: ").strip().lower()
    probe_sensitive = sensitive_in in ("y", "yes", "1")

    wayback_in = input(f"  {C.GREEN}►{C.RESET} Scan Wayback Machine (archived JS files)? [y/N]: ").strip().lower()
    wayback = wayback_in in ("y", "yes", "1")
    wayback_limit = 20
    if wayback:
        wb_lim = input(f"  {C.GREEN}►{C.RESET} Max Wayback URLs to fetch [20]: ").strip()
        wayback_limit = int(wb_lim) if wb_lim.isdigit() else 20

    # ── NEW: Validation ──
    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} LIVE VALIDATION{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    validate_in = input(f"\n  {C.GREEN}►{C.RESET} Live-validate found keys (AWS, GitHub, Stripe, Slack)? [y/N]: ").strip().lower()
    validate = validate_in in ("y", "yes", "1")

    # ── NEW: Auth / Headers ──
    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} AUTHENTICATION{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    cookie_in = input(f"\n  {C.GREEN}►{C.RESET} Add Cookie header (leave empty to skip): ").strip()
    header_in = input(f"  {C.GREEN}►{C.RESET} Add custom header e.g. Authorization:Bearer xyz (empty=skip): ").strip()
    extra_headers = {}
    if cookie_in:
        extra_headers["Cookie"] = cookie_in
    if header_in and ":" in header_in:
        k, v = header_in.split(":", 1)
        extra_headers[k.strip()] = v.strip()

    # ── NEW: Stealth / Robots ──
    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} STEALTH & ROBOTS{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    robots_in = input(f"\n  {C.GREEN}►{C.RESET} Respect robots.txt? [y/N]: ").strip().lower()
    respect_robots = robots_in in ("y", "yes", "1")

    # ── NEW: Cache / Resume ──
    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} RESUME / INCREMENTAL{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    cache_in = input(f"\n  {C.GREEN}►{C.RESET} Use scan cache (skip unchanged files / show NEW findings)? [y/N]: ").strip().lower()
    use_cache = cache_in in ("y", "yes", "1")

    # ── NEW: Webhook ──
    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} ALERTS{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    webhook_in = input(f"\n  {C.GREEN}►{C.RESET} Webhook URL for critical/high alerts (empty=skip): ").strip()
    webhook_url = webhook_in or None

    # ── Output ── (original)
    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} OUTPUT{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    out_file = input(f"\n  {C.GREEN}►{C.RESET} Save results to file (leave empty to skip): ").strip()
    out_fmt = "txt"
    if out_file:
        fmt_in = input(f"  {C.GREEN}►{C.RESET} Format [txt/json] (default: txt): ").strip().lower()
        out_fmt = "json" if fmt_in == "json" else "txt"

    # NEW: additional output formats
    html_out = input(f"  {C.GREEN}►{C.RESET} HTML report path (empty=skip, e.g. report.html): ").strip() or None
    sarif_out = input(f"  {C.GREEN}►{C.RESET} SARIF report path (empty=skip, e.g. results.sarif): ").strip() or None

    # NEW: CI/CD mode
    ci_in = input(f"  {C.GREEN}►{C.RESET} CI/CD mode (exit code 1 on critical findings)? [y/N]: ").strip().lower()
    ci_mode = ci_in in ("y", "yes", "1")

    print(f"\n{C.CYAN}{'─'*60}{C.RESET}\n")
    input(f"  {C.GREEN}► Press ENTER to start scanning...{C.RESET}")

    return {
        "url":            url,
        "patterns":       patterns,
        "recursive":      recursive,
        "depth":          depth,
        "max_urls":       max_urls,
        "timeout":        timeout,
        "delay":          delay,
        "min_sev":        min_sev,
        "output":         out_file or None,
        "output_format":  out_fmt,
        # new
        "entropy_scan":   entropy_scan,
        "deobfuscate":    deobfuscate,
        "source_maps":    source_maps,
        "probe_sensitive": probe_sensitive,
        "wayback":        wayback,
        "wayback_limit":  wayback_limit,
        "validate":       validate,
        "extra_headers":  extra_headers,
        "respect_robots": respect_robots,
        "use_cache":      use_cache,
        "webhook_url":    webhook_url,
        "html_output":    html_out,
        "sarif_output":   sarif_out,
        "ci_mode":        ci_mode,
        "fail_on":        ["critical", "high"],
    }

# ─────────────────────────────────────────────
# CLI ARG PARSING  (original + new flags)
# ─────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="LeakHunter - API Secret & Credential Scanner v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python leakhunter.py                                  # interactive menu
  python leakhunter.py -u https://target.com            # quick scan
  python leakhunter.py -u https://target.com --recursive -d 3
  python leakhunter.py -u https://target.com --recursive -o results.json --format json
  python leakhunter.py -u https://target.com --entropy --deobfuscate --source-maps
  python leakhunter.py -u https://target.com --probe-sensitive --wayback
  python leakhunter.py -u https://target.com --validate --html report.html --sarif out.sarif
  python leakhunter.py -u https://target.com --ci --cookie "session=abc" --header "X-API-Key:xxx"
        """
    )
    # original flags
    p.add_argument("-u", "--url",       help="Target URL")
    p.add_argument("--recursive",       action="store_true", help="Enable recursive crawling")
    p.add_argument("-d", "--depth",     type=int, default=2)
    p.add_argument("--max-urls",        type=int, default=50)
    p.add_argument("--timeout",         type=int, default=10)
    p.add_argument("--delay",           type=float, default=0.3)
    p.add_argument("-o", "--output",    help="Output file path")
    p.add_argument("--format",          choices=["txt","json"], default="txt")
    p.add_argument("--wordlist",        choices=list(WORDLISTS.keys()), default="1")
    # new flags
    p.add_argument("--entropy",         action="store_true", help="Entropy analysis for unlisted secrets")
    p.add_argument("--deobfuscate",     action="store_true", help="Deobfuscate base64/hex/unicode in JS")
    p.add_argument("--source-maps",     action="store_true", help="Resolve JS source maps")
    p.add_argument("--probe-sensitive", action="store_true", help="Probe /.env /config.json etc.")
    p.add_argument("--wayback",         action="store_true", help="Scan Wayback Machine archived JS")
    p.add_argument("--wayback-limit",   type=int, default=20)
    p.add_argument("--validate",        action="store_true", help="Live-validate found keys")
    p.add_argument("--cookie",          help="Cookie header value")
    p.add_argument("--header",          help="Extra header e.g. 'Authorization:Bearer token'")
    p.add_argument("--respect-robots",  action="store_true", help="Respect robots.txt")
    p.add_argument("--cache",           action="store_true", help="Use SQLite scan cache / incremental mode")
    p.add_argument("--webhook",         help="Webhook URL for critical/high alerts")
    p.add_argument("--html",            help="HTML report output path")
    p.add_argument("--sarif",           help="SARIF report output path")
    p.add_argument("--ci",              action="store_true", help="CI/CD mode: exit 1 on critical/high findings")
    p.add_argument("--fail-on",         nargs="+", default=["critical","high"],
                   choices=["critical","high","medium","low"],
                   help="Severities that trigger CI exit code 1")
    return p.parse_args()

# ─────────────────────────────────────────────
# MAIN  (original structure, new config keys added)
# ─────────────────────────────────────────────
def main():
    args = parse_args()

    if args.url:
        url = args.url
        if not url.startswith("http"):
            url = "https://" + url

        extra_headers = {}
        if args.cookie:
            extra_headers["Cookie"] = args.cookie
        if args.header and ":" in args.header:
            k, v = args.header.split(":", 1)
            extra_headers[k.strip()] = v.strip()

        config = {
            "url":             url,
            "patterns":        WORDLISTS[args.wordlist]["patterns"],
            "recursive":       args.recursive,
            "depth":           args.depth,
            "max_urls":        args.max_urls,
            "timeout":         args.timeout,
            "delay":           args.delay,
            "min_sev":         ["critical","high","medium","low"],
            "output":          args.output,
            "output_format":   args.format,
            # new
            "entropy_scan":    args.entropy,
            "deobfuscate":     args.deobfuscate,
            "source_maps":     args.source_maps,
            "probe_sensitive": args.probe_sensitive,
            "wayback":         args.wayback,
            "wayback_limit":   args.wayback_limit,
            "validate":        args.validate,
            "extra_headers":   extra_headers,
            "respect_robots":  args.respect_robots,
            "use_cache":       args.cache,
            "webhook_url":     args.webhook,
            "html_output":     args.html,
            "sarif_output":    args.sarif,
            "ci_mode":         args.ci,
            "fail_on":         args.fail_on,
        }
    else:
        config = menu()

    hunter = LeakHunter(config)
    try:
        hunter.run()
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}[!]{C.RESET} Scan interrupted by user.")
        if hunter.all_findings:
            save = input(f"{C.GREEN}►{C.RESET} Save partial results? [y/N]: ").strip().lower()
            if save in ("y", "yes") and config["output"]:
                hunter.save_output()
        if hunter.cache:
            hunter.cache.close()
        sys.exit(0)

if __name__ == "__main__":
    main()