#!/usr/bin/env python3
"""
LeakHunter - API Secret & Credential Scanner
For use only on authorized bug bounty targets / your own systems.
"""

import re
import sys
import json
import time
import argparse
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────
# 300+ PATTERNS
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
# COLORS
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

# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────
BANNER = f"""
{C.GREEN}{C.BOLD}
  ██╗     ███████╗ █████╗ ██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██║     ██╔════╝██╔══██╗██║ ██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██║     █████╗  ███████║█████╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██║     ██╔══╝  ██╔══██║██╔═██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ███████╗███████╗██║  ██║██║  ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RESET}{C.DIM}  API Secret & Credential Scanner  |  300+ Patterns  |  For authorized targets only{C.RESET}
"""

# ─────────────────────────────────────────────
# HTML LINK EXTRACTOR
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
            if parsed.netloc == base_parsed.netloc and parsed.scheme in ("http","https"):
                self.links.add(full.split("#")[0])

# ─────────────────────────────────────────────
# SCANNER CORE
# ─────────────────────────────────────────────
class LeakHunter:
    def __init__(self, config):
        self.config = config
        self.visited = set()
        self.all_findings = []
        self.compiled = {name: re.compile(pat) for name, pat in PATTERNS.items()
                         if name in config["patterns"]}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (compatible; LeakHunter/1.0; +https://github.com/leakhunter)",
            "Accept": "text/html,application/xhtml+xml,application/javascript,text/plain,*/*",
        }

    def fetch(self, url):
        try:
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.config["timeout"]) as r:
                ct = r.headers.get("Content-Type","")
                charset = "utf-8"
                if "charset=" in ct:
                    charset = ct.split("charset=")[-1].strip()
                return r.read().decode(charset, errors="replace"), ct
        except Exception as e:
            return None, str(e)

    def scan_content(self, url, content):
        findings = []
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for name, pattern in self.compiled.items():
                matches = pattern.findall(line)
                if matches:
                    for match in matches:
                        val = match if isinstance(match, str) else match[0] if match else ""
                        findings.append({
                            "url":      url,
                            "pattern":  name,
                            "severity": get_severity(name),
                            "match":    val[:120],
                            "line":     i,
                            "context":  line.strip()[:200],
                        })
        return findings

    def get_links(self, url, content):
        extractor = LinkExtractor(url)
        try:
            extractor.feed(content)
        except Exception:
            pass
        # also extract from JS src attributes and inline urls
        js_urls = re.findall(r'(?:src|href|url)\s*[=:]\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]', content)
        for j in js_urls:
            full = urllib.parse.urljoin(url, j)
            parsed = urllib.parse.urlparse(full)
            base_parsed = urllib.parse.urlparse(url)
            if parsed.netloc == base_parsed.netloc:
                extractor.links.add(full)
        return extractor.links

    def scan_url(self, url, depth=0):
        if url in self.visited:
            return []
        self.visited.add(url)

        prefix = "  " * depth
        print(f"{prefix}{C.BLUE}►{C.RESET} Scanning: {C.WHITE}{url}{C.RESET}")

        content, ct = self.fetch(url)
        if content is None:
            print(f"{prefix}{C.DIM}  ✗ Failed to fetch: {ct}{C.RESET}")
            return []

        findings = self.scan_content(url, content)

        for f in findings:
            sev_col = SEV_COLOR.get(f["severity"], C.WHITE)
            print(f"{prefix}  {sev_col}[{f['severity'].upper()}]{C.RESET} "
                  f"{C.BOLD}{f['pattern']}{C.RESET} "
                  f"{C.DIM}(line {f['line']}){C.RESET}")
            print(f"{prefix}    {C.DIM}→ {f['match'][:80]}{C.RESET}")

        self.all_findings.extend(findings)

        if self.config["recursive"] and depth < self.config["depth"]:
            links = self.get_links(url, content)
            new_links = links - self.visited
            if new_links:
                print(f"{prefix}  {C.DIM}Found {len(new_links)} new links to crawl{C.RESET}")
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
        print(f"{C.CYAN}[*]{C.RESET} Output      : {C.WHITE}{self.config['output'] or 'stdout only'}{C.RESET}")
        print(f"\n{C.DIM}{'─'*70}{C.RESET}\n")

        start = time.time()
        self.scan_url(self.config["url"])
        elapsed = time.time() - start

        print(f"\n{C.DIM}{'─'*70}{C.RESET}")
        print(f"\n{C.GREEN}[+]{C.RESET} Scan complete in {elapsed:.1f}s")
        print(f"{C.GREEN}[+]{C.RESET} URLs scanned  : {C.WHITE}{len(self.visited)}{C.RESET}")
        print(f"{C.GREEN}[+]{C.RESET} Total findings: {C.WHITE}{len(self.all_findings)}{C.RESET}")

        # Summary by severity
        by_sev = defaultdict(list)
        for f in self.all_findings:
            by_sev[f["severity"]].append(f)

        for sev in ["critical","high","medium","low"]:
            count = len(by_sev[sev])
            if count:
                col = SEV_COLOR[sev]
                print(f"  {col}[{sev.upper()}]{C.RESET} {count} finding(s)")

        # Save output
        if self.config["output"]:
            self.save_output()

    def save_output(self):
        fmt = self.config["output_format"]
        path = self.config["output"]
        try:
            if fmt == "json":
                with open(path, "w") as f:
                    json.dump({
                        "target": self.config["url"],
                        "scanned_at": datetime.now().isoformat(),
                        "total_urls": len(self.visited),
                        "findings": self.all_findings
                    }, f, indent=2)
            else:
                with open(path, "w") as f:
                    f.write(f"LeakHunter Report\n")
                    f.write(f"Target: {self.config['url']}\n")
                    f.write(f"Scanned: {datetime.now().isoformat()}\n")
                    f.write(f"URLs scanned: {len(self.visited)}\n")
                    f.write(f"Total findings: {len(self.all_findings)}\n")
                    f.write("="*60 + "\n\n")
                    for f2 in self.all_findings:
                        f.write(f"[{f2['severity'].upper()}] {f2['pattern']}\n")
                        f.write(f"  URL    : {f2['url']}\n")
                        f.write(f"  Line   : {f2['line']}\n")
                        f.write(f"  Match  : {f2['match']}\n")
                        f.write(f"  Context: {f2['context']}\n\n")
            print(f"\n{C.GREEN}[+]{C.RESET} Results saved to: {C.WHITE}{path}{C.RESET}")
        except Exception as e:
            print(f"\n{C.RED}[!]{C.RESET} Failed to save: {e}")

# ─────────────────────────────────────────────
# PATTERN GROUPS (wordlists)
# ─────────────────────────────────────────────
WORDLISTS = {
    "1": {
        "name": "All Patterns (300+)",
        "patterns": list(PATTERNS.keys()),
    },
    "2": {
        "name": "Cloud & Infrastructure (AWS, GCP, Azure)",
        "patterns": [k for k in PATTERNS if any(x in k for x in
            ["AWS","Google","Azure","GCP","S3","Heroku","Firebase","GCS","Cloudinary","Databricks"])],
    },
    "3": {
        "name": "Payment & Finance (Stripe, PayPal, Braintree...)",
        "patterns": [k for k in PATTERNS if any(x in k for x in
            ["Stripe","PayPal","Braintree","Square","Shopify","Plaid"])],
    },
    "4": {
        "name": "Social & Messaging (Slack, Discord, Telegram...)",
        "patterns": [k for k in PATTERNS if any(x in k for x in
            ["Slack","Discord","Telegram","Twitter","Facebook","LinkedIn","Twilio"])],
    },
    "5": {
        "name": "Developer Tools (GitHub, GitLab, NPM, Docker...)",
        "patterns": [k for k in PATTERNS if any(x in k for x in
            ["GitHub","GitLab","NPM","PyPI","Docker","CircleCI","Travis","Bitbucket","Snyk"])],
    },
    "6": {
        "name": "Database Connections",
        "patterns": [k for k in PATTERNS if any(x in k for x in
            ["MongoDB","PostgreSQL","MySQL","Redis","JDBC","Elasticsearch"])],
    },
    "7": {
        "name": "Private Keys & Certificates",
        "patterns": [k for k in PATTERNS if any(x in k for x in
            ["Private Key","Certificate","PGP","RSA","EC","DSA","OpenSSH","PKCS8"])],
    },
    "8": {
        "name": "Analytics & Monitoring (Datadog, Sentry, New Relic...)",
        "patterns": [k for k in PATTERNS if any(x in k for x in
            ["Datadog","Sentry","New Relic","Amplitude","Segment","Mixpanel","LaunchDarkly"])],
    },
    "9": {
        "name": "Generic / Catch-All (password, secret, token...)",
        "patterns": [k for k in PATTERNS if k.startswith("Generic") or
                     k in ["JWT Token","JWT Secret","Basic Auth in URL","Dotenv Secret",
                            "Django Secret Key","Rails Secret","Laravel App Key",
                            "Debug/Dev Flag","Hardcoded Admin Cred","Hardcoded Username",
                            "Internal IP","Localhost URL"]],
    },
    "10": {
        "name": "Email Services (SendGrid, Mailgun, Mailchimp...)",
        "patterns": [k for k in PATTERNS if any(x in k for x in
            ["SendGrid","Mailgun","Mailchimp","SMTP"])],
    },
}

# ─────────────────────────────────────────────
# INTERACTIVE MENU
# ─────────────────────────────────────────────
def clear():
    print("\033[2J\033[H", end="")

def menu():
    print(BANNER)

    # ── Target ──
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} TARGET CONFIGURATION{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    url = input(f"\n  {C.GREEN}►{C.RESET} Enter target URL: ").strip()
    if not url.startswith("http"):
        url = "https://" + url

    # ── Wordlist ──
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

    # ── Options ──
    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} SCAN OPTIONS{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")

    recursive_in = input(f"\n  {C.GREEN}►{C.RESET} Enable recursive crawling? [y/N]: ").strip().lower()
    recursive = recursive_in in ("y","yes","1")

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

    # ── Severity filter ──
    print(f"\n  Minimum severity to report:")
    print(f"  {C.GREEN}[1]{C.RESET} critical only")
    print(f"  {C.GREEN}[2]{C.RESET} high+")
    print(f"  {C.GREEN}[3]{C.RESET} medium+")
    print(f"  {C.GREEN}[4]{C.RESET} all (default)")
    sev_in = input(f"  {C.GREEN}►{C.RESET} Choose [4]: ").strip() or "4"
    sev_map = {"1":["critical"],"2":["critical","high"],"3":["critical","high","medium"],"4":["critical","high","medium","low"]}
    min_sev = sev_map.get(sev_in, sev_map["4"])

    # ── Output ──
    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD} OUTPUT{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    out_file = input(f"\n  {C.GREEN}►{C.RESET} Save results to file (leave empty to skip): ").strip()
    out_fmt = "txt"
    if out_file:
        fmt_in = input(f"  {C.GREEN}►{C.RESET} Format [txt/json] (default: txt): ").strip().lower()
        out_fmt = "json" if fmt_in == "json" else "txt"

    print(f"\n{C.CYAN}{'─'*60}{C.RESET}\n")
    input(f"  {C.GREEN}► Press ENTER to start scanning...{C.RESET}")

    return {
        "url":           url,
        "patterns":      patterns,
        "recursive":     recursive,
        "depth":         depth,
        "max_urls":      max_urls,
        "timeout":       timeout,
        "delay":         delay,
        "min_sev":       min_sev,
        "output":        out_file or None,
        "output_format": out_fmt,
    }

# ─────────────────────────────────────────────
# CLI ARG PARSING (alternative to menu)
# ─────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="LeakHunter - API Secret & Credential Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python leakhunter.py                          # interactive menu
  python leakhunter.py -u https://target.com    # quick scan
  python leakhunter.py -u https://target.com --recursive -d 3
  python leakhunter.py -u https://target.com --recursive -o results.json --format json
        """
    )
    p.add_argument("-u","--url",      help="Target URL")
    p.add_argument("--recursive",     action="store_true", help="Enable recursive crawling")
    p.add_argument("-d","--depth",    type=int, default=2, help="Crawl depth (default: 2)")
    p.add_argument("--max-urls",      type=int, default=50, help="Max URLs per depth level")
    p.add_argument("--timeout",       type=int, default=10, help="Request timeout (seconds)")
    p.add_argument("--delay",         type=float, default=0.3, help="Delay between requests")
    p.add_argument("-o","--output",   help="Output file path")
    p.add_argument("--format",        choices=["txt","json"], default="txt")
    p.add_argument("--wordlist",      choices=list(WORDLISTS.keys()), default="1",
                                      help="Pattern wordlist (1=all, 2=cloud, 3=payment...)")
    return p.parse_args()

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    args = parse_args()

    if args.url:
        # CLI mode — skip menu
        url = args.url
        if not url.startswith("http"):
            url = "https://" + url
        config = {
            "url":           url,
            "patterns":      WORDLISTS[args.wordlist]["patterns"],
            "recursive":     args.recursive,
            "depth":         args.depth,
            "max_urls":      args.max_urls,
            "timeout":       args.timeout,
            "delay":         args.delay,
            "min_sev":       ["critical","high","medium","low"],
            "output":        args.output,
            "output_format": args.format,
        }
    else:
        # Interactive menu
        config = menu()

    hunter = LeakHunter(config)
    try:
        hunter.run()
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}[!]{C.RESET} Scan interrupted by user.")
        if hunter.all_findings:
            save = input(f"{C.GREEN}►{C.RESET} Save partial results? [y/N]: ").strip().lower()
            if save in ("y","yes") and config["output"]:
                hunter.save_output()
        sys.exit(0)

if __name__ == "__main__":
    main()