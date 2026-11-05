"""Detection rules: content patterns (API keys, tokens, crypto keys) and sensitive filenames."""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    pattern: re.Pattern
    category: str = "api-key"
    group: int = 1                  # regex group holding the secret value
    keywords: tuple = ()            # cheap lowercase prefilter; rule only runs if one is in the line
    validate: Optional[Callable[[re.Match], bool]] = None
    generic: bool = False           # suppressed when a specific rule already matched the same span
    path_filter: Optional[re.Pattern] = None
    name_group: Optional[int] = None  # regex group holding the variable name, if any
    env_name: str = "SECRET"
    rotate: str = ""
    per_file: bool = False          # matched text is not unique per secret (e.g. a PEM header): fingerprint by file


@dataclass(frozen=True)
class FileRule:
    id: str
    name: str
    severity: str
    pattern: re.Pattern
    category: str = "sensitive-file"
    gitignore: str = ""             # pattern to add to .gitignore
    rotate: str = ""
    exclude: Optional[re.Pattern] = None


# --------------------------------------------------------------------------- helpers

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    if len(value) <= 16:
        return value[:2] + "…" + value[-1:]
    return value[:4] + "…" + value[-3:]


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_decode(s: str) -> Optional[bytes]:
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    body, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != chk:
        return None
    return body


_PLACEHOLDER = re.compile(
    r"(?i)your|example|sample|dummy|placeholder|changeme|change_me|replace|insert|redacted|"
    r"xxxx|\*\*\*|<|>|\$\{|\{\{|%\(|process\.env|os\.environ|getenv|env\(|todo|fixme|"
    r"fake|mock|lorem|foobar|^test|^none$|^null$|^true$|^false$|^undefined$"
)
_NOT_SECRET_NAME = re.compile(
    r"(?i)(url|uri|path|file|dir|name|type|field|label|length|len|header|prefix|endpoint|"
    r"env|var|key_id|_id|format|policy|regex|pattern|count|expir\w*|ttl|timeout|hint|placeholder|"
    r"input|error|message|msg|question|reset|confirm|strength|hash_alg\w*|algorithm)$"
)


_DOTTED_IDENT = re.compile(r"^[A-Za-z_]+(?:[.:/-][A-Za-z_]+)+$")
_TEMPLATED = re.compile(r"^[{%$<]|[}>]$")


def looks_random(value: str, min_entropy: float = 3.0) -> bool:
    if _PLACEHOLDER.search(value):
        return False
    if value.startswith(("http://", "https://", "/", "./", "../", "~")):
        return False
    if _DOTTED_IDENT.match(value):        # module paths / entry points like "pkg.cli:main"
        return False
    if len(set(value)) < 6:
        return False
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 2:
        return False
    return shannon_entropy(value) >= min_entropy


def _generic_ok(m: re.Match) -> bool:
    name = m.group(1)
    return not _NOT_SECRET_NAME.search(name) and looks_random(m.group(2))


def _env_ok(m: re.Match) -> bool:
    value = m.group(2)
    return not _PLACEHOLDER.search(value) and not _TEMPLATED.search(value) and len(set(value)) >= 4


def _db_ok(m: re.Match) -> bool:
    pw = m.group(2)
    return not _PLACEHOLDER.search(pw) and not _TEMPLATED.search(pw) and pw.lower() not in {"password", "pass", "pwd", "secret", "user", "postgres", "root", "admin"}


def _wif_ok(m: re.Match) -> bool:
    body = b58check_decode(m.group(1))
    return body is not None and body[0] in (0x80, 0xEF) and len(body) in (33, 34)


def _xprv_ok(m: re.Match) -> bool:
    body = b58check_decode(m.group(1))
    return body is not None and len(body) == 78


# Widely-published dev-chain keys (Hardhat/Anvil account #0). Flagged low: still worth knowing,
# but they are not *your* secret. Never send real funds to these.
KNOWN_TEST_KEYS = {
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",  # secretsweep:allow
}


def _evm_ok(m: re.Match) -> bool:
    hexkey = m.group(1).lower().removeprefix("0x")
    return len(set(hexkey)) > 8 and hexkey not in KNOWN_TEST_KEYS


def _seed_ok(m: re.Match) -> bool:
    words = m.group(1).split()
    return len(words) in (12, 15, 18, 21, 24) and len(set(words)) >= len(words) // 2


def _solana_ok(m: re.Match) -> bool:
    nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
    return len(nums) == 64 and all(n < 256 for n in nums) and len(set(nums)) > 20


# --------------------------------------------------------------------------- content rules

_ENV_FILE = re.compile(r"(^|/)\.env(\.[\w.-]+)?$|\.env$")
_ENV_TEMPLATE = re.compile(r"(?i)\.(example|sample|template|dist|defaults?)$")

R = re.compile
RULES: list[Rule] = [
    # Cloud
    Rule("aws-access-key-id", "AWS Access Key ID", "critical", R(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
         keywords=("akia", "asia", "abia", "acca"), env_name="AWS_ACCESS_KEY_ID",
         rotate="https://console.aws.amazon.com/iam/home#/security_credentials"),
    Rule("aws-secret-access-key", "AWS Secret Access Key", "critical",
         R(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?[\"'=:\s]\s*[\"']?(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
         keywords=("aws",), env_name="AWS_SECRET_ACCESS_KEY",
         rotate="https://console.aws.amazon.com/iam/home#/security_credentials"),
    Rule("gcp-api-key", "Google API Key", "high", R(r"\b(AIza[0-9A-Za-z\-_]{35})(?![0-9A-Za-z\-_])"),
         keywords=("aiza",), env_name="GOOGLE_API_KEY", rotate="https://console.cloud.google.com/apis/credentials"),
    Rule("gcp-service-account", "Google Service Account JSON", "critical",
         R(r"(\"type\"\s*:\s*\"service_account\")"), keywords=("service_account",), per_file=True,
         env_name="GOOGLE_APPLICATION_CREDENTIALS", rotate="https://console.cloud.google.com/iam-admin/serviceaccounts"),
    Rule("azure-storage-key", "Azure Storage Account Key", "critical", R(r"AccountKey=([A-Za-z0-9+/=]{86,88})"),
         keywords=("accountkey",), env_name="AZURE_STORAGE_CONNECTION_STRING", rotate="https://portal.azure.com/"),
    Rule("digitalocean-token", "DigitalOcean Token", "critical", R(r"\b(do[opr]_v1_[a-f0-9]{64})\b"),
         keywords=("_v1_",), env_name="DIGITALOCEAN_TOKEN", rotate="https://cloud.digitalocean.com/account/api/tokens"),
    # Code hosting / package registries
    Rule("github-token", "GitHub Token", "critical", R(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
         keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), env_name="GITHUB_TOKEN", rotate="https://github.com/settings/tokens"),
    Rule("github-fine-grained-pat", "GitHub Fine-grained PAT", "critical", R(r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"),
         keywords=("github_pat_",), env_name="GITHUB_TOKEN", rotate="https://github.com/settings/tokens?type=beta"),
    Rule("gitlab-token", "GitLab Token", "critical", R(r"\b(glpat-[A-Za-z0-9\-_]{20,})\b"),
         keywords=("glpat-",), env_name="GITLAB_TOKEN", rotate="https://gitlab.com/-/user_settings/personal_access_tokens"),
    Rule("npm-token", "npm Access Token", "critical", R(r"\b(npm_[A-Za-z0-9]{36})\b"),
         keywords=("npm_",), env_name="NPM_TOKEN", rotate="https://www.npmjs.com/settings/~/tokens"),
    Rule("pypi-token", "PyPI API Token", "critical", R(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})"),
         keywords=("pypi-",), env_name="PYPI_TOKEN", rotate="https://pypi.org/manage/account/token/"),
    # AI providers
    Rule("anthropic-key", "Anthropic API Key", "critical", R(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})"),
         keywords=("sk-ant-",), env_name="ANTHROPIC_API_KEY", rotate="https://console.anthropic.com/settings/keys"),
    Rule("openai-key", "OpenAI API Key", "critical",
         R(r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"),
         keywords=("sk-",), env_name="OPENAI_API_KEY", rotate="https://platform.openai.com/api-keys"),
    Rule("huggingface-token", "Hugging Face Token", "high", R(r"\b(hf_[A-Za-z]{34,40})\b"),
         keywords=("hf_",), env_name="HF_TOKEN", rotate="https://huggingface.co/settings/tokens"),
    # Payments / comms
    Rule("stripe-live-key", "Stripe Live Secret Key", "critical", R(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"),
         keywords=("_live_",), env_name="STRIPE_SECRET_KEY", rotate="https://dashboard.stripe.com/apikeys"),
    Rule("stripe-test-key", "Stripe Test Secret Key", "low", R(r"\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b"),
         keywords=("_test_",), env_name="STRIPE_SECRET_KEY", rotate="https://dashboard.stripe.com/test/apikeys"),
    Rule("square-token", "Square Access Token", "critical", R(r"\b(sq0atp-[0-9A-Za-z\-_]{22}|EAAA[0-9A-Za-z\-_]{60})\b"),
         keywords=("sq0atp-", "eaaa"), env_name="SQUARE_ACCESS_TOKEN", rotate="https://developer.squareup.com/apps"),
    Rule("shopify-token", "Shopify Access Token", "critical", R(r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b"),
         keywords=("shpat_", "shpca_", "shppa_", "shpss_"), env_name="SHOPIFY_ACCESS_TOKEN", rotate="https://admin.shopify.com/"),
    Rule("slack-token", "Slack Token", "critical", R(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b"),
         keywords=("xox",), env_name="SLACK_TOKEN", rotate="https://api.slack.com/apps"),
    Rule("slack-webhook", "Slack Webhook URL", "high",
         R(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"),
         keywords=("hooks.slack.com",), env_name="SLACK_WEBHOOK_URL", rotate="https://api.slack.com/apps"),
    Rule("discord-webhook", "Discord Webhook URL", "high",
         R(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)"),
         keywords=("discord",), env_name="DISCORD_WEBHOOK_URL", rotate="https://discord.com/developers/applications"),
    Rule("discord-bot-token", "Discord Bot Token", "critical",
         R(r"\b([MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38})\b"),
         keywords=("discord", "bot", "token"), env_name="DISCORD_BOT_TOKEN", rotate="https://discord.com/developers/applications"),
    Rule("telegram-bot-token", "Telegram Bot Token", "high", R(r"\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b"),
         keywords=(":aa",), env_name="TELEGRAM_BOT_TOKEN", rotate="https://t.me/BotFather"),
    Rule("twilio-api-key", "Twilio API Key", "high", R(r"\b(SK[0-9a-f]{32})\b"),
         keywords=("sk",), env_name="TWILIO_API_KEY", rotate="https://console.twilio.com/"),
    Rule("sendgrid-key", "SendGrid API Key", "critical", R(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"),
         keywords=("sg.",), env_name="SENDGRID_API_KEY", rotate="https://app.sendgrid.com/settings/api_keys"),
    Rule("mailgun-key", "Mailgun API Key", "high", R(r"\b(key-[0-9a-zA-Z]{32})\b"),
         keywords=("key-",), env_name="MAILGUN_API_KEY", rotate="https://app.mailgun.com/settings/api_security"),
    # Keys & credentials
    Rule("private-key", "Private Key (PEM/SSH/PGP)", "critical",
         R(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"),
         keywords=("private key",), env_name="PRIVATE_KEY", category="private-key", per_file=True,
         rotate="Generate a new key pair and revoke the old public key wherever it is trusted."),
    Rule("db-connection-string", "Database URL with password", "high",
         R(r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://[^\s:'\"/@]+:([^\s'\"@/]{3,})@[^\s'\"]+)"),
         group=2, keywords=("://",), validate=_db_ok, env_name="DATABASE_URL",
         rotate="Change the database user's password."),
    Rule("jwt", "JSON Web Token", "medium",
         R(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
         keywords=("eyj",), env_name="JWT_TOKEN", rotate="Revoke the token / rotate the signing secret that issued it."),
    # Crypto wallets
    Rule("evm-private-key", "Ethereum/EVM Private Key", "critical",
         R(r"(?i)(?:priv(?:ate)?[_\s-]?key|secret|wallet|signer|deployer|mnemonic|pk)\w*[\"']?\s*[:=]+\s*[\"']?((?:0x)?[a-fA-F0-9]{64})\b"),
         keywords=("priv", "secret", "wallet", "signer", "deployer", "pk"), validate=_evm_ok,
         env_name="WALLET_PRIVATE_KEY", category="crypto",
         rotate="Cannot be rotated: move all funds to a NEW wallet immediately."),
    Rule("evm-test-key", "Well-known dev-chain private key (Hardhat/Anvil)", "low",
         R(r"\b((?:0x)?(?:" + "|".join(KNOWN_TEST_KEYS) + r"))\b"),
         keywords=tuple(k[:12] for k in KNOWN_TEST_KEYS), env_name="WALLET_PRIVATE_KEY", category="crypto",
         rotate="Public test key: never use it on mainnet."),
    Rule("bitcoin-wif", "Bitcoin Private Key (WIF)", "critical", R(r"\b([5KLc9][1-9A-HJ-NP-Za-km-z]{50,51})\b"),
         validate=_wif_ok, env_name="BTC_PRIVATE_KEY", category="crypto",
         rotate="Cannot be rotated: move all funds to a NEW wallet immediately."),
    Rule("bip32-xprv", "BIP32 Extended Private Key (xprv)", "critical",
         R(r"\b([xyzt]prv[1-9A-HJ-NP-Za-km-z]{107,108})\b"), keywords=("prv",), validate=_xprv_ok,
         env_name="WALLET_XPRV", category="crypto",
         rotate="Cannot be rotated: move all funds from every derived address to a NEW wallet."),
    Rule("seed-phrase", "Wallet Seed / Mnemonic Phrase", "critical",
         R(r"(?i)(?:mnemonic|seed|recovery[_\s-]?phrase|secret[_\s-]?phrase|passphrase)\w*[\"']?\s*[:=]+\s*[\"'`]((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})[\"'`]"),
         keywords=("mnemonic", "seed", "phrase"), validate=_seed_ok, env_name="WALLET_MNEMONIC", category="crypto",
         rotate="Cannot be rotated: create a NEW wallet and move all funds immediately."),
    Rule("evm-keystore", "Encrypted Ethereum keystore (offline brute-forceable)", "high",
         R(r"(\"ciphertext\"\s*:\s*\"[0-9a-f]{64,}\")"), keywords=("ciphertext",), per_file=True,
         env_name="WALLET_KEYSTORE", category="crypto",
         rotate="Assume the password can be cracked: move funds to a NEW wallet."),
    Rule("solana-keypair", "Solana Keypair (64-byte array)", "critical",
         R(r"(\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\])"), keywords=(",",), validate=_solana_ok,
         env_name="SOLANA_KEYPAIR", category="crypto",
         rotate="Cannot be rotated: move all funds/authorities to a NEW keypair immediately."),
    # Generic fallbacks (only fire when no specific rule matched the same text)
    Rule("generic-secret", "Hardcoded secret assignment", "medium",
         R(r"(?i)\b([A-Za-z0-9_.-]*(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|auth[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)[A-Za-z0-9_.-]*)[\"']?\s*(?:=|:|:=|=>)\s*[\"'`]([^\"'`\s]{8,})[\"'`]"),
         group=2, name_group=1, keywords=("key", "secret", "token", "pass", "pwd"), validate=_generic_ok, generic=True,
         env_name="SECRET", category="generic", rotate="Revoke/rotate this credential with whoever issued it."),
    Rule("env-file-secret", "Secret in committed env file", "high",
         R(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|PWD|AUTH|CREDENTIALS?|PRIVATE|MNEMONIC|SEED|DSN)[A-Za-z0-9_]*)\s*=\s*[\"']?([^\"'\s]{6,})", re.I),
         group=2, name_group=1, keywords=("=",), validate=_env_ok, generic=True, path_filter=_ENV_FILE,
         env_name="SECRET", category="generic", rotate="Revoke/rotate this credential with whoever issued it."),
]

# --------------------------------------------------------------------------- file rules

FILE_RULES: list[FileRule] = [
    FileRule("env-file", "Committed .env file", "high", R(r"(^|/)\.env(\.[\w.-]+)?$|(^|/)[\w.-]+\.env$"),
             gitignore=".env", exclude=_ENV_TEMPLATE),
    FileRule("ssh-private-key", "SSH private key file", "critical", R(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$"), gitignore="id_*"),
    FileRule("pem-key-file", "Key/certificate bundle file", "high", R(r"(?i)\.(pem|key|p12|pfx|jks|keystore|ppk)$"),
             gitignore="*.{ext}", exclude=R(r"(?i)(public|pub|cert|ca|chain|fullchain)[\w.-]*\.pem$")),
    FileRule("crypto-wallet-file", "Crypto wallet file", "critical",
             R(r"(?i)(^|/)(wallet\.dat|UTC--[\w:.-]+--[0-9a-f]{40}(\.json)?|keystore/[\w.-]+\.json|[\w.-]*keypair\.json)$"),
             category="crypto", gitignore="", rotate="Cannot be rotated: move all funds to a NEW wallet immediately."),
    FileRule("credentials-file", "Credentials/config file", "high",
             R(r"(?i)(^|/)(\.npmrc|\.pypirc|\.netrc|_netrc|\.git-credentials|\.htpasswd|credentials(\.json)?|"
               r"service[-_]?account[\w.-]*\.json|client_secret[\w.-]*\.json|\.dockercfg|secrets?\.(ya?ml|json|toml))$"),
             gitignore=""),
    FileRule("terraform-state", "Terraform state (contains secrets in plain text)", "high",
             R(r"(^|/)[\w.-]*\.tfstate(\.backup)?$"), gitignore="*.tfstate*"),
    FileRule("password-db", "Password manager database", "critical", R(r"(?i)\.(kdbx?|1pif|agilekeychain)$"), gitignore="*.{ext}"),
]

# Paths we never content-scan (still checked by FILE_RULES).
SKIP_CONTENT = re.compile(
    r"(?i)(^|/)(node_modules|vendor|bower_components|\.git|dist|build|\.next|__pycache__|\.venv|venv|site-packages)/|"
    r"\.(min\.js|min\.css|map|lock|svg|png|jpe?g|gif|ico|webp|bmp|tiff?|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|"
    r"exe|dll|so|dylib|o|a|bin|woff2?|ttf|otf|eot|mp[34]|mov|avi|wav|flac|ogg|psd|ai|sketch|fig|ipynb_checkpoints)$|"
    r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock)$"
)

ALLOW_MARKERS = ("secretsweep:allow", "gitleaks:allow", "pragma: allowlist secret")


def match_file_rule(path: str) -> Optional[FileRule]:
    for fr in FILE_RULES:
        if fr.pattern.search(path) and not (fr.exclude and fr.exclude.search(path)):
            return fr
    return None


def gitignore_pattern(fr: FileRule, path: str) -> str:
    if fr.gitignore and "{ext}" in fr.gitignore:
        return fr.gitignore.replace("{ext}", path.rsplit(".", 1)[-1].lower())
    return fr.gitignore or "/" + path


@dataclass
class Match:
    rule: Rule
    secret: str
    start: int          # span of the secret in the line
    end: int
    var_name: Optional[str] = None
    extra: dict = field(default_factory=dict)


def scan_line(line: str, path: str = "") -> list[Match]:
    if len(line) > 4000:
        line = line[:4000]
    if any(marker in line for marker in ALLOW_MARKERS):
        return []
    lower = line.lower()
    found: list[Match] = []
    taken: list[tuple[int, int]] = []
    for rule in RULES:
        if rule.keywords and not any(k in lower for k in rule.keywords):
            continue
        if rule.path_filter is not None and not (rule.path_filter.search(path) and not _ENV_TEMPLATE.search(path)):
            continue
        for m in rule.pattern.finditer(line):
            if rule.validate and not rule.validate(m):
                continue
            s, e = m.span(rule.group)
            if rule.generic and any(s < te and ts < e for ts, te in taken):
                continue
            if any(s == ts and e == te for ts, te in taken):
                continue
            taken.append((s, e))
            found.append(Match(rule, m.group(rule.group), s, e,
                               m.group(rule.name_group) if rule.name_group else None))
    return found
