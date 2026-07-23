from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import math
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlparse, urlunparse

import aiohttp


@dataclass
class ReputationVerdict:
    item: str
    status: str = "unknown"  # clean | suspicious | malicious | unknown
    reasons: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    malicious_count: int = 0
    suspicious_count: int = 0
    checked: bool = False
    domain: str = ""
    sha256: str = ""

    @property
    def is_malicious(self) -> bool:
        return self.status == "malicious"

    @property
    def is_suspicious(self) -> bool:
        return self.status == "suspicious"

    @property
    def status_label(self) -> str:
        return {
            "clean": "✅ угроз не найдено",
            "suspicious": "⚠️ подозрительно",
            "malicious": "🚫 вредоносно",
            "unknown": "❔ не удалось подтвердить",
        }.get(self.status, self.status)


class SecurityScanner:
    """Checks URL/file reputation without visiting or executing user content."""

    SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v5/urls:search"
    VIRUSTOTAL_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{url_id}"
    VIRUSTOTAL_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files/{sha256}"

    SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at",
        "rebrand.ly", "tiny.one", "soo.gd", "buff.ly", "ow.ly",
    }
    OFFICIAL_DISCORD_DOMAINS = {
        "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discordcdn.com",
    }
    OFFICIAL_STEAM_DOMAINS = {
        "steampowered.com", "steamcommunity.com", "steamstatic.com",
    }
    SUSPICIOUS_KEYWORDS = {
        "nitro", "gift", "claim", "free", "login", "verify", "verification", "airdrop",
        "wallet", "bonus", "giveaway", "steamgift", "discordgift", "auth", "secure-account",
        "подарок", "бесплат", "проверка", "подтверд",
    }

    def __init__(self, settings_getter: Callable[[], dict[str, Any]]) -> None:
        self.settings_getter = settings_getter
        self._session: Optional[aiohttp.ClientSession] = None
        self._url_cache: dict[str, tuple[float, ReputationVerdict]] = {}
        self._file_cache: dict[str, tuple[float, ReputationVerdict]] = {}
        self._lock = asyncio.Lock()

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=8, connect=4)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": "Peach-Lounge-Security/2.0"},
            )
        return self._session

    @staticmethod
    def normalize_url(raw_url: str) -> Optional[str]:
        value = (raw_url or "").strip().rstrip(".,!?;:)]}>'\"")
        if not value:
            return None
        if value.lower().startswith("www."):
            value = "https://" + value
        try:
            parsed = urlparse(value)
        except ValueError:
            return None
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        try:
            host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError:
            return None
        if not host:
            return None
        try:
            port = parsed.port
        except ValueError:
            return None
        netloc = host
        if port and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
            netloc = f"{host}:{port}"
        path = parsed.path or "/"
        return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))

    @staticmethod
    def domain_matches(domain: str, configured: Iterable[str]) -> bool:
        domain = domain.lower().rstrip(".")
        for item in configured:
            candidate = str(item).lower().strip().lstrip(".").rstrip(".")
            if candidate and (domain == candidate or domain.endswith("." + candidate)):
                return True
        return False

    def trusted_domain(self, domain: str) -> bool:
        settings = self.settings_getter()
        trusted = settings.get("trusted_domains", [])
        return self.domain_matches(domain, trusted)

    def _heuristic_reasons(self, url: str) -> tuple[int, list[str]]:
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()
        try:
            parsed_port = parsed.port
        except ValueError:
            parsed_port = None
        full = f"{domain}{parsed.path}?{parsed.query}".lower()
        score = 0
        reasons: list[str] = []

        if parsed.scheme == "http":
            score += 8
            reasons.append("соединение без HTTPS")
        if "@" in parsed.netloc:
            score += 30
            reasons.append("в адресе скрыта переадресация через @")
        if "xn--" in domain:
            score += 22
            reasons.append("домен использует punycode и может имитировать другой сайт")
        try:
            ipaddress.ip_address(domain)
            score += 20
            reasons.append("вместо домена используется IP-адрес")
        except ValueError:
            pass
        if domain in self.SHORTENERS:
            score += 15
            reasons.append("сокращённая ссылка скрывает конечный адрес")
        if "discord" in domain and not self.domain_matches(domain, self.OFFICIAL_DISCORD_DOMAINS):
            score += 55
            reasons.append("домен похож на Discord, но не является официальным")
        if "steam" in domain and not self.domain_matches(domain, self.OFFICIAL_STEAM_DOMAINS):
            score += 45
            reasons.append("домен похож на Steam, но не является официальным")
        keyword_hits = sorted({word for word in self.SUSPICIOUS_KEYWORDS if word in full})
        if keyword_hits:
            score += min(25, 8 + len(keyword_hits) * 4)
            reasons.append("слова-приманки: " + ", ".join(keyword_hits[:5]))
        if domain.count(".") >= 4:
            score += 10
            reasons.append("слишком много уровней поддоменов")
        if len(url) > 180:
            score += 10
            reasons.append("необычно длинная ссылка")
        if parsed_port and parsed_port not in {80, 443}:
            score += 15
            reasons.append(f"нестандартный порт {parsed_port}")

        return min(score, 100), reasons

    @staticmethod
    def _duration_seconds(value: Any, default: int = 900) -> int:
        text = str(value or "").strip().lower()
        match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)s", text)
        if not match:
            return default
        return max(30, min(int(math.ceil(float(match.group(1)))), 86400))

    @classmethod
    def _safe_browsing_expression_matches(cls, requested_url: str, threat_url: str) -> bool:
        requested = cls.normalize_url(requested_url)
        threat = cls.normalize_url(threat_url)
        if requested is None:
            return False
        if threat is None and threat_url and "://" not in threat_url:
            threat = cls.normalize_url("http://" + threat_url.lstrip("/"))
        if threat is None:
            return False
        requested_parts = urlparse(requested)
        threat_parts = urlparse(threat)
        requested_host = (requested_parts.hostname or "").lower()
        threat_host = (threat_parts.hostname or "").lower()
        host_match = requested_host == threat_host or requested_host.endswith("." + threat_host)
        if not host_match:
            return False
        threat_path = threat_parts.path or "/"
        requested_path = requested_parts.path or "/"
        return requested_path.startswith(threat_path.rstrip("/") + "/") or requested_path == threat_path

    async def _safe_browsing_lookup(self, urls: list[str]) -> tuple[dict[str, list[str]], int, Optional[str]]:
        api_key = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
        if not api_key:
            return {}, 900, "Google Safe Browsing API key не настроен"
        session = await self._get_session()

        async def request_with(parameter_name: str) -> tuple[int, dict[str, Any]]:
            params: list[tuple[str, str]] = [("key", api_key)]
            params.extend((parameter_name, url) for url in urls[:50])
            async with session.get(self.SAFE_BROWSING_ENDPOINT, params=params) as response:
                try:
                    payload = await response.json(content_type=None)
                except ValueError:
                    payload = {}
                return response.status, payload

        try:
            status, payload = await request_with("urls")
            if status == 400:
                # Some REST clients expose repeated query fields with [] in the name.
                status, payload = await request_with("urls[]")
            if status != 200:
                return {}, 300, f"Google Safe Browsing HTTP {status}"
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {}, 300, f"Google Safe Browsing недоступен: {type(exc).__name__}"

        result: dict[str, list[str]] = {}
        for item in payload.get("threats", []) or []:
            matched_url = self.normalize_url(str(item.get("url", "")))
            if not matched_url:
                continue
            result[matched_url] = [str(x) for x in item.get("threatTypes", [])]
        ttl = self._duration_seconds(payload.get("cacheDuration"), default=900)
        return result, ttl, None

    async def _virustotal_url_lookup(self, url: str) -> tuple[Optional[dict[str, int]], Optional[str]]:
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if not api_key:
            return None, "VirusTotal API key не настроен"
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        session = await self._get_session()
        try:
            async with session.get(
                self.VIRUSTOTAL_URL_ENDPOINT.format(url_id=url_id),
                headers={"x-apikey": api_key},
            ) as response:
                if response.status == 404:
                    return None, "ссылка ещё не известна VirusTotal"
                if response.status != 200:
                    return None, f"VirusTotal HTTP {response.status}"
                payload = await response.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            return None, f"VirusTotal недоступен: {type(exc).__name__}"
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {str(k): int(v or 0) for k, v in stats.items()}, None

    async def scan_urls(self, raw_urls: Iterable[str]) -> list[ReputationVerdict]:
        settings = self.settings_getter()
        max_urls = max(1, min(int(settings.get("max_reputation_urls_per_message", 5)), 20))
        urls: list[str] = []
        for raw in raw_urls:
            normalized = self.normalize_url(raw)
            if normalized and normalized not in urls:
                urls.append(normalized)
            if len(urls) >= max_urls:
                break
        if not urls:
            return []

        now = time.time()
        results: dict[str, ReputationVerdict] = {}
        missing: list[str] = []
        for url in urls:
            cached = self._url_cache.get(url)
            if cached and cached[0] > now:
                results[url] = cached[1]
            else:
                missing.append(url)

        if missing:
            sb_matches, sb_ttl, sb_error = await self._safe_browsing_lookup(missing)
            vt_enabled = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip()) and bool(
                settings.get("virustotal_url_lookup", True)
            )
            for url in missing:
                parsed = urlparse(url)
                score, heuristic_reasons = self._heuristic_reasons(url)
                verdict = ReputationVerdict(item=url, domain=(parsed.hostname or "").lower())
                verdict.reasons.extend(heuristic_reasons)

                matched_threats: list[str] = []
                for threat_url, threat_types in sb_matches.items():
                    if self._safe_browsing_expression_matches(url, threat_url):
                        matched_threats.extend(threat_types)
                matched_threats = sorted(set(matched_threats))
                if matched_threats:
                    verdict.status = "malicious"
                    verdict.checked = True
                    verdict.providers.append("Google Safe Browsing")
                    verdict.reasons.insert(0, "Google Safe Browsing: " + ", ".join(matched_threats))
                elif not sb_error:
                    verdict.checked = True
                    verdict.providers.append("Google Safe Browsing")

                vt_stats: Optional[dict[str, int]] = None
                vt_error: Optional[str] = None
                if vt_enabled:
                    vt_stats, vt_error = await self._virustotal_url_lookup(url)
                if vt_stats is not None:
                    verdict.checked = True
                    verdict.providers.append("VirusTotal")
                    verdict.malicious_count = int(vt_stats.get("malicious", 0))
                    verdict.suspicious_count = int(vt_stats.get("suspicious", 0))
                    vt_threshold = max(1, int(settings.get("virustotal_malicious_threshold", 2)))
                    if verdict.malicious_count >= vt_threshold:
                        verdict.status = "malicious"
                        verdict.reasons.insert(
                            0,
                            f"VirusTotal: {verdict.malicious_count} детектов вредоносности",
                        )
                    elif verdict.malicious_count or verdict.suspicious_count:
                        if verdict.status != "malicious":
                            verdict.status = "suspicious"
                        verdict.reasons.insert(
                            0,
                            f"VirusTotal: malicious={verdict.malicious_count}, suspicious={verdict.suspicious_count}",
                        )
                elif vt_error and vt_enabled:
                    verdict.reasons.append(vt_error)

                if verdict.status not in {"malicious", "suspicious"}:
                    suspicious_threshold = max(1, int(settings.get("local_suspicious_score", 35)))
                    if score >= suspicious_threshold:
                        verdict.status = "suspicious"
                    elif verdict.checked:
                        verdict.status = "clean"
                    else:
                        verdict.status = "unknown"
                        if sb_error:
                            verdict.reasons.append(sb_error)

                if not verdict.reasons:
                    verdict.reasons.append("репутационные сервисы не нашли признаков угрозы")

                ttl = sb_ttl if verdict.checked else 300
                if verdict.status == "malicious":
                    ttl = min(ttl, 1800)
                self._url_cache[url] = (now + ttl, verdict)
                results[url] = verdict

        return [results[url] for url in urls if url in results]

    async def _virustotal_file_lookup(self, sha256: str) -> tuple[Optional[dict[str, int]], Optional[str]]:
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if not api_key:
            return None, "VirusTotal API key не настроен"
        session = await self._get_session()
        try:
            async with session.get(
                self.VIRUSTOTAL_FILE_ENDPOINT.format(sha256=sha256),
                headers={"x-apikey": api_key},
            ) as response:
                if response.status == 404:
                    return None, "файл ещё не известен VirusTotal"
                if response.status != 200:
                    return None, f"VirusTotal HTTP {response.status}"
                payload = await response.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            return None, f"VirusTotal недоступен: {type(exc).__name__}"
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {str(k): int(v or 0) for k, v in stats.items()}, None

    async def scan_attachment(self, attachment: Any) -> ReputationVerdict:
        name = str(getattr(attachment, "filename", "attachment"))
        size = int(getattr(attachment, "size", 0) or 0)
        verdict = ReputationVerdict(item=name)
        settings = self.settings_getter()
        max_bytes = max(1, int(settings.get("attachment_scan_max_mb", 20))) * 1024 * 1024
        if size > max_bytes:
            verdict.status = "unknown"
            verdict.reasons.append(f"файл больше лимита проверки ({size / 1024 / 1024:.1f} МБ)")
            return verdict
        try:
            data = await attachment.read(use_cached=True)
        except Exception as exc:  # Discord may raise several HTTP exceptions here.
            verdict.status = "unknown"
            verdict.reasons.append(f"не удалось прочитать вложение: {type(exc).__name__}")
            return verdict

        sha256 = hashlib.sha256(data).hexdigest()
        verdict.sha256 = sha256
        now = time.time()
        cached = self._file_cache.get(sha256)
        if cached and cached[0] > now:
            cached_verdict = cached[1]
            return ReputationVerdict(
                item=name,
                status=cached_verdict.status,
                reasons=list(cached_verdict.reasons),
                providers=list(cached_verdict.providers),
                malicious_count=cached_verdict.malicious_count,
                suspicious_count=cached_verdict.suspicious_count,
                checked=cached_verdict.checked,
                sha256=sha256,
            )

        stats, error = await self._virustotal_file_lookup(sha256)
        if stats is None:
            verdict.status = "unknown"
            verdict.reasons.append(error or "нет результата проверки")
            self._file_cache[sha256] = (now + 300, verdict)
            return verdict

        verdict.checked = True
        verdict.providers.append("VirusTotal")
        verdict.malicious_count = int(stats.get("malicious", 0))
        verdict.suspicious_count = int(stats.get("suspicious", 0))
        threshold = max(1, int(settings.get("virustotal_malicious_threshold", 2)))
        if verdict.malicious_count >= threshold:
            verdict.status = "malicious"
            verdict.reasons.append(f"VirusTotal: {verdict.malicious_count} детектов вредоносности")
        elif verdict.malicious_count or verdict.suspicious_count:
            verdict.status = "suspicious"
            verdict.reasons.append(
                f"VirusTotal: malicious={verdict.malicious_count}, suspicious={verdict.suspicious_count}"
            )
        else:
            verdict.status = "clean"
            verdict.reasons.append("VirusTotal не обнаружил угрозу в известном отчёте")
        self._file_cache[sha256] = (now + 3600, verdict)
        return verdict
