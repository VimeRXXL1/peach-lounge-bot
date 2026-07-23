import asyncio
import io
import json
import math
import os
import random
import re
import sqlite3
import subprocess
import time
import urllib.request
import urllib.error
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional

import discord
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv
from PIL import Image, ImageDraw, ImageFilter, ImageFont

from security import ReputationVerdict, SecurityScanner

CONFIG_PATH = Path("config.json")

ANTISPAM_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "log_channel_id": 0,
    "alert_role_id": 0,
    "alert_role_ids": [],
    "timeout_minutes": 60,
    "delete_recent_messages": True,
    "cleanup_window_seconds": 90,
    "cleanup_message_limit": 25,
    "action_cooldown_seconds": 20,
    "max_messages": 6,
    "message_window_seconds": 8,
    "max_duplicate_messages": 3,
    "duplicate_window_seconds": 35,
    "max_mentions": 5,
    "max_links_per_message": 4,
    "max_same_link_messages": 3,
    "link_repeat_window_seconds": 45,
    "cross_channel_messages": 4,
    "cross_channel_count": 3,
    "cross_channel_window_seconds": 12,
    "block_dangerous_attachments": False,
    "suspicious_link_filter": False,
    "link_reputation_enabled": True,
    "alert_on_external_link": True,
    "link_alert_cooldown_seconds": 60,
    "auto_delete_malicious_links": True,
    "max_reputation_urls_per_message": 5,
    "virustotal_url_lookup": True,
    "virustotal_malicious_threshold": 2,
    "local_suspicious_score": 35,
    "trusted_domains": [
        "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discordcdn.com"
    ],
    "review_attachment_extensions": [
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".ps1", ".vbs", ".lnk",
        ".jar", ".apk", ".zip", ".rar", ".7z"
    ],
    "attachment_scan_max_mb": 20,
    "auto_delete_malicious_attachments": True,
    "voice_hop_protection": True,
    "voice_hop_max_events": 6,
    "voice_hop_window_seconds": 30,
    "voice_hop_timeout_minutes": 10,
    "disconnect_voice_spammer": True,
    "dm_user": True,
    "ignored_channel_ids": [],
    "ignored_role_ids": [],
    "ignored_user_ids": [],
}

DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".ps1", ".vbs", ".lnk"
}

SUSPICIOUS_LINK_PHRASES = (
    "free nitro",
    "discord nitro gift",
    "nitro for free",
    "steam gift",
    "free steam",
    "gift inventory",
    "crypto giveaway",
    "test my game",
    "playtest my game",
    "бесплатный нитро",
    "нитро бесплатно",
    "подарок стим",
    "подарок steam",
    "скачай мою игру",
    "протестируй мою игру",
)

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>]+")


# ------------------------- CONFIG -------------------------

def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            "Файл config.json не найден. Скопируй config.example.json в config.json и настрой сервер."
        )
    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_config(config: dict[str, Any]) -> None:
    with CONFIG_PATH.open("w", encoding="utf-8") as file:
        json.dump(config, file, ensure_ascii=False, indent=2)


def parse_hex_color(value: str, default: tuple[int, int, int] = (88, 101, 242)) -> tuple[int, int, int]:
    value = str(value).strip().lstrip("#")
    if len(value) != 6:
        return default
    try:
        return tuple(int(value[i : i + 2], 16) for i in (0, 2, 4))
    except ValueError:
        return default


def parse_discord_color(value: str) -> discord.Color:
    return discord.Color.from_rgb(*parse_hex_color(value))


def format_duration_minutes(total_minutes: int) -> str:
    hours = total_minutes // 60
    minutes = total_minutes % 60
    days = hours // 24
    hours = hours % 24
    parts = []
    if days:
        parts.append(f"{days}д")
    if hours:
        parts.append(f"{hours}ч")
    parts.append(f"{minutes}м")
    return " ".join(parts)


def get_role_categories(config: dict[str, Any]) -> list[dict[str, Any]]:
    categories = config.get("role_categories")
    if isinstance(categories, list) and categories:
        return categories

    old_buttons = config.get("role_buttons", [])
    if isinstance(old_buttons, list) and old_buttons:
        return [
            {
                "name": "Выбор ролей",
                "placeholder": "Выбери роли",
                "selection_mode": "toggle",
                "roles": old_buttons,
            }
        ]
    return []


def safe_role_id(role_config: dict[str, Any]) -> int:
    try:
        return int(role_config.get("role_id", 0) or 0)
    except (TypeError, ValueError):
        return 0


def build_role_display_map(config: dict[str, Any]) -> dict[int, str]:
    """Красивые названия ролей для карточки профиля: берём emoji/label из config.json."""
    result: dict[int, str] = {}

    for category in get_role_categories(config):
        for role_cfg in category.get("roles", []):
            if not isinstance(role_cfg, dict):
                continue
            role_id = safe_role_id(role_cfg)
            if role_id <= 0:
                continue
            label = str(role_cfg.get("label", "Роль")).strip()
            emoji = str(role_cfg.get("emoji", "")).strip()
            result[role_id] = f"{emoji}・{label}" if emoji and not label.startswith(emoji) else label

    for item in config.get("leveling", {}).get("level_roles", []):
        if not isinstance(item, dict):
            continue
        role_id = safe_role_id(item)
        if role_id <= 0:
            continue
        label = str(item.get("label", "")).strip()
        if not label:
            level = int(item.get("level", 0) or 0)
            emoji = str(item.get("emoji", "⭐")).strip()
            label = f"{emoji}・{level} Level"
        result[role_id] = label

    return result


def truncate_text(value: str, max_chars: int) -> str:
    value = str(value)
    return value if len(value) <= max_chars else value[: max_chars - 1] + "…"


def draw_text_with_shadow(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    text_value: str,
    font: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    fill: tuple[int, int, int, int] = (255, 255, 255, 255),
    shadow: tuple[int, int, int, int] = (0, 0, 0, 120),
) -> None:
    x, y = xy
    draw.text((x + 2, y + 2), text_value, font=font, fill=shadow)
    draw.text((x, y), text_value, font=font, fill=fill)


# Emoji rendering for profile cards.
# On many Linux hosts Pillow can draw Cyrillic after our font fix, but not colored emoji.
# These helpers render emoji as small Twemoji PNGs cached in data/emoji_cache.
EMOJI_RE = re.compile(
    r"[\U0001F1E6-\U0001F1FF]{2}|"
    r"[\U0001F300-\U0001FAFF]\ufe0f?(?:\u200d[\U0001F300-\U0001FAFF]\ufe0f?)*|"
    r"[\u2600-\u27BF]\ufe0f?"
)
TWEMOJI_BASE_URL = "https://cdn.jsdelivr.net/gh/twitter/twemoji@14.0.2/assets/72x72"


def _emoji_codepoint(emoji_text: str) -> str:
    # Twemoji filenames usually do not include variation selectors FE0E/FE0F.
    return "-".join(f"{ord(ch):x}" for ch in emoji_text if ch not in ("\ufe0e", "\ufe0f")).lower()


def _emoji_cache_path(emoji_text: str) -> Path:
    cache_dir = Path("data") / "emoji_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"{_emoji_codepoint(emoji_text)}.png"


def _download_emoji(emoji_text: str) -> Optional[Path]:
    path = _emoji_cache_path(emoji_text)
    if path.exists() and path.stat().st_size > 0:
        return path

    codepoint = _emoji_codepoint(emoji_text)
    url = f"{TWEMOJI_BASE_URL}/{codepoint}.png"
    try:
        with urllib.request.urlopen(url, timeout=4) as response:
            data = response.read()
        if data:
            path.write_bytes(data)
            return path
    except Exception:
        return None
    return None


def _load_emoji_image(emoji_text: str, size: int) -> Optional[Image.Image]:
    path = _download_emoji(emoji_text)
    if path is None:
        return None
    try:
        return Image.open(path).convert("RGBA").resize((size, size), Image.LANCZOS)
    except Exception:
        return None


def _font_px(font: ImageFont.FreeTypeFont | ImageFont.ImageFont) -> int:
    return int(getattr(font, "size", 18) or 18)


def _plain_text_size(draw: ImageDraw.ImageDraw, value: str, font: ImageFont.FreeTypeFont | ImageFont.ImageFont) -> tuple[int, int]:
    if not value:
        return 0, _font_px(font)
    bbox = draw.textbbox((0, 0), value, font=font)
    return bbox[2] - bbox[0], bbox[3] - bbox[1]


def rich_text_size(draw: ImageDraw.ImageDraw, value: str, font: ImageFont.FreeTypeFont | ImageFont.ImageFont) -> tuple[int, int]:
    value = str(value)
    emoji_size = max(16, int(_font_px(font) * 1.12))
    total_w = 0
    max_h = emoji_size

    pos = 0
    for match in EMOJI_RE.finditer(value):
        if match.start() > pos:
            w, h = _plain_text_size(draw, value[pos:match.start()], font)
            total_w += w
            max_h = max(max_h, h)
        total_w += emoji_size + 2
        max_h = max(max_h, emoji_size)
        pos = match.end()

    if pos < len(value):
        w, h = _plain_text_size(draw, value[pos:], font)
        total_w += w
        max_h = max(max_h, h)

    return int(total_w), int(max_h)


def draw_rich_text(
    image: Image.Image,
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    value: str,
    font: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    fill: tuple[int, int, int, int] = (255, 255, 255, 255),
) -> None:
    value = str(value)
    x, y = xy
    start_x = x
    emoji_size = max(16, int(_font_px(font) * 1.12))
    _, text_h = _plain_text_size(draw, "Ag", font)
    emoji_y = y + max(0, (text_h - emoji_size) // 2)

    pos = 0
    for match in EMOJI_RE.finditer(value):
        if match.start() > pos:
            chunk = value[pos:match.start()]
            draw.text((x, y), chunk, font=font, fill=fill)
            w, _ = _plain_text_size(draw, chunk, font)
            x += w

        emoji_text = match.group(0)
        emoji_image = _load_emoji_image(emoji_text, emoji_size)
        if emoji_image is not None:
            image.alpha_composite(emoji_image, (int(x), int(emoji_y)))
        else:
            # No internet/CDN/font: draw a neutral small badge instead of a broken square.
            draw.rounded_rectangle(
                (x, emoji_y + 2, x + emoji_size, emoji_y + emoji_size + 2),
                radius=max(4, emoji_size // 4),
                fill=(255, 255, 255, 42),
                outline=(255, 255, 255, 90),
                width=1,
            )
        x += emoji_size + 2
        pos = match.end()

    if pos < len(value):
        chunk = value[pos:]
        draw.text((x, y), chunk, font=font, fill=fill)


DECORATION_CHARS = "╰╭╯╮┃│┊┆┋├┤└┘┌┐─━︱・»«›‹｜|"


def clean_display_value(value: str, max_chars: int = 14) -> str:
    """Убирает декоративные символы Discord-каналов, которые часто ломают шрифт в PNG."""
    value = EMOJI_RE.sub("", str(value))
    for char in DECORATION_CHARS:
        value = value.replace(char, " ")
    value = " ".join(value.split()).strip()
    return truncate_text(value or "Комната", max_chars)


def get_currency_symbol() -> str:
    currency = bot.config.get("currency", {}) if "bot" in globals() else {}
    return str(currency.get("symbol", "🍑"))


def draw_currency_icon(image: Image.Image, draw: ImageDraw.ImageDraw, center: tuple[int, int], radius: int = 18) -> None:
    x, y = center
    # base coin
    draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=(95, 170, 220, 82), outline=(190, 230, 255, 105), width=2)
    symbol = get_currency_symbol()
    emoji_img = _load_emoji_image(symbol, max(18, radius + 8)) if symbol else None
    if emoji_img is not None:
        image.alpha_composite(emoji_img, (x - emoji_img.width // 2, y - emoji_img.height // 2))
        return
    # vector fallback: stylized peach/token mark
    draw.arc((x - 9, y - 11, x + 8, y + 11), start=80, end=290, fill=(225, 245, 255, 230), width=3)
    draw.line((x + 2, y - 12, x + 10, y - 18), fill=(160, 235, 190, 220), width=3)
    draw.ellipse((x + 7, y - 21, x + 17, y - 13), fill=(120, 235, 170, 210))


def draw_profile_icon(image: Image.Image, draw: ImageDraw.ImageDraw, kind: str, box: tuple[int, int, int, int]) -> None:
    """Векторные иконки без зависимости от emoji-шрифтов."""
    x1, y1, x2, y2 = box
    cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
    w, h = x2 - x1, y2 - y1
    if kind == "location":
        draw.ellipse((cx - 5, cy - 12, cx + 5, cy - 2), fill=(255, 80, 110, 230))
        draw.polygon([(cx, cy + 12), (cx - 7, cy - 2), (cx + 7, cy - 2)], fill=(255, 80, 110, 210))
        draw.ellipse((cx - 2, cy - 9, cx + 2, cy - 5), fill=(255, 235, 240, 235))
    elif kind == "mic":
        draw.rounded_rectangle((cx - 5, cy - 14, cx + 5, cy + 4), radius=5, fill=(170, 220, 255, 230))
        draw.arc((cx - 12, cy - 4, cx + 12, cy + 15), start=0, end=180, fill=(170, 220, 255, 210), width=3)
        draw.line((cx, cy + 15, cx, cy + 22), fill=(170, 220, 255, 210), width=3)
    elif kind == "star":
        pts = []
        for i in range(10):
            r = 13 if i % 2 == 0 else 6
            a = -1.57 + i * 3.14159 / 5
            pts.append((cx + int(r * math.cos(a)), cy + int(r * math.sin(a))))
        draw.polygon(pts, fill=(180, 220, 255, 230))
    elif kind == "heart":
        draw.ellipse((cx - 13, cy - 10, cx - 1, cy + 2), fill=(110, 195, 255, 230))
        draw.ellipse((cx + 1, cy - 10, cx + 13, cy + 2), fill=(110, 195, 255, 230))
        draw.polygon([(cx - 14, cy - 2), (cx + 14, cy - 2), (cx, cy + 16)], fill=(110, 195, 255, 230))
    elif kind == "achievement":
        draw.polygon([(cx, cy - 16), (cx - 15, cy - 4), (cx - 9, cy + 15), (cx + 9, cy + 15), (cx + 15, cy - 4)], fill=(110, 165, 255, 210))
        draw.ellipse((cx - 7, cy - 7, cx + 7, cy + 7), fill=(255, 210, 90, 235))
    elif kind == "pair":
        draw.ellipse((cx - 13, cy - 11, cx - 2, cy), fill=(255, 85, 120, 220))
        draw.ellipse((cx + 2, cy - 11, cx + 13, cy), fill=(255, 85, 120, 220))
        draw.polygon([(cx - 14, cy - 2), (cx + 14, cy - 2), (cx, cy + 16)], fill=(255, 85, 120, 220))
        draw.ellipse((cx + 9, cy - 18, cx + 18, cy - 9), fill=(255, 175, 195, 220))
    elif kind == "clan":
        draw.polygon([(cx, cy - 17), (cx - 15, cy - 7), (cx - 10, cy + 14), (cx + 10, cy + 14), (cx + 15, cy - 7)], fill=(185, 135, 255, 210))
        draw.ellipse((cx - 6, cy - 5, cx + 6, cy + 7), fill=(120, 255, 160, 170))
    else:
        draw.ellipse((cx - 12, cy - 12, cx + 12, cy + 12), fill=(180, 220, 255, 190))


def draw_profile_art(image: Image.Image, draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], theme: str, colors: list[str]) -> None:
    """Красивая мини-иллюстрация справа вместо технического символа."""
    x1, y1, x2, y2 = box
    w, h = x2 - x1, y2 - y1
    art = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ad = ImageDraw.Draw(art)
    c1 = parse_hex_color(colors[0] if colors else "#111827")
    c2 = parse_hex_color(colors[-1] if colors else "#7aa2ff")
    # gradient
    for yy in range(h):
        ratio = yy / max(h - 1, 1)
        col = tuple(int(c1[i] * (1 - ratio) + c2[i] * ratio) for i in range(3))
        ad.line((0, yy, w, yy), fill=(*col, 190))
    rng = random.Random(str(theme) + str(colors))
    # stars/particles
    for _ in range(45):
        px, py = rng.randint(5, w - 5), rng.randint(5, h - 5)
        r = rng.choice([1, 1, 2])
        ad.ellipse((px - r, py - r, px + r, py + r), fill=(255, 255, 255, rng.randint(45, 130)))
    theme = str(theme).lower()
    if any(k in theme for k in ["forest", "mountain", "nature"]):
        # moon + mountains + trees
        ad.ellipse((w - 85, 24, w - 35, 74), fill=(240, 250, 255, 150))
        for base, alpha in [(0.67, 170), (0.78, 150), (0.9, 130)]:
            pts = [(0, h)]
            for i in range(0, w + 60, 60):
                pts.append((i, int(h * base + rng.randint(-25, 25))))
            pts.append((w, h))
            ad.polygon(pts, fill=(18, 70, 55, alpha))
    elif any(k in theme for k in ["sakura", "anime"]):
        ad.ellipse((w - 88, 18, w - 28, 78), fill=(255, 235, 245, 150))
        ad.line((58, 30, 28, h - 15), fill=(95, 45, 65, 230), width=9)
        for off in range(0, 70, 18):
            ad.line((58, 75 + off, 150 + off, 45 + off), fill=(110, 55, 80, 210), width=5)
        for _ in range(90):
            px, py = rng.randint(0, w), rng.randint(0, h)
            ad.ellipse((px, py, px + 6, py + 3), fill=(255, 180, 215, rng.randint(80, 170)))
    elif any(k in theme for k in ["ocean", "water"]):
        ad.ellipse((w - 96, 18, w - 26, 88), fill=(230, 255, 255, 95))
        for wave in range(6):
            yy = int(h * 0.54 + wave * 24)
            pts = [(0, h)]
            for xx in range(0, w + 20, 20):
                pts.append((xx, yy + int(math.sin(xx / 42 + wave) * 8)))
            pts.append((w, h))
            ad.polygon(pts, fill=(40, 130 + wave * 12, 190 + wave * 8, 80))
    elif any(k in theme for k in ["fox", "wolf", "panda", "animal"]):
        # stylized animal silhouette
        ad.ellipse((w // 2 - 55, h // 2 - 38, w // 2 + 55, h // 2 + 58), fill=(20, 24, 34, 180))
        ad.polygon([(w//2-48,h//2-25),(w//2-25,h//2-75),(w//2-5,h//2-28)], fill=(20,24,34,185))
        ad.polygon([(w//2+48,h//2-25),(w//2+25,h//2-75),(w//2+5,h//2-28)], fill=(20,24,34,185))
        ad.ellipse((w//2-26,h//2-3,w//2-16,h//2+7), fill=(210,230,255,170))
        ad.ellipse((w//2+16,h//2-3,w//2+26,h//2+7), fill=(210,230,255,170))
        ad.polygon([(w//2-7,h//2+18),(w//2+7,h//2+18),(w//2,h//2+28)], fill=(255,190,170,160))
    else:
        # peach/neon orb illustration
        cx, cy = w // 2, h // 2
        accent = c2
        for r, a in [(95, 18), (72, 25), (52, 32)]:
            ad.ellipse((cx-r, cy-r, cx+r, cy+r), fill=(*accent, a))
        ad.ellipse((cx - 50, cy - 48, cx + 42, cy + 52), fill=(255, 155, 185, 50), outline=(255, 210, 225, 140), width=3)
        ad.line((cx + 14, cy - 52, cx + 48, cy - 82), fill=(130, 255, 180, 130), width=5)
        ad.ellipse((cx + 38, cy - 88, cx + 78, cy - 58), fill=(100, 240, 165, 105))
    # glass vignette, rounded mask
    art.alpha_composite(Image.new("RGBA", (w, h), (0, 0, 0, 45)))
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, w, h), radius=24, fill=255)
    image.paste(art, (x1, y1), mask)
    draw.rounded_rectangle(box, radius=24, outline=(255, 255, 255, 25), width=1)


def draw_achievement_symbol(image: Image.Image, draw: ImageDraw.ImageDraw, xy: tuple[int, int], done: bool = False) -> None:
    x, y = xy
    color = (255, 215, 90, 230) if done else (120, 170, 255, 210)
    draw.polygon([(x + 24, y), (x + 4, y + 15), (x + 11, y + 41), (x + 37, y + 41), (x + 44, y + 15)], fill=color)
    draw.ellipse((x + 15, y + 12, x + 33, y + 30), fill=(255, 255, 255, 95))
# ------------------------- DATABASE -------------------------
class Database:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.setup()

    def _column_exists(self, table: str, column: str) -> bool:
        rows = self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        return any(row[1] == column for row in rows)

    def setup(self) -> None:
        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    xp INTEGER NOT NULL DEFAULT 0,
                    level INTEGER NOT NULL DEFAULT 0,
                    balance INTEGER NOT NULL DEFAULT 0,
                    background TEXT NOT NULL DEFAULT 'default',
                    voice_minutes INTEGER NOT NULL DEFAULT 0,
                    message_count INTEGER NOT NULL DEFAULT 0,
                    case_opened INTEGER NOT NULL DEFAULT 0,
                    daily_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (guild_id, user_id)
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS purchases (
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    item_type TEXT NOT NULL,
                    item_key TEXT NOT NULL,
                    purchased_at INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, user_id, item_type, item_key)
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS warnings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    moderator_id INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS relationships (
                    guild_id INTEGER NOT NULL,
                    user1_id INTEGER NOT NULL,
                    user2_id INTEGER NOT NULL,
                    relation_type TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, user1_id, user2_id, relation_type)
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    amount INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS voice_channel_stats (
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    channel_id INTEGER NOT NULL,
                    minutes INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (guild_id, user_id, channel_id)
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS profile_items (
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    item_type TEXT NOT NULL,
                    item_key TEXT NOT NULL,
                    equipped INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, user_id, item_type, item_key)
                )
                """
            )

        user_extra_columns = {
            "voice_minutes": "ALTER TABLE users ADD COLUMN voice_minutes INTEGER NOT NULL DEFAULT 0",
            "message_count": "ALTER TABLE users ADD COLUMN message_count INTEGER NOT NULL DEFAULT 0",
            "case_opened": "ALTER TABLE users ADD COLUMN case_opened INTEGER NOT NULL DEFAULT 0",
            "daily_count": "ALTER TABLE users ADD COLUMN daily_count INTEGER NOT NULL DEFAULT 0",
        }
        with self.conn:
            for column, sql in user_extra_columns.items():
                if not self._column_exists("users", column):
                    self.conn.execute(sql)

    def ensure_user(self, guild_id: int, user_id: int) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO users (guild_id, user_id) VALUES (?, ?)",
                (guild_id, user_id),
            )

    def get_user(self, guild_id: int, user_id: int) -> dict[str, Any]:
        self.ensure_user(guild_id, user_id)
        row = self.conn.execute(
            "SELECT * FROM users WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id),
        ).fetchone()
        return dict(row)

    def add_transaction(self, guild_id: int, user_id: int, amount: int, category: str, reason: str) -> None:
        self.ensure_user(guild_id, user_id)
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO transactions (guild_id, user_id, amount, category, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (guild_id, user_id, int(amount), str(category)[:60], str(reason)[:240], int(time.time())),
            )

    def get_transactions(self, guild_id: int, user_id: int, limit: int = 30) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT * FROM transactions
            WHERE guild_id = ? AND user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (guild_id, user_id, int(limit)),
        ).fetchall()
        return [dict(row) for row in rows]

    def transaction_summary(self, guild_id: int, user_id: int) -> dict[str, Any]:
        rows = self.conn.execute(
            """
            SELECT category,
                   SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) AS income,
                   SUM(CASE WHEN amount < 0 THEN -amount ELSE 0 END) AS expense
            FROM transactions
            WHERE guild_id = ? AND user_id = ?
            GROUP BY category
            """,
            (guild_id, user_id),
        ).fetchall()
        total_income = sum(int(row["income"] or 0) for row in rows)
        total_expense = sum(int(row["expense"] or 0) for row in rows)
        return {
            "rows": [dict(row) for row in rows],
            "total_income": total_income,
            "total_expense": total_expense,
            "turnover": total_income + total_expense,
        }

    def add_voice_reward(
        self,
        guild_id: int,
        user_id: int,
        xp: int,
        coins: int,
        minutes: int,
        new_level: int,
        channel_id: Optional[int] = None,
    ) -> dict[str, Any]:
        self.ensure_user(guild_id, user_id)
        with self.conn:
            self.conn.execute(
                """
                UPDATE users
                SET xp = xp + ?,
                    balance = balance + ?,
                    voice_minutes = voice_minutes + ?,
                    level = ?
                WHERE guild_id = ? AND user_id = ?
                """,
                (xp, coins, minutes, new_level, guild_id, user_id),
            )
            if channel_id is not None and minutes > 0:
                self.conn.execute(
                    """
                    INSERT INTO voice_channel_stats (guild_id, user_id, channel_id, minutes)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(guild_id, user_id, channel_id)
                    DO UPDATE SET minutes = minutes + excluded.minutes
                    """,
                    (guild_id, user_id, int(channel_id), int(minutes)),
                )
        if coins:
            self.add_transaction(guild_id, user_id, coins, "voice", f"Голосовой онлайн: {minutes} мин.")
        return self.get_user(guild_id, user_id)

    def add_balance(self, guild_id: int, user_id: int, amount: int, category: str = "manual", reason: str = "Изменение баланса") -> dict[str, Any]:
        self.ensure_user(guild_id, user_id)
        with self.conn:
            self.conn.execute(
                "UPDATE users SET balance = MAX(balance + ?, 0) WHERE guild_id = ? AND user_id = ?",
                (amount, guild_id, user_id),
            )
        if amount:
            self.add_transaction(guild_id, user_id, amount, category, reason)
        return self.get_user(guild_id, user_id)

    def set_background(self, guild_id: int, user_id: int, background: str) -> None:
        self.ensure_user(guild_id, user_id)
        with self.conn:
            self.conn.execute(
                "UPDATE users SET background = ? WHERE guild_id = ? AND user_id = ?",
                (background, guild_id, user_id),
            )

    def has_purchase(self, guild_id: int, user_id: int, item_type: str, item_key: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM purchases WHERE guild_id = ? AND user_id = ? AND item_type = ? AND item_key = ?",
            (guild_id, user_id, item_type, item_key),
        ).fetchone()
        return row is not None

    def add_purchase(self, guild_id: int, user_id: int, item_type: str, item_key: str) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO purchases (guild_id, user_id, item_type, item_key, purchased_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (guild_id, user_id, item_type, item_key, int(time.time())),
            )

    def top_users(self, guild_id: int, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM users WHERE guild_id = ? ORDER BY xp DESC, user_id ASC LIMIT ?",
            (guild_id, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_rank(self, guild_id: int, user_id: int) -> int:
        self.ensure_user(guild_id, user_id)
        row = self.conn.execute(
            """
            SELECT rank_pos FROM (
                SELECT user_id, ROW_NUMBER() OVER (ORDER BY xp DESC, user_id ASC) AS rank_pos
                FROM users WHERE guild_id = ?
            ) WHERE user_id = ?
            """,
            (guild_id, user_id),
        ).fetchone()
        return int(row[0]) if row else 0

    def increment_messages(self, guild_id: int, user_id: int, amount: int = 1) -> dict[str, Any]:
        self.ensure_user(guild_id, user_id)
        with self.conn:
            self.conn.execute(
                "UPDATE users SET message_count = message_count + ? WHERE guild_id = ? AND user_id = ?",
                (int(amount), guild_id, user_id),
            )
        return self.get_user(guild_id, user_id)

    def get_purchases(self, guild_id: int, user_id: int, item_type: Optional[str] = None) -> list[dict[str, Any]]:
        if item_type is None:
            rows = self.conn.execute(
                "SELECT * FROM purchases WHERE guild_id = ? AND user_id = ? ORDER BY purchased_at DESC",
                (guild_id, user_id),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM purchases WHERE guild_id = ? AND user_id = ? AND item_type = ? ORDER BY purchased_at DESC",
                (guild_id, user_id, item_type),
            ).fetchall()
        return [dict(row) for row in rows]

    def favorite_voice_channel(self, guild_id: int, user_id: int) -> Optional[dict[str, Any]]:
        row = self.conn.execute(
            """
            SELECT channel_id, minutes
            FROM voice_channel_stats
            WHERE guild_id = ? AND user_id = ?
            ORDER BY minutes DESC
            LIMIT 1
            """,
            (guild_id, user_id),
        ).fetchone()
        return dict(row) if row else None

    def grant_profile_item(self, guild_id: int, user_id: int, item_type: str, item_key: str, equipped: int = 0) -> None:
        self.ensure_user(guild_id, user_id)
        with self.conn:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO profile_items (guild_id, user_id, item_type, item_key, equipped, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (guild_id, user_id, item_type, item_key, int(equipped), int(time.time())),
            )

    def get_profile_items(self, guild_id: int, user_id: int, item_type: Optional[str] = None) -> list[dict[str, Any]]:
        if item_type is None:
            rows = self.conn.execute(
                "SELECT * FROM profile_items WHERE guild_id = ? AND user_id = ? ORDER BY created_at DESC",
                (guild_id, user_id),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM profile_items WHERE guild_id = ? AND user_id = ? AND item_type = ? ORDER BY created_at DESC",
                (guild_id, user_id, item_type),
            ).fetchall()
        return [dict(row) for row in rows]

    def add_warning(self, guild_id: int, user_id: int, moderator_id: int, reason: str) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO warnings (guild_id, user_id, moderator_id, reason, created_at) VALUES (?, ?, ?, ?, ?)",
                (guild_id, user_id, moderator_id, reason, int(time.time())),
            )
        return int(cur.lastrowid)

    def get_warnings(self, guild_id: int, user_id: int) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM warnings WHERE guild_id = ? AND user_id = ? ORDER BY id DESC",
            (guild_id, user_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def clear_warnings(self, guild_id: int, user_id: int) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM warnings WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))

    def add_relationship(self, guild_id: int, user1_id: int, user2_id: int, relation_type: str) -> None:
        user1_id, user2_id = sorted((user1_id, user2_id))
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO relationships (guild_id, user1_id, user2_id, relation_type, created_at) VALUES (?, ?, ?, ?, ?)",
                (guild_id, user1_id, user2_id, relation_type, int(time.time())),
            )

    def delete_relationship(self, guild_id: int, user1_id: int, user2_id: int, relation_type: str) -> None:
        user1_id, user2_id = sorted((user1_id, user2_id))
        with self.conn:
            self.conn.execute(
                "DELETE FROM relationships WHERE guild_id = ? AND user1_id = ? AND user2_id = ? AND relation_type = ?",
                (guild_id, user1_id, user2_id, relation_type),
            )

    def relationships_for_member(self, guild_id: int, user_id: int) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT * FROM relationships
            WHERE guild_id = ? AND (user1_id = ? OR user2_id = ?)
            ORDER BY created_at DESC
            """,
            (guild_id, user_id, user_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def has_exclusive_relationship(self, guild_id: int, user_id: int, relation_types: list[str]) -> bool:
        placeholders = ",".join("?" for _ in relation_types)
        row = self.conn.execute(
            f"SELECT 1 FROM relationships WHERE guild_id = ? AND (user1_id = ? OR user2_id = ?) AND relation_type IN ({placeholders}) LIMIT 1",
            [guild_id, user_id, user_id, *relation_types],
        ).fetchone()
        return row is not None


# ------------------------- ROLE PANEL -------------------------
class RoleCategorySelect(discord.ui.Select):
    def __init__(self, category_index: int, category: dict[str, Any]):
        self.category_index = category_index
        self.category_name = str(category.get("name", f"Категория {category_index + 1}"))
        self.selection_mode = str(category.get("selection_mode", "toggle")).lower()
        self.roles_config = [
            role for role in category.get("roles", []) if isinstance(role, dict) and safe_role_id(role) > 0
        ][:25]

        options = []
        for option_index, role_config in enumerate(self.roles_config):
            role_id = safe_role_id(role_config)
            options.append(
                discord.SelectOption(
                    label=str(role_config.get("label", "Роль"))[:100],
                    value=f"{option_index}:{role_id}",
                    description=str(role_config.get("description", ""))[:100] or None,
                    emoji=role_config.get("emoji") or None,
                )
            )

        max_values = category.get("max_values")
        if max_values is None:
            max_values = 1 if self.selection_mode == "exclusive" else max(1, len(options))
        max_values = max(1, min(int(max_values), max(1, len(options)), 25))
        min_values = max(0, min(int(category.get("min_values", 0)), max_values))

        super().__init__(
            placeholder=str(category.get("placeholder", self.category_name))[:150],
            min_values=min_values,
            max_values=max_values,
            options=options,
            custom_id=f"role_category:{category_index}",
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        if interaction.guild is None or not isinstance(interaction.user, discord.Member):
            await interaction.response.send_message("Это меню работает только на сервере.", ephemeral=True)
            return

        if not self.values:
            await interaction.response.send_message("Ты ничего не выбрал.", ephemeral=True)
            return

        member = interaction.user
        guild = interaction.guild
        bot_member = guild.me
        if bot_member is None:
            await interaction.response.send_message("Не могу проверить свою роль на сервере.", ephemeral=True)
            return

        selected_role_ids: set[int] = set()
        for value in self.values:
            try:
                selected_role_ids.add(int(value.split(":", 1)[1]))
            except (IndexError, ValueError):
                continue

        category_role_ids = {safe_role_id(role_config) for role_config in self.roles_config}
        category_role_ids.discard(0)

        added: list[str] = []
        removed: list[str] = []
        skipped: list[str] = []

        try:
            if self.selection_mode == "exclusive":
                for role_id in category_role_ids:
                    role = guild.get_role(role_id)
                    if role is None:
                        continue
                    if role >= bot_member.top_role:
                        skipped.append(role.name)
                        continue
                    if role in member.roles and role_id not in selected_role_ids:
                        await member.remove_roles(role, reason=f"Role panel / {self.category_name}")
                        removed.append(role.name)
                for role_id in selected_role_ids:
                    role = guild.get_role(role_id)
                    if role is None:
                        continue
                    if role >= bot_member.top_role:
                        skipped.append(role.name)
                        continue
                    if role not in member.roles:
                        await member.add_roles(role, reason=f"Role panel / {self.category_name}")
                        added.append(role.name)
            else:
                for role_id in selected_role_ids:
                    role = guild.get_role(role_id)
                    if role is None:
                        continue
                    if role >= bot_member.top_role:
                        skipped.append(role.name)
                        continue
                    if role in member.roles:
                        await member.remove_roles(role, reason=f"Role panel / {self.category_name}")
                        removed.append(role.name)
                    else:
                        await member.add_roles(role, reason=f"Role panel / {self.category_name}")
                        added.append(role.name)
        except discord.Forbidden:
            await interaction.response.send_message(
                "У меня не хватает прав на изменение ролей. Проверь Manage Roles и иерархию ролей.",
                ephemeral=True,
            )
            return

        parts = []
        if added:
            parts.append("Выдано: " + ", ".join(added))
        if removed:
            parts.append("Снято: " + ", ".join(removed))
        if skipped:
            parts.append("Не смог обработать: " + ", ".join(sorted(set(skipped))))
        if not parts:
            parts.append("Ничего не изменилось.")
        await interaction.response.send_message("\n".join(parts), ephemeral=True)


class RolePanelView(discord.ui.View):
    def __init__(self, bot: "ServerBot"):
        super().__init__(timeout=None)
        for category_index, category in enumerate(get_role_categories(bot.config)[:5]):
            if not isinstance(category, dict):
                continue
            select = RoleCategorySelect(category_index, category)
            if select.options:
                self.add_item(select)


# ------------------------- RELATIONSHIPS -------------------------
RELATIONSHIP_LABELS = {
    "friend": "Дружба",
    "family": "Семья",
    "love": "Пара",
    "marriage": "Брак",
}
EXCLUSIVE_REL_TYPES = ["love", "marriage"]


class RelationshipRequestView(discord.ui.View):
    def __init__(self, requester_id: int, target_id: int, relation_type: str, bot_ref: "ServerBot"):
        super().__init__(timeout=60 * 60 * 12)
        self.requester_id = requester_id
        self.target_id = target_id
        self.relation_type = relation_type
        self.bot_ref = bot_ref
        self.done = False

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.target_id:
            await interaction.response.send_message("Ответить на это предложение может только получатель.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Принять", style=discord.ButtonStyle.success)
    async def accept(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if self.done or interaction.guild is None:
            return
        requester = interaction.guild.get_member(self.requester_id)
        target = interaction.guild.get_member(self.target_id)
        if requester is None or target is None:
            await interaction.response.send_message("Не удалось найти участников.", ephemeral=True)
            return

        if self.relation_type in EXCLUSIVE_REL_TYPES:
            if self.bot_ref.db.has_exclusive_relationship(interaction.guild.id, requester.id, EXCLUSIVE_REL_TYPES):
                await interaction.response.send_message(
                    "У отправителя уже есть активные отношения типа пара/брак.", ephemeral=True
                )
                return
            if self.bot_ref.db.has_exclusive_relationship(interaction.guild.id, target.id, EXCLUSIVE_REL_TYPES):
                await interaction.response.send_message(
                    "У получателя уже есть активные отношения типа пара/брак.", ephemeral=True
                )
                return

        self.bot_ref.db.add_relationship(interaction.guild.id, requester.id, target.id, self.relation_type)
        self.done = True
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(view=self)
        await interaction.followup.send(
            f"💖 {requester.mention} и {target.mention}: связь **{RELATIONSHIP_LABELS.get(self.relation_type, self.relation_type)}** успешно создана!"
        )

    @discord.ui.button(label="Отклонить", style=discord.ButtonStyle.danger)
    async def decline(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if self.done:
            return
        self.done = True
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(view=self)
        await interaction.followup.send("❌ Предложение отклонено.")


# ------------------------- MAIN BOT -------------------------
class ServerBot(commands.Bot):
    def __init__(self):
        self.config = load_config()
        intents = discord.Intents.default()
        intents.guilds = True
        intents.members = True
        intents.voice_states = True
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)
        self.db = Database(self.config.get("database_path", "data/bot.sqlite3"))
        self.voice_last_award: dict[tuple[int, int], float] = {}
        self.antispam_history: dict[tuple[int, int], deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=60)
        )
        self.antispam_last_action: dict[tuple[int, int], float] = {}
        self.security_scanner = SecurityScanner(self.antispam_settings)
        self.security_alert_last: dict[tuple[int, int, str], float] = {}
        self.voice_security_history: dict[tuple[int, int], deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=30)
        )
        self.voice_security_last_action: dict[tuple[int, int], float] = {}

    async def setup_hook(self) -> None:
        self.add_view(RolePanelView(self))
        if not self.voice_xp_loop.is_running():
            self.voice_xp_loop.start()
        guild_id = int(self.config.get("guild_id_for_fast_sync", 0) or 0)
        if guild_id:
            guild = discord.Object(id=guild_id)
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
            print(f"Slash-команды синхронизированы для сервера {guild_id}.")
        else:
            await self.tree.sync()
            print("Глобальные slash-команды синхронизированы.")

    async def on_ready(self) -> None:
        print(f"Бот запущен: {self.user} | Серверов: {len(self.guilds)}")
        await self.change_presence(activity=discord.Game(name="/profile | /leaderboard | /help_admin"))

    async def close(self) -> None:
        await self.security_scanner.close()
        await super().close()

    def save_config(self) -> None:
        save_config(self.config)

    def xp_settings(self) -> dict[str, Any]:
        return self.config.setdefault("voice_xp", {})

    def leveling_settings(self) -> dict[str, Any]:
        return self.config.setdefault("leveling", {})

    def welcome_settings(self) -> dict[str, Any]:
        return self.config.setdefault("welcome", {})

    def antispam_settings(self) -> dict[str, Any]:
        settings = self.config.setdefault("antispam", {})
        for key, value in ANTISPAM_DEFAULTS.items():
            if key not in settings:
                settings[key] = value.copy() if isinstance(value, list) else value
        return settings

    @staticmethod
    def normalize_antispam_text(value: str) -> str:
        value = value.lower().strip()
        value = re.sub(r"\s+", " ", value)
        return value[:1200]

    @staticmethod
    def extract_message_urls(value: str) -> tuple[str, ...]:
        urls = []
        for raw_url in URL_RE.findall(value or ""):
            clean_url = raw_url.rstrip(".,!?;:)]}>'\"").lower()
            urls.append(clean_url)
        return tuple(urls)

    def member_antispam_bypassed(
        self,
        member: discord.Member,
        channel: Optional[discord.abc.GuildChannel] = None,
    ) -> bool:
        if member.bot:
            return True
        settings = self.antispam_settings()
        if member.id in {int(x) for x in settings.get("ignored_user_ids", [])}:
            return True
        if channel is not None:
            ignored_channels = {int(x) for x in settings.get("ignored_channel_ids", [])}
            if channel.id in ignored_channels:
                return True
            category_id = getattr(channel, "category_id", None)
            if category_id and category_id in ignored_channels:
                return True
        ignored_roles = {int(x) for x in settings.get("ignored_role_ids", [])}
        if any(role.id in ignored_roles for role in member.roles):
            return True
        return False

    def antispam_bypassed(self, message: discord.Message) -> bool:
        if message.guild is None or not isinstance(message.author, discord.Member):
            return True
        channel = message.channel if isinstance(message.channel, discord.abc.GuildChannel) else None
        return self.member_antispam_bypassed(message.author, channel)

    def security_alert_roles(self, guild: discord.Guild) -> list[discord.Role]:
        settings = self.antispam_settings()
        role_ids = {int(x) for x in settings.get("alert_role_ids", []) if int(x) > 0}
        legacy_id = int(settings.get("alert_role_id", 0) or 0)
        if legacy_id:
            role_ids.add(legacy_id)
        roles = [guild.get_role(role_id) for role_id in role_ids]
        return [role for role in roles if role is not None]

    def security_log_channel(self, guild: discord.Guild) -> Optional[discord.abc.Messageable]:
        channel_id = int(self.antispam_settings().get("log_channel_id", 0) or 0)
        channel = guild.get_channel(channel_id) if channel_id else None
        if channel is None or not isinstance(channel, discord.abc.Messageable):
            channel = guild.system_channel
        return channel if isinstance(channel, discord.abc.Messageable) else None

    @staticmethod
    def defang_security_item(value: str) -> str:
        safe = str(value).replace("```", "`​``")
        safe = re.sub(r"(?i)^https://", "hxxps://", safe)
        safe = re.sub(r"(?i)^http://", "hxxp://", safe)
        return safe.replace(".", "[.]")[:900]

    async def send_security_review_alert(
        self,
        message: discord.Message,
        title: str,
        verdicts: list[ReputationVerdict],
        action: str,
        force_ping: bool = False,
    ) -> None:
        if message.guild is None or not verdicts:
            return
        settings = self.antispam_settings()
        now = time.time()
        cooldown = int(settings.get("link_alert_cooldown_seconds", 60))
        filtered: list[ReputationVerdict] = []
        for verdict in verdicts:
            alert_key = verdict.domain or verdict.sha256 or verdict.item
            key = (message.guild.id, message.author.id, alert_key)
            if not force_ping and now - self.security_alert_last.get(key, 0.0) < cooldown:
                continue
            self.security_alert_last[key] = now
            filtered.append(verdict)
        if not filtered:
            return

        channel = self.security_log_channel(message.guild)
        if channel is None:
            return
        highest = "clean"
        if any(item.status == "malicious" for item in filtered):
            highest = "malicious"
        elif any(item.status == "suspicious" for item in filtered):
            highest = "suspicious"
        elif any(item.status == "unknown" for item in filtered):
            highest = "unknown"
        color = {
            "malicious": discord.Color.red(),
            "suspicious": discord.Color.orange(),
            "unknown": discord.Color.yellow(),
            "clean": discord.Color.green(),
        }[highest]
        channel_kind = (
            "голосовой канал (текстовый чат)"
            if isinstance(message.channel, discord.VoiceChannel)
            else "текстовый канал"
        )
        embed = discord.Embed(
            title=title,
            description=(
                f"**Пользователь:** {message.author.mention} (`{message.author.id}`)\n"
                f"**Канал:** {message.channel.mention} — {channel_kind}\n"
                f"**Действие бота:** {action}"
            ),
            color=color,
            timestamp=discord.utils.utcnow(),
        )
        for index, verdict in enumerate(filtered[:5], start=1):
            reasons = "; ".join(verdict.reasons[:4]) or "нет дополнительных данных"
            providers = ", ".join(verdict.providers) if verdict.providers else "локальная проверка"
            value = (
                f"**Статус:** {verdict.status_label}\n"
                f"**Объект:** `{self.defang_security_item(verdict.item)}`\n"
                f"**Проверка:** {providers}\n"
                f"**Причины:** {reasons[:650]}"
            )
            if verdict.sha256:
                value += f"\n**SHA-256:** `{verdict.sha256}`"
            embed.add_field(name=f"Проверка {index}", value=value[:1024], inline=False)
        content = " ".join(role.mention for role in self.security_alert_roles(message.guild)) or None
        try:
            await channel.send(
                content=content,
                embed=embed,
                allowed_mentions=discord.AllowedMentions(roles=True, users=False, everyone=False),
            )
        except (discord.Forbidden, discord.HTTPException):
            pass

    async def inspect_message_security(self, message: discord.Message, now: float) -> bool:
        settings = self.antispam_settings()
        if not bool(settings.get("link_reputation_enabled", True)):
            return False

        urls = self.extract_message_urls(message.content)
        if urls:
            verdicts = await self.security_scanner.scan_urls(urls)
            malicious = [item for item in verdicts if item.is_malicious]
            if malicious and bool(settings.get("auto_delete_malicious_links", True)):
                details = "\n".join(
                    f"{item.status_label}: {self.defang_security_item(item.item)} — {'; '.join(item.reasons[:3])}"
                    for item in malicious
                )
                await self.handle_antispam(
                    message,
                    "репутационные сервисы подтвердили вредоносную ссылку",
                    now,
                    extra_details=details,
                )
                return True

            should_alert = bool(settings.get("alert_on_external_link", True))
            review = [
                item
                for item in verdicts
                if item.status in {"suspicious", "unknown"}
                or (should_alert and not self.security_scanner.trusted_domain(item.domain))
            ]
            if review:
                await self.send_security_review_alert(
                    message,
                    "🔎 Ссылка требует внимания модерации",
                    review,
                    "сообщение оставлено; модерации отправлен результат проверки",
                    force_ping=any(item.status == "suspicious" for item in review),
                )

        review_extensions = {
            str(item).lower() for item in settings.get("review_attachment_extensions", [])
        }
        attachment_verdicts: list[ReputationVerdict] = []
        for attachment in message.attachments[:3]:
            if Path(attachment.filename).suffix.lower() not in review_extensions:
                continue
            verdict = await self.security_scanner.scan_attachment(attachment)
            attachment_verdicts.append(verdict)

        malicious_files = [item for item in attachment_verdicts if item.is_malicious]
        if malicious_files and bool(settings.get("auto_delete_malicious_attachments", True)):
            details = "\n".join(
                f"{item.item}: {'; '.join(item.reasons[:3])} | SHA-256 {item.sha256}"
                for item in malicious_files
            )
            await self.handle_antispam(
                message,
                "VirusTotal подтвердил вредоносное вложение",
                now,
                extra_details=details,
            )
            return True
        if attachment_verdicts:
            await self.send_security_review_alert(
                message,
                "📦 Приложение или архив отправлен на проверку",
                attachment_verdicts,
                "файл не удалён автоматически; модерация получила отчёт",
                force_ping=any(item.status in {"suspicious", "unknown"} for item in attachment_verdicts),
            )
        return False

    def antispam_reason(self, message: discord.Message, now: float) -> Optional[str]:
        settings = self.antispam_settings()
        key = (message.guild.id, message.author.id)
        history = self.antispam_history[key]
        normalized = self.normalize_antispam_text(message.content)
        urls = self.extract_message_urls(message.content)
        attachment_names = tuple(attachment.filename.lower() for attachment in message.attachments)
        history.append(
            {
                "time": now,
                "message": message,
                "normalized": normalized,
                "urls": urls,
                "channel_id": message.channel.id,
            }
        )

        retention = max(
            int(settings.get("cleanup_window_seconds", 90)),
            int(settings.get("duplicate_window_seconds", 35)),
            int(settings.get("link_repeat_window_seconds", 45)),
            120,
        )
        while history and now - float(history[0]["time"]) > retention:
            history.popleft()

        if bool(settings.get("block_dangerous_attachments", True)):
            for filename in attachment_names:
                if Path(filename).suffix.lower() in DANGEROUS_ATTACHMENT_EXTENSIONS:
                    return f"опасное вложение `{filename}`"

        raw_mention_count = len(message.raw_mentions) + len(message.raw_role_mentions)
        if message.mention_everyone:
            raw_mention_count += 2
        if raw_mention_count >= int(settings.get("max_mentions", 5)):
            return f"массовые упоминания ({raw_mention_count})"

        if len(urls) >= int(settings.get("max_links_per_message", 4)):
            return f"слишком много ссылок в одном сообщении ({len(urls)})"

        if urls and bool(settings.get("suspicious_link_filter", True)):
            if any(phrase in normalized for phrase in SUSPICIOUS_LINK_PHRASES):
                return "подозрительная мошенническая ссылка"

        message_window = int(settings.get("message_window_seconds", 8))
        recent_messages = [item for item in history if now - float(item["time"]) <= message_window]
        if len(recent_messages) >= int(settings.get("max_messages", 6)):
            return f"флуд ({len(recent_messages)} сообщений за {message_window} сек.)"

        duplicate_window = int(settings.get("duplicate_window_seconds", 35))
        if normalized and len(normalized) >= 4:
            duplicates = [
                item for item in history
                if now - float(item["time"]) <= duplicate_window and item["normalized"] == normalized
            ]
            if len(duplicates) >= int(settings.get("max_duplicate_messages", 3)):
                return f"повтор одинакового сообщения ({len(duplicates)} раз)"

        link_window = int(settings.get("link_repeat_window_seconds", 45))
        if urls:
            url_counts: dict[str, int] = defaultdict(int)
            for item in history:
                if now - float(item["time"]) > link_window:
                    continue
                for url in set(item["urls"]):
                    url_counts[url] += 1
            most_repeated = max((url_counts.get(url, 0) for url in urls), default=0)
            if most_repeated >= int(settings.get("max_same_link_messages", 3)):
                return f"массовая рассылка одной ссылки ({most_repeated} раз)"

        cross_window = int(settings.get("cross_channel_window_seconds", 12))
        cross_messages = [item for item in history if now - float(item["time"]) <= cross_window]
        cross_channels = {int(item["channel_id"]) for item in cross_messages}
        if (
            len(cross_messages) >= int(settings.get("cross_channel_messages", 4))
            and len(cross_channels) >= int(settings.get("cross_channel_count", 3))
        ):
            return f"быстрая рассылка по каналам ({len(cross_channels)} канала)"

        return None

    async def delete_antispam_messages(self, message: discord.Message, now: float) -> int:
        settings = self.antispam_settings()
        key = (message.guild.id, message.author.id)
        history = self.antispam_history.get(key, deque())
        cleanup_window = int(settings.get("cleanup_window_seconds", 90))
        cleanup_limit = int(settings.get("cleanup_message_limit", 25))
        candidates = [
            item["message"] for item in history
            if now - float(item["time"]) <= cleanup_window
        ][-cleanup_limit:]
        if not bool(settings.get("delete_recent_messages", True)):
            candidates = [message]

        deleted = 0
        seen_ids: set[int] = set()
        for candidate in reversed(candidates):
            if candidate.id in seen_ids:
                continue
            seen_ids.add(candidate.id)
            try:
                await candidate.delete()
                deleted += 1
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                continue
        return deleted

    async def send_antispam_alert(
        self,
        message: discord.Message,
        reason: str,
        deleted: int,
        timeout_applied: bool,
        timeout_error: Optional[str],
        extra_details: Optional[str] = None,
    ) -> None:
        settings = self.antispam_settings()
        channel_id = int(settings.get("log_channel_id", 0) or 0)
        channel = message.guild.get_channel(channel_id) if channel_id else None
        if channel is None or not isinstance(channel, discord.abc.Messageable):
            channel = message.guild.system_channel
        if channel is None or not isinstance(channel, discord.abc.Messageable):
            return

        excerpt = message.content.strip() or "[сообщение без текста]"
        if message.attachments:
            files = ", ".join(attachment.filename for attachment in message.attachments)
            excerpt = f"{excerpt}\nВложения: {files}"
        excerpt = excerpt.replace("```", "`​``")[:700]
        timeout_text = "✅ применён" if timeout_applied else f"❌ не применён ({timeout_error or 'неизвестная причина'})"
        embed = discord.Embed(
            title="🛡️ AntiSpam остановил рассылку",
            description=(
                f"**Пользователь:** {message.author} (`{message.author.id}`)\n"
                f"**Канал:** {message.channel.mention}\n"
                f"**Причина:** {reason}\n"
                f"**Удалено сообщений:** {deleted}\n"
                f"**Тайм-аут:** {timeout_text}"
            ),
            color=discord.Color.red(),
            timestamp=discord.utils.utcnow(),
        )
        embed.add_field(name="Фрагмент", value=f"```{excerpt}```", inline=False)
        if extra_details:
            embed.add_field(name="Результат проверки", value=extra_details[:1024], inline=False)
        if isinstance(message.author, discord.Member):
            embed.add_field(
                name="Аккаунт",
                value=(
                    f"Создан: <t:{int(message.author.created_at.timestamp())}:R>\n"
                    f"На сервере: <t:{int(message.author.joined_at.timestamp())}:R>"
                    if message.author.joined_at else
                    f"Создан: <t:{int(message.author.created_at.timestamp())}:R>"
                ),
                inline=False,
            )

        alert_roles = self.security_alert_roles(message.guild)
        content = " ".join(role.mention for role in alert_roles) or None
        try:
            await channel.send(
                content=content,
                embed=embed,
                allowed_mentions=discord.AllowedMentions(roles=True, users=False, everyone=False),
            )
        except (discord.Forbidden, discord.HTTPException):
            pass

    async def handle_antispam(
        self,
        message: discord.Message,
        reason: str,
        now: float,
        extra_details: Optional[str] = None,
    ) -> None:
        settings = self.antispam_settings()
        key = (message.guild.id, message.author.id)
        cooldown = int(settings.get("action_cooldown_seconds", 20))
        last_action = self.antispam_last_action.get(key, 0.0)
        if now - last_action < cooldown:
            try:
                await message.delete()
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                pass
            return

        self.antispam_last_action[key] = now
        deleted = await self.delete_antispam_messages(message, now)
        timeout_applied = False
        timeout_error: Optional[str] = None

        member = message.author if isinstance(message.author, discord.Member) else None
        bot_member = message.guild.me
        if member is None:
            timeout_error = "автор не является участником сервера"
        elif member.id == message.guild.owner_id:
            timeout_error = "владельцу сервера нельзя выдать тайм-аут"
        elif bot_member is None or not bot_member.guild_permissions.moderate_members:
            timeout_error = "у бота нет права Moderate Members"
        elif bot_member.top_role <= member.top_role:
            timeout_error = "роль бота находится ниже роли участника"
        else:
            try:
                until = discord.utils.utcnow() + timedelta(minutes=int(settings.get("timeout_minutes", 60)))
                await member.timeout(until, reason=f"Peach AntiSpam: {reason}")
                timeout_applied = True
            except discord.Forbidden:
                timeout_error = "Discord запретил действие — проверь права и иерархию ролей"
            except discord.HTTPException:
                timeout_error = "ошибка Discord API"

        if bool(settings.get("dm_user", True)) and member is not None:
            try:
                await member.send(
                    f"🛡️ На сервере **{message.guild.name}** сработала защита от спама.\n"
                    f"Причина: **{reason}**.\n"
                    "Если твой аккаунт взломали — срочно смени пароль, заверши все сеансы и включи 2FA."
                )
            except (discord.Forbidden, discord.HTTPException):
                pass

        await self.send_antispam_alert(
            message,
            reason,
            deleted,
            timeout_applied,
            timeout_error,
            extra_details=extra_details,
        )
        self.antispam_history.pop(key, None)

    def xp_for_level(self, level: int) -> int:
        settings = self.leveling_settings()
        base_xp = max(int(settings.get("base_xp", 100)), 1)
        curve = max(float(settings.get("curve", 2)), 1)
        return int(base_xp * (level ** curve))

    def level_for_xp(self, xp: int) -> int:
        settings = self.leveling_settings()
        base_xp = max(int(settings.get("base_xp", 100)), 1)
        curve = max(float(settings.get("curve", 2)), 1)
        return int((max(xp, 0) / base_xp) ** (1 / curve))

    def is_earning_voice_channel(self, channel: Optional[discord.abc.GuildChannel]) -> bool:
        if channel is None:
            return False
        settings = self.xp_settings()
        ignored = {int(x) for x in settings.get("ignored_voice_channel_ids", [])}
        return channel.id not in ignored

    def effective_humans_in_channel(self, channel: discord.VoiceChannel | discord.StageChannel) -> list[discord.Member]:
        humans = []
        for member in channel.members:
            if member.bot:
                continue
            if member.voice is not None and (member.voice.self_deaf or member.voice.deaf):
                continue
            humans.append(member)
        return humans

    async def add_voice_reward(self, member: discord.Member, xp: int, coins: int, minutes: int) -> None:
        if xp <= 0 and coins <= 0 and minutes <= 0:
            return
        before = self.db.get_user(member.guild.id, member.id)
        total_xp = before["xp"] + xp
        new_level = self.level_for_xp(total_xp)
        channel_id = member.voice.channel.id if member.voice and member.voice.channel else None
        after = self.db.add_voice_reward(member.guild.id, member.id, xp, coins, minutes, new_level, channel_id=channel_id)
        await self.sync_level_roles(member, after["level"])
        if after["level"] > before["level"]:
            await self.send_levelup_message(member, before["level"], after["level"])

    async def award_elapsed_voice_time(self, member: discord.Member, now: Optional[float] = None) -> None:
        now = now or time.time()
        key = (member.guild.id, member.id)
        last = self.voice_last_award.get(key)
        if last is None:
            self.voice_last_award[key] = now
            return

        elapsed = now - last
        if elapsed < 60:
            return
        settings = self.xp_settings()
        minutes = int(elapsed // 60)
        xp = minutes * int(settings.get("xp_per_minute", 5))
        coins = minutes * int(settings.get("coins_per_minute", 1))
        self.voice_last_award[key] = last + minutes * 60
        await self.add_voice_reward(member, xp, coins, minutes)

    async def sync_level_roles(self, member: discord.Member, level: int) -> None:
        settings = self.leveling_settings()
        configured = settings.get("level_roles", [])
        if not configured:
            return

        bot_member = member.guild.me
        if bot_member is None:
            return

        eligible_roles: list[discord.Role] = []
        all_level_roles: list[discord.Role] = []
        for item in configured:
            role = member.guild.get_role(int(item.get("role_id", 0) or 0))
            if role is None or role >= bot_member.top_role:
                continue
            all_level_roles.append(role)
            if level >= int(item.get("level", 0)):
                eligible_roles.append(role)

        try:
            if bool(settings.get("keep_all_level_roles", False)):
                to_add = [role for role in eligible_roles if role not in member.roles]
                if to_add:
                    await member.add_roles(*to_add, reason="Level role reward")
            else:
                highest = max(eligible_roles, key=lambda role: role.position, default=None)
                to_remove = [role for role in all_level_roles if role in member.roles and role != highest]
                if to_remove:
                    await member.remove_roles(*to_remove, reason="Replacing level role")
                if highest is not None and highest not in member.roles:
                    await member.add_roles(highest, reason="Level role reward")
        except discord.Forbidden:
            print(f"Не могу обновить level-роли для {member} — проверь права и иерархию ролей.")

    async def send_levelup_message(self, member: discord.Member, old_level: int, new_level: int) -> None:
        channel_id = int(self.config.get("levelup_channel_id", 0) or 0)
        channel = member.guild.get_channel(channel_id) if channel_id else None
        if channel is None and member.guild.system_channel is not None:
            channel = member.guild.system_channel
        if channel is not None and isinstance(channel, discord.abc.Messageable):
            embed = discord.Embed(
                title="🎉 Новый уровень!",
                description=f"{member.mention} апнул **{new_level} уровень**! Было: **{old_level}**.",
                color=discord.Color.gold(),
            )
            await channel.send(embed=embed)

    @tasks.loop(seconds=60)
    async def voice_xp_loop(self) -> None:
        settings = self.xp_settings()
        min_members = int(settings.get("min_members_in_channel", 1))
        for guild in self.guilds:
            for channel in guild.voice_channels:
                if not self.is_earning_voice_channel(channel):
                    continue
                humans = self.effective_humans_in_channel(channel)
                if len(humans) < min_members:
                    continue
                for member in humans:
                    await self.award_elapsed_voice_time(member)

    @voice_xp_loop.before_loop
    async def before_voice_xp_loop(self) -> None:
        await self.wait_until_ready()

    async def send_voice_security_alert(
        self,
        member: discord.Member,
        events: list[dict[str, Any]],
        disconnected: bool,
        timeout_applied: bool,
        timeout_error: Optional[str],
    ) -> None:
        channel = self.security_log_channel(member.guild)
        if channel is None:
            return
        transitions = []
        for item in events[-8:]:
            before_name = item.get("before") or "не в канале"
            after_name = item.get("after") or "не в канале"
            transitions.append(f"• {before_name} → {after_name}")
        embed = discord.Embed(
            title="🎙️ Зафиксирован спам по голосовым каналам",
            description=(
                f"**Пользователь:** {member.mention} (`{member.id}`)\n"
                f"**Переходов:** {len(events)}\n"
                f"**Отключён от голосового:** {'да' if disconnected else 'нет'}\n"
                f"**Тайм-аут:** {'применён' if timeout_applied else 'не применён'}"
                + (f" — {timeout_error}" if timeout_error else "")
            ),
            color=discord.Color.red(),
            timestamp=discord.utils.utcnow(),
        )
        if transitions:
            embed.add_field(name="Последние переходы", value="\n".join(transitions)[:1024], inline=False)
        content = " ".join(role.mention for role in self.security_alert_roles(member.guild)) or None
        try:
            await channel.send(
                content=content,
                embed=embed,
                allowed_mentions=discord.AllowedMentions(roles=True, users=False, everyone=False),
            )
        except (discord.Forbidden, discord.HTTPException):
            pass

    async def inspect_voice_hopping(
        self,
        member: discord.Member,
        before: discord.VoiceState,
        after: discord.VoiceState,
        now: float,
    ) -> None:
        settings = self.antispam_settings()
        if not bool(settings.get("enabled", True)) or not bool(settings.get("voice_hop_protection", True)):
            return
        if before.channel == after.channel:
            return
        channel_for_bypass = after.channel or before.channel
        if self.member_antispam_bypassed(member, channel_for_bypass):
            return

        key = (member.guild.id, member.id)
        history = self.voice_security_history[key]
        history.append(
            {
                "time": now,
                "before": before.channel.name if before.channel else None,
                "after": after.channel.name if after.channel else None,
            }
        )
        window = max(5, int(settings.get("voice_hop_window_seconds", 30)))
        while history and now - float(history[0]["time"]) > window:
            history.popleft()
        threshold = max(3, int(settings.get("voice_hop_max_events", 6)))
        if len(history) < threshold:
            return
        if now - self.voice_security_last_action.get(key, 0.0) < window:
            return
        self.voice_security_last_action[key] = now

        bot_member = member.guild.me
        disconnected = False
        timeout_applied = False
        timeout_error: Optional[str] = None
        if (
            bool(settings.get("disconnect_voice_spammer", True))
            and after.channel is not None
            and bot_member is not None
            and bot_member.guild_permissions.move_members
        ):
            try:
                await member.move_to(None, reason="Peach AntiSpam: частые переходы по голосовым каналам")
                disconnected = True
            except (discord.Forbidden, discord.HTTPException):
                pass

        if member.id == member.guild.owner_id:
            timeout_error = "владельцу сервера нельзя выдать тайм-аут"
        elif bot_member is None or not bot_member.guild_permissions.moderate_members:
            timeout_error = "у бота нет права Moderate Members"
        elif bot_member.top_role <= member.top_role:
            timeout_error = "роль бота находится ниже роли участника"
        else:
            try:
                timeout_minutes = max(1, int(settings.get("voice_hop_timeout_minutes", 10)))
                until = discord.utils.utcnow() + timedelta(minutes=timeout_minutes)
                await member.timeout(until, reason="Peach AntiSpam: спам переходами по голосовым каналам")
                timeout_applied = True
            except discord.Forbidden:
                timeout_error = "Discord запретил тайм-аут"
            except discord.HTTPException:
                timeout_error = "ошибка Discord API"

        await self.send_voice_security_alert(
            member,
            list(history),
            disconnected,
            timeout_applied,
            timeout_error,
        )
        history.clear()

    async def on_voice_state_update(
        self,
        member: discord.Member,
        before: discord.VoiceState,
        after: discord.VoiceState,
    ) -> None:
        if member.bot:
            return
        before_earning = self.is_earning_voice_channel(before.channel)
        after_earning = self.is_earning_voice_channel(after.channel)
        key = (member.guild.id, member.id)
        now = time.time()

        await self.inspect_voice_hopping(member, before, after, now)

        if not before_earning and after_earning:
            self.voice_last_award[key] = now
        elif before_earning and not after_earning:
            await self.award_elapsed_voice_time(member, now=now)
            self.voice_last_award.pop(key, None)

    async def on_member_join(self, member: discord.Member) -> None:
        settings = self.welcome_settings()
        # autoroles
        auto_roles = []
        for role_id in settings.get("auto_role_ids", []):
            role = member.guild.get_role(int(role_id))
            if role is not None:
                auto_roles.append(role)
        if auto_roles:
            try:
                await member.add_roles(*auto_roles, reason="Auto role on join")
            except discord.Forbidden:
                print("Не смог выдать авто-роли новому участнику.")

        if not bool(settings.get("enabled", False)):
            return
        channel = member.guild.get_channel(int(settings.get("channel_id", 0) or 0))
        if channel is None or not isinstance(channel, discord.abc.Messageable):
            channel = member.guild.system_channel
        if channel is None:
            return
        message_template = str(settings.get("message", "Добро пожаловать, {mention}!"))
        message = message_template.format(
            mention=member.mention,
            user=member.display_name,
            server=member.guild.name,
            count=member.guild.member_count,
        )
        color = parse_discord_color(str(settings.get("color", "#5865F2")))
        embed = discord.Embed(
            title=str(settings.get("title", "👋 Добро пожаловать!")),
            description=message,
            color=color,
        )
        if settings.get("footer"):
            embed.set_footer(text=str(settings.get("footer")))
        embed.set_thumbnail(url=member.display_avatar.url)
        if settings.get("image_url"):
            embed.set_image(url=str(settings.get("image_url")))
        await channel.send(content=member.mention, embed=embed)

    async def on_message(self, message: discord.Message) -> None:
        if message.guild is not None and not message.author.bot:
            if bool(self.antispam_settings().get("enabled", True)) and not self.antispam_bypassed(message):
                now = time.time()
                reason = self.antispam_reason(message, now)
                if reason is not None:
                    await self.handle_antispam(message, reason, now)
                    return
                if await self.inspect_message_security(message, now):
                    return
            self.db.increment_messages(message.guild.id, message.author.id, 1)
        await self.process_commands(message)

    async def on_message_edit(self, before: discord.Message, after: discord.Message) -> None:
        if before.content == after.content or after.guild is None or after.author.bot:
            return
        if not bool(self.antispam_settings().get("enabled", True)) or self.antispam_bypassed(after):
            return
        now = time.time()
        reason = self.antispam_reason(after, now)
        if reason is not None:
            await self.handle_antispam(after, f"изменённое сообщение: {reason}", now)
            return
        await self.inspect_message_security(after, now)


bot = ServerBot()


# ------------------------- PROFILE ART -------------------------
def make_gradient(size: tuple[int, int], c1: tuple[int, int, int], c2: tuple[int, int, int]) -> Image.Image:
    width, height = size
    image = Image.new("RGB", size, c1)
    pixels = image.load()
    for y in range(height):
        ratio = y / max(height - 1, 1)
        color = tuple(int(c1[i] * (1 - ratio) + c2[i] * ratio) for i in range(3))
        for x in range(width):
            pixels[x, y] = color
    return image.convert("RGBA")


def draw_theme_background(size: tuple[int, int], theme: str, colors: list[str]) -> Image.Image:
    c1 = parse_hex_color(colors[0] if colors else "#23272A")
    c2 = parse_hex_color(colors[1] if len(colors) > 1 else colors[0] if colors else "#5865F2")
    base = make_gradient(size, c1, c2)
    draw = ImageDraw.Draw(base)
    width, height = size

    rng = random.Random(theme)

    if theme in {"anime_city", "cyber", "night"}:
        for _ in range(40):
            x = rng.randint(0, width)
            y = rng.randint(0, int(height * 0.5))
            r = rng.randint(1, 3)
            draw.ellipse((x - r, y - r, x + r, y + r), fill=(255, 255, 255, 180))
        skyline_y = int(height * 0.72)
        for i in range(12):
            bw = rng.randint(55, 110)
            bh = rng.randint(80, 220)
            x = i * (width // 11) - 20
            draw.rectangle((x, skyline_y - bh, x + bw, skyline_y), fill=(15, 18, 35, 220))
            for wx in range(x + 10, x + bw - 10, 16):
                for wy in range(skyline_y - bh + 12, skyline_y - 10, 22):
                    if rng.random() > 0.45:
                        draw.rectangle((wx, wy, wx + 7, wy + 10), fill=(255, 222, 89, 180))
        draw.rectangle((0, skyline_y, width, height), fill=(14, 16, 28, 160))
    elif theme in {"forest", "nature", "mountain"}:
        for layer, alpha in [(0.65, 180), (0.75, 160), (0.85, 140)]:
            points = [(0, height)]
            step = max(90, width // 8)
            for x in range(0, width + step, step):
                y = int(height * layer + rng.randint(-35, 35))
                points.append((x, y))
            points.append((width, height))
            draw.polygon(points, fill=(20, 60, 45, alpha))
        for _ in range(18):
            x = rng.randint(0, width)
            trunk_h = rng.randint(30, 60)
            draw.rectangle((x, height - 90, x + 6, height - 90 + trunk_h), fill=(70, 45, 25, 220))
            draw.polygon([(x - 20, height - 80), (x + 3, height - 130), (x + 26, height - 80)], fill=(50, 120, 80, 220))
    elif theme in {"sakura", "anime"}:
        moon_r = 46
        draw.ellipse((width - 140, 60, width - 140 + moon_r * 2, 60 + moon_r * 2), fill=(255, 245, 230, 180))
        for _ in range(120):
            x = rng.randint(0, width)
            y = rng.randint(0, height)
            draw.ellipse((x, y, x + 5, y + 3), fill=(255, 190, 220, rng.randint(90, 170)))
        draw.line((110, 40, 60, height), fill=(80, 40, 60, 220), width=12)
        for offset in [0, 24, 48, 72]:
            draw.line((110, 120 + offset, 220 + offset, 80 + offset), fill=(90, 50, 70, 220), width=6)
    elif theme in {"ocean", "water"}:
        for wave in range(5):
            y = int(height * 0.55 + wave * 26)
            pts = []
            for x in range(0, width + 1, 30):
                pts.append((x, y + int(math.sin((x / 80) + wave) * 10)))
            pts += [(width, height), (0, height)]
            draw.polygon(pts, fill=(30, 90 + wave * 15, 150 + wave * 10, 90))
        draw.ellipse((width - 190, 40, width - 80, 150), fill=(255, 255, 255, 120))
    elif theme in {"panda", "fox", "wolf", "animals"}:
        # abstract animal motif: paw prints + soft circles
        for _ in range(16):
            x = rng.randint(0, width)
            y = rng.randint(0, height)
            draw.ellipse((x, y, x + 70, y + 70), fill=(255, 255, 255, 18))
        for i in range(8):
            x = 120 + i * 110
            y = 40 + (i % 2) * 35
            draw.ellipse((x, y + 20, x + 28, y + 48), fill=(255, 255, 255, 45))
            draw.ellipse((x + 8, y, x + 18, y + 12), fill=(255, 255, 255, 45))
            draw.ellipse((x + 22, y + 2, x + 32, y + 14), fill=(255, 255, 255, 45))
            draw.ellipse((x - 4, y + 4, x + 6, y + 16), fill=(255, 255, 255, 45))
            draw.ellipse((x + 30, y + 5, x + 40, y + 17), fill=(255, 255, 255, 45))
    else:
        for _ in range(25):
            x = rng.randint(0, width)
            y = rng.randint(0, height)
            r = rng.randint(20, 90)
            draw.ellipse((x - r, y - r, x + r, y + r), fill=(255, 255, 255, 15))

    overlay = Image.new("RGBA", size, (0, 0, 0, 68))
    base.alpha_composite(overlay)
    return base


_FONT_CACHE: dict[bool, Optional[str]] = {}


def _try_font_path(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    path = str(path).strip()
    if path and Path(path).exists():
        return path
    return None


def _find_font_path(bold: bool = False) -> Optional[str]:
    cached = _FONT_CACHE.get(bold)
    if cached:
        return cached

    # 1) Стандартные пути Windows/macOS/Linux + частые Docker-образы.
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/local/share/fonts/DejaVuSans-Bold.ttf" if bold else "/usr/local/share/fonts/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc" if bold else "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf" if bold else "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
        "/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf" if bold else "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Helvetica.ttf",
    ]
    for candidate in candidates:
        path = _try_font_path(candidate)
        if path:
            _FONT_CACHE[bold] = path
            return path

    # 2) Если на хостинге есть fontconfig, просим систему найти шрифт.
    font_queries = [
        "DejaVu Sans:style=Bold" if bold else "DejaVu Sans:style=Book",
        "Noto Sans:style=Bold" if bold else "Noto Sans:style=Regular",
        "Liberation Sans:style=Bold" if bold else "Liberation Sans:style=Regular",
        "Arial:style=Bold" if bold else "Arial:style=Regular",
        "sans-serif:style=Bold" if bold else "sans-serif:style=Regular",
    ]
    for query in font_queries:
        try:
            result = subprocess.run(
                ["fc-match", "-f", "%{file}", query],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
            path = _try_font_path(result.stdout)
            if path:
                _FONT_CACHE[bold] = path
                return path
        except Exception:
            pass

    # 3) Последний надёжный fallback: matplotlib ставится через requirements
    # и приносит DejaVu Sans, который нормально рисует кириллицу.
    try:
        from matplotlib import font_manager

        font_path = font_manager.findfont(
            "DejaVu Sans",
            fallback_to_default=True,
            rebuild_if_missing=False,
        )
        path = _try_font_path(font_path)
        if path:
            _FONT_CACHE[bold] = path
            return path
    except Exception:
        pass

    _FONT_CACHE[bold] = None
    return None


def load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    font_path = _find_font_path(bold)
    if font_path:
        try:
            return ImageFont.truetype(font_path, size)
        except OSError:
            pass

    # Если этот fallback сработал — на хостинге реально нет шрифта.
    # Карточка всё равно создастся, но кириллица может быть квадратиками.
    return ImageFont.load_default()


async def create_profile_card(member: discord.Member) -> io.BytesIO:
    """Главный экран профиля в стиле компактной dashboard-карточки, без ломаных emoji."""
    row = bot.db.get_user(member.guild.id, member.id)
    backgrounds = bot.config.get("profile_backgrounds", {})
    background_key = row.get("background", "default")
    bg_data = backgrounds.get(background_key, backgrounds.get("default", {}))
    theme = str(bg_data.get("theme", background_key))
    colors = bg_data.get("colors", ["#111827", "#2f3f46"])

    width, height = 1120, 620
    image = draw_theme_background((width, height), theme, colors)
    draw = ImageDraw.Draw(image)

    image.alpha_composite(Image.new("RGBA", (width, height), (0, 0, 0, 92)))
    draw = ImageDraw.Draw(image)

    name_font = load_font(28, True)
    medium_bold = load_font(22, True)
    text_font = load_font(20)
    small_font = load_font(17)
    tiny_font = load_font(14)

    def glass_rect(box: tuple[int, int, int, int], radius: int = 22, alpha: int = 42, outline: int = 28) -> None:
        draw.rounded_rectangle(box, radius=radius, fill=(255, 255, 255, alpha), outline=(255, 255, 255, outline), width=1)

    def pill(box: tuple[int, int, int, int], alpha: int = 42) -> None:
        draw.rounded_rectangle(box, radius=(box[3] - box[1]) // 2, fill=(255, 255, 255, alpha), outline=(255, 255, 255, 18), width=1)

    def draw_centered_emoji(box: tuple[int, int, int, int], emoji_text: str, size: int = 24) -> None:
        """Рисует именно emoji по центру. Сначала Twemoji-картинка, потом fallback через шрифт."""
        x1, y1, x2, y2 = box
        emoji_text = str(emoji_text)
        emoji_size = min(size, x2 - x1, y2 - y1)

        emoji_image = _load_emoji_image(emoji_text, emoji_size)
        if emoji_image is not None:
            px = int(x1 + ((x2 - x1) - emoji_size) / 2)
            py = int(y1 + ((y2 - y1) - emoji_size) / 2)
            image.alpha_composite(emoji_image, (px, py))
            return

        # Если Twemoji не скачалась, пробуем рисовать именно emoji текстом, без замены на символы.
        emoji_font = load_font(max(emoji_size - 2, 16), False)
        bbox = draw.textbbox((0, 0), emoji_text, font=emoji_font)
        sw = bbox[2] - bbox[0]
        sh = bbox[3] - bbox[1]
        px = x1 + ((x2 - x1) - sw) / 2 - bbox[0]
        py = y1 + ((y2 - y1) - sh) / 2 - bbox[1]
        draw.text((px, py), emoji_text, font=emoji_font, fill=(255, 255, 255, 255))

    glass_rect((18, 18, width - 18, height - 18), radius=34, alpha=28, outline=34)
    glass_rect((50, 56, 300, height - 62), radius=28, alpha=34, outline=24)
    glass_rect((320, 56, 808, 356), radius=24, alpha=32, outline=20)
    glass_rect((824, 56, width - 50, 356), radius=24, alpha=32, outline=20)
    glass_rect((824, 382, width - 50, 520), radius=24, alpha=24, outline=18)

    # Avatar
    avatar_bytes = await member.display_avatar.replace(size=256, static_format="png").read()
    avatar = Image.open(io.BytesIO(avatar_bytes)).convert("RGBA").resize((152, 152))
    mask = Image.new("L", (152, 152), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, 152, 152), radius=18, fill=255)
    image.paste(avatar, (99, 76), mask)
    draw.rounded_rectangle((95, 72, 255, 232), radius=20, outline=(255, 255, 255, 82), width=2)

    display_name = truncate_text(member.display_name, 15)
    name_w, _ = rich_text_size(draw, display_name, name_font)
    draw_rich_text(image, draw, (175 - name_w // 2, 252), display_name, name_font, fill=(255, 255, 255, 245))

    level = int(row["level"])
    xp = int(row["xp"])
    balance = int(row["balance"])
    voice_minutes = int(row.get("voice_minutes", 0))
    message_count = int(row.get("message_count", 0))
    rank = bot.db.get_rank(member.guild.id, member.id)
    warnings_count = len(bot.db.get_warnings(member.guild.id, member.id))
    current_level_xp = bot.xp_for_level(level)
    next_level_xp = bot.xp_for_level(level + 1)
    progress = 0 if next_level_xp == current_level_xp else (xp - current_level_xp) / (next_level_xp - current_level_xp)
    progress = max(0, min(1, progress))

    try:
        achieved_count = sum(1 for ach in calculate_achievements(member) if ach.get("done") or ach.get("completed"))
    except Exception:
        achieved_count = len(bot.db.get_purchases(member.guild.id, member.id, "background"))

    # Left economy chips: plain emoji, no PNG icons.
    chip_y = 318
    coin_text = f"{balance:,}".replace(",", " ")
    ach_text = f"{achieved_count} шт."
    left_chips = [("🍑", coin_text), ("🔥", ach_text)]
    for emoji, value in left_chips:
        pill((78, chip_y, 270, chip_y + 50), alpha=42)
        draw_centered_emoji((88, chip_y + 6, 132, chip_y + 46), emoji, size=28)
        val_w, _ = rich_text_size(draw, value, medium_bold)
        draw_rich_text(image, draw, (248 - val_w, chip_y + 12), value, medium_bold, fill=(255, 255, 255, 245))
        chip_y += 62

    joined = member.joined_at.strftime("%d.%m.%Y") if member.joined_at else "—"
    created = member.created_at.strftime("%d.%m.%Y") if member.created_at else "—"

    # Vibe block under avatar: no duplicated LVL/TOP/voice stats.
    if member.joined_at:
        now_dt = discord.utils.utcnow()
        server_days = max(0, (now_dt - member.joined_at).days)
        server_age = f"{server_days} дн."
    else:
        server_age = "—"

    if voice_minutes >= 600:
        vibe_type = "Ночной"
    elif message_count >= 250:
        vibe_type = "Общительный"
    elif level >= 10:
        vibe_type = "Активный"
    else:
        vibe_type = "Новый персик"

    status_text = "В войсе" if member.voice and member.voice.channel else "В сети"

    vibe_lines = [
        ("🍑 Стаж", server_age),
        ("🌙 Вайб", vibe_type),
        ("💫 Статус", status_text),
    ]

    y = 450
    for label, value in vibe_lines:
        draw_rich_text(image, draw, (82, y), label, tiny_font, fill=(210, 220, 255, 175))
        draw_rich_text(image, draw, (170, y - 2), value, small_font, fill=(255, 255, 255, 225))
        y += 32

    pill((458, 82, 666, 124), alpha=34)
    title = "Статистика"
    tw, _ = _plain_text_size(draw, title, medium_bold)
    draw.text((562 - tw // 2, 92), title, font=medium_bold, fill=(255, 255, 255, 235))

    current_voice = "Не в войсе"
    if member.voice and member.voice.channel:
        current_voice = clean_display_value(member.voice.channel.name, 13)

    fav = bot.db.favorite_voice_channel(member.guild.id, member.id)
    if fav:
        fav_channel = member.guild.get_channel(int(fav["channel_id"]))
        fav_name = clean_display_value(fav_channel.name if fav_channel else "Комната", 13)
    else:
        fav_name = "Нет"

    stat_cards = [
        ("📍", "Находится в", current_voice),
        ("⏳", "Голосовой онлайн", format_duration_minutes(voice_minutes)),
        ("🏆", "Топ по онлайну", f"{rank or '-'} место"),
        ("⭐", "Любимая комната", fav_name),
    ]
    positions = [(348, 154), (570, 154), (348, 244), (570, 244)]
    for (emoji, label, value), (x, y) in zip(stat_cards, positions):
        glass_rect((x, y, x + 205, y + 70), radius=18, alpha=30, outline=16)
        draw.rounded_rectangle((x + 12, y + 21, x + 42, y + 51), radius=11, fill=(120, 175, 220, 60))
        draw_centered_emoji((x + 12, y + 21, x + 42, y + 51), emoji, size=22)
        draw.text((x + 54, y + 14), label, font=tiny_font, fill=(205, 214, 235, 155))
        draw_rich_text(image, draw, (x + 54, y + 36), truncate_text(value, 14), medium_bold, fill=(255, 255, 255, 238))

        bar_x, bar_y, bar_w, bar_h = 356, 390, 430, 18
    draw.text((356, 366), f"Прогресс: {xp:,}/{next_level_xp:,} XP".replace(",", " "), font=small_font, fill=(235, 240, 255, 200))
    draw.rounded_rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), radius=9, fill=(10, 12, 22, 170))
    fill_w = int(bar_w * progress)
    if fill_w > 0:
        accent = parse_hex_color(colors[-1] if colors else "#7C86FF", default=(124, 134, 255))
        draw.rounded_rectangle((bar_x, bar_y, bar_x + fill_w, bar_y + bar_h), radius=9, fill=(*accent, 230))
    draw.text((bar_x + bar_w + 12, bar_y - 2), f"{int(progress * 100)}%", font=tiny_font, fill=(255, 255, 255, 200))

    # Roles strip under XP bar: show participant roles with emojis preserved.
    roles_y = 422
    roles_box = (356, roles_y, 786, roles_y + 42)
    pill(roles_box, alpha=32)

    visible_roles = [
        role for role in member.roles
        if role != member.guild.default_role and not role.managed
    ]
    visible_roles = sorted(visible_roles, key=lambda r: r.position, reverse=True)

    def clean_role_value(value: str, max_chars: int = 24) -> str:
        # Убираем только декоративные разделители, но оставляем emoji ролей.
        value = str(value)
        for char in DECORATION_CHARS:
            value = value.replace(char, " ")
        value = " ".join(value.split()).strip()
        return truncate_text(value or "Роль", max_chars)

    def fit_role_text(value: str, max_width: int) -> str:
        # Режем строку именно по пикселям, чтобы текст не вылезал из плашки.
        value = str(value)
        if rich_text_size(draw, value, role_font)[0] <= max_width:
            return value
        ellipsis = "…"
        clean = value
        while clean and rich_text_size(draw, clean + ellipsis, role_font)[0] > max_width:
            clean = clean[:-1]
        return (clean + ellipsis) if clean else ellipsis

    role_x = roles_box[0] + 10
    max_role_x = roles_box[2] - 10
    role_font = tiny_font
    chip_gap = 8
    max_chips = 3

    if not visible_roles:
        empty_text = "Ролей пока нет"
        ew, _ = _plain_text_size(draw, empty_text, role_font)
        draw.text(
            (roles_box[0] + ((roles_box[2] - roles_box[0]) - ew) / 2, roles_y + 13),
            empty_text,
            font=role_font,
            fill=(220, 228, 255, 145),
        )
    else:
        shown_count = 0
        hidden_count = 0

        for role in visible_roles:
            remaining_roles = len(visible_roles) - shown_count - 1
            reserve_more = 50 if remaining_roles > 0 and shown_count >= 1 else 0
            available_w = max_role_x - role_x - reserve_more

            if available_w < 58:
                hidden_count += 1
                continue

            role_text = clean_role_value(role.name, 24)
            text_max_w = max(24, min(available_w - 22, 128))
            fitted_text = fit_role_text(role_text, text_max_w)
            tw, _ = rich_text_size(draw, fitted_text, role_font)
            chip_w = min(max(58, tw + 22), available_w)

            if role_x + chip_w > max_role_x:
                hidden_count += 1
                continue

            role_color = role.color.to_rgb() if role.color.value else (255, 170, 200)
            chip_box = (role_x, roles_y + 7, role_x + chip_w, roles_y + 35)

            draw.rounded_rectangle(
                chip_box,
                radius=14,
                fill=(*role_color, 86),
                outline=(*role_color, 145),
                width=1,
            )

            # Маска-клип: даже если шрифт/emoji даст странную ширину, текст физически не выйдет за плашку.
            chip_layer = Image.new("RGBA", image.size, (0, 0, 0, 0))
            chip_draw = ImageDraw.Draw(chip_layer)
            draw_rich_text(
                chip_layer,
                chip_draw,
                (role_x + 10, roles_y + 12),
                fitted_text,
                role_font,
                fill=(255, 255, 255, 230),
            )
            clip_mask = Image.new("L", image.size, 0)
            mask_draw = ImageDraw.Draw(clip_mask)
            mask_draw.rounded_rectangle(
                (role_x + 6, roles_y + 7, role_x + chip_w - 6, roles_y + 35),
                radius=12,
                fill=255,
            )
            clipped = Image.new("RGBA", image.size, (0, 0, 0, 0))
            clipped.alpha_composite(chip_layer)
            clipped.putalpha(Image.composite(clipped.getchannel("A"), Image.new("L", image.size, 0), clip_mask))
            image.alpha_composite(clipped)

            role_x += chip_w + chip_gap
            shown_count += 1

            if shown_count >= max_chips:
                hidden_count += max(0, len(visible_roles) - shown_count)
                break

        if hidden_count > 0 and role_x + 44 <= max_role_x:
            more_text = f"+{hidden_count}"
            more_w = 42
            draw.rounded_rectangle(
                (role_x, roles_y + 7, role_x + more_w, roles_y + 35),
                radius=14,
                fill=(255, 255, 255, 32),
                outline=(255, 255, 255, 55),
                width=1,
            )
            draw.text((role_x + 10, roles_y + 12), more_text, font=role_font, fill=(255, 255, 255, 210))

    # Right art panel: generated mini-art based on selected background/theme.
    draw_profile_art(image, draw, (856, 84, 1038, 270), theme, colors)

    # Pair/clan blocks with vector icons.
    relations = bot.db.relationships_for_member(member.guild.id, member.id)
    pair_text = "Пары нет"
    pair_sub = "Пусто"
    for relation in relations:
        if relation["relation_type"] in ("love", "marriage"):
            other_id = relation["user2_id"] if relation["user1_id"] == member.id else relation["user1_id"]
            other = member.guild.get_member(other_id)
            pair_text = "Пара"
            pair_sub = truncate_text(other.display_name if other else str(other_id), 15)
            break

    right_rows = [("💕", pair_text, pair_sub), ("👑", "Клана нет", "Пусто")]
    ry = 395
    for emoji, main, sub in right_rows:
        draw.ellipse((850, ry + 10, 892, ry + 52), fill=(255, 255, 255, 34), outline=(255, 255, 255, 24), width=1)
        draw_centered_emoji((850, ry + 10, 892, ry + 52), emoji, size=26)
        draw_rich_text(image, draw, (908, ry + 12), main, medium_bold, fill=(255, 255, 255, 240))
        draw.text((908, ry + 40), sub, font=tiny_font, fill=(210, 220, 235, 145))
        ry += 64

    # Completed achievement emojis strip.
    completed_achievements = [ach for ach in calculate_achievements(member) if ach.get("done") or ach.get("completed")]
    ach_strip_y = 476
    ach_box = (356, ach_strip_y, 786, ach_strip_y + 38)
    pill(ach_box, alpha=26)

    draw.text((ach_box[0] + 14, ach_strip_y + 12), "Ачивки", font=tiny_font, fill=(210, 220, 245, 150))
    ach_x = ach_box[0] + 80
    max_ach_x = ach_box[2] - 12
    shown_achievements = completed_achievements[:7]

    if not shown_achievements:
        draw.text((ach_x, ach_strip_y + 12), "пока нет", font=tiny_font, fill=(220, 228, 255, 125))
    else:
        for ach in shown_achievements:
            if ach_x + 28 > max_ach_x:
                break
            draw.rounded_rectangle(
                (ach_x, ach_strip_y + 6, ach_x + 28, ach_strip_y + 34),
                radius=14,
                fill=(255, 255, 255, 24),
                outline=(255, 255, 255, 42),
                width=1,
            )
            draw_centered_emoji((ach_x + 4, ach_strip_y + 4, ach_x + 24, ach_strip_y + 32), str(ach.get("emoji", "🏅")), size=18)
            ach_x += 32

        hidden_achievements = max(0, len(completed_achievements) - len(shown_achievements))
        if hidden_achievements > 0 and ach_x + 34 <= max_ach_x:
            draw.rounded_rectangle(
                (ach_x, ach_strip_y + 6, ach_x + 34, ach_strip_y + 34),
                radius=14,
                fill=(255, 255, 255, 20),
                outline=(255, 255, 255, 36),
                width=1,
            )
            more_text = f"+{hidden_achievements}"
            draw.text((ach_x + 8, ach_strip_y + 11), more_text, font=tiny_font, fill=(255, 255, 255, 190))

    # Bottom info cards: cleaner than one small gray footer line.
    bottom_cards = [
        ("💬", "Сообщения", f"{message_count:,}".replace(",", " ")),
        ("❗", "Варны", str(warnings_count)),
        ("🎨", "Фон", str(bg_data.get("name", background_key))),
    ]
    bx = 350
    by = 526
    card_w = 142
    card_h = 46
    for emoji, label, value in bottom_cards:
        draw.rounded_rectangle(
            (bx, by, bx + card_w, by + card_h),
            radius=16,
            fill=(255, 255, 255, 24),
            outline=(255, 255, 255, 34),
            width=1,
        )
        draw_centered_emoji((bx + 10, by + 10, bx + 36, by + 36), emoji, size=20)
        draw.text((bx + 42, by + 8), label, font=tiny_font, fill=(210, 220, 245, 145))
        draw_rich_text(
            image,
            draw,
            (bx + 42, by + 25),
            truncate_text(value, 13),
            small_font,
            fill=(255, 255, 255, 225),
        )
        bx += card_w + 14

    output = io.BytesIO()
    image.save(output, format="PNG")
    output.seek(0)
    return output



def achievement_progress(member: discord.Member) -> list[dict[str, Any]]:
    metrics = user_achievement_metrics(member)
    result = []
    for item in ACHIEVEMENT_DEFS:
        value = int(metrics.get(item["metric"], 0))
        target = int(item["target"])
        result.append({**item, "value": value, "done": value >= target, "percent": min(value / max(target, 1), 1)})
    return result


def make_ui_canvas(width: int = 1200, height: int = 620, theme: str = "night", colors: Optional[list[str]] = None) -> Image.Image:
    colors = colors or ["#10141f", "#243B55"]
    image = draw_theme_background((width, height), theme, colors)
    overlay = Image.new("RGBA", (width, height), (0, 0, 0, 40))
    image.alpha_composite(overlay)
    return image


def draw_glass(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], radius: int = 24, fill=(255, 255, 255, 26)) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=(255, 255, 255, 35), width=1)


def create_achievement_screen(member: discord.Member, page: int = 0) -> io.BytesIO:
    width, height = 1200, 720
    image = make_ui_canvas(width, height, "night", ["#0f172a", "#1e293b"])
    draw = ImageDraw.Draw(image)
    title_font = load_font(36, True)
    text_font = load_font(22)
    small_font = load_font(18)
    tiny_font = load_font(15)

    draw_text_with_shadow(draw, (42, 34), "Достижения Peach Lounge", title_font)
    metrics = achievement_progress(member)
    done_count = sum(1 for x in metrics if x["done"])
    draw.text((46, 82), f"{member.display_name} • выполнено {done_count}/{len(metrics)}", font=text_font, fill=(225, 232, 255, 220))

    per_page = 5
    max_page = max(0, math.ceil(len(metrics) / per_page) - 1)
    page = max(0, min(page, max_page))
    items = metrics[page * per_page : (page + 1) * per_page]

    y = 128
    for item in items:
        draw_glass(draw, (40, y, width - 40, y + 100), radius=22, fill=(255, 255, 255, 24))
        draw_achievement_symbol(image, draw, (66, y + 20), done=bool(item["done"]))
        draw.text((124, y + 18), item["title"], font=text_font, fill=(255, 255, 255, 242))
        draw.text((124, y + 48), item["desc"], font=small_font, fill=(210, 220, 255, 205))
        progress_text = "Макс. уровень" if item["done"] else f"{item['value']}/{item['target']}"
        draw.text((width - 270, y + 24), progress_text, font=small_font, fill=(255, 255, 255, 235))
        bar_x, bar_y, bar_w, bar_h = 124, y + 76, width - 420, 12
        draw.rounded_rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), radius=6, fill=(10, 12, 20, 175))
        fill_w = int(bar_w * float(item["percent"]))
        if fill_w:
            draw.rounded_rectangle((bar_x, bar_y, bar_x + fill_w, bar_y + bar_h), radius=6, fill=(255, 150, 190, 230))
        y += 112

    draw.text((width // 2 - 70, height - 54), f"Страница {page + 1}/{max_page + 1}", font=small_font, fill=(230, 236, 255, 210))
    out = io.BytesIO()
    image.save(out, format="PNG")
    out.seek(0)
    return out


def create_economy_screen(member: discord.Member, page: int = 0) -> io.BytesIO:
    width, height = 1200, 650
    image = make_ui_canvas(width, height, "cyber", ["#0f172a", "#111827"])
    draw = ImageDraw.Draw(image)
    title_font = load_font(34, True)
    text_font = load_font(22)
    small_font = load_font(17)

    row = bot.db.get_user(member.guild.id, member.id)
    summary = bot.db.transaction_summary(member.guild.id, member.id)
    transactions = bot.db.get_transactions(member.guild.id, member.id, 80)

    draw_text_with_shadow(draw, (42, 34), "📉 Анализ поступлений и расходов", title_font)
    draw.text((46, 78), f"{member.display_name} • баланс {int(row.get('balance', 0)):,} {get_currency_symbol()}".replace(',', ' '), font=text_font, fill=(225, 232, 255, 220))

    draw_glass(draw, (42, 118, 355, 300), radius=24)
    draw.text((70, 148), "За всё время", font=small_font, fill=(210, 220, 255, 200))
    draw.text((70, 178), f"Получено: {summary['total_income']:,} {get_currency_symbol()}".replace(',', ' '), font=text_font, fill=(255, 255, 255, 235))
    draw.text((70, 214), f"Потрачено: {summary['total_expense']:,} {get_currency_symbol()}".replace(',', ' '), font=text_font, fill=(255, 255, 255, 235))
    draw.text((70, 250), f"Оборот: {summary['turnover']:,} {get_currency_symbol()}".replace(',', ' '), font=text_font, fill=(255, 255, 255, 235))

    draw_glass(draw, (380, 118, width - 42, 300), radius=24)
    draw.text((410, 146), "Категории", font=text_font, fill=(255, 255, 255, 235))
    cats = summary["rows"]
    total = max(summary["turnover"], 1)
    y = 184
    for cat in cats[:5]:
        value = int(cat.get("income") or 0) + int(cat.get("expense") or 0)
        percent = value / total
        label = str(cat.get("category", "other"))
        draw.text((410, y), label, font=small_font, fill=(225, 232, 255, 220))
        draw.rounded_rectangle((560, y + 4, 1010, y + 18), radius=7, fill=(20, 22, 34, 180))
        draw.rounded_rectangle((560, y + 4, 560 + int(450 * percent), y + 18), radius=7, fill=(120, 130, 255, 230))
        draw.text((1030, y - 2), f"{value:,}".replace(",", " "), font=small_font, fill=(245, 248, 255, 230))
        y += 30

    draw_glass(draw, (42, 326, width - 42, height - 42), radius=24)
    draw.text((70, 356), "Последние транзакции", font=text_font, fill=(255, 255, 255, 238))
    per_page = 7
    max_page = max(0, math.ceil(len(transactions) / per_page) - 1)
    page = max(0, min(page, max_page))
    y = 398
    for tx in transactions[page * per_page : (page + 1) * per_page]:
        amount = int(tx["amount"])
        sign = "+" if amount > 0 else ""
        created = time.strftime("%d.%m %H:%M", time.localtime(int(tx["created_at"])))
        draw.text((74, y), created, font=small_font, fill=(180, 190, 215, 200))
        draw.text((190, y), str(tx["category"]), font=small_font, fill=(220, 230, 255, 210))
        draw.text((360, y), truncate_text(str(tx["reason"]), 55), font=small_font, fill=(235, 240, 255, 220))
        draw.text((1000, y), f"{sign}{amount:,} {get_currency_symbol()}".replace(',', ' '), font=small_font, fill=(255, 255, 255, 235))
        y += 32
    if not transactions:
        draw.text((74, 410), "Пока нет транзакций. Новые начисления и покупки появятся тут.", font=small_font, fill=(235, 240, 255, 220))
    draw.text((width // 2 - 70, height - 28), f"Страница {page + 1}/{max_page + 1}", font=small_font, fill=(230, 236, 255, 210))
    out = io.BytesIO()
    image.save(out, format="PNG")
    out.seek(0)
    return out


def background_items() -> list[tuple[str, dict[str, Any]]]:
    return list(bot.config.get("profile_backgrounds", {}).items())


def create_shop_screen(member: discord.Member, page: int = 0) -> io.BytesIO:
    width, height = 1200, 650
    image = make_ui_canvas(width, height, "anime_city", ["#0b1020", "#172033"])
    draw = ImageDraw.Draw(image)
    title_font = load_font(34, True)
    text_font = load_font(22)
    small_font = load_font(17)
    tiny_font = load_font(14)

    row = bot.db.get_user(member.guild.id, member.id)
    purchased = {p["item_key"] for p in bot.db.get_purchases(member.guild.id, member.id, "background")}
    purchased.add("default")
    items = background_items()
    per_page = 6
    max_page = max(0, math.ceil(len(items) / per_page) - 1)
    page = max(0, min(page, max_page))

    draw_text_with_shadow(draw, (42, 34), "🛒 Магазин фонов", title_font)
    draw.text((930, 42), f"{int(row.get('balance', 0)):,} {get_currency_symbol()}".replace(',', ' '), font=text_font, fill=(255, 255, 255, 235))

    cards = items[page * per_page : (page + 1) * per_page]
    positions = [(42, 112), (420, 112), (798, 112), (42, 338), (420, 338), (798, 338)]
    for (key, data), (x, y) in zip(cards, positions):
        theme = str(data.get("theme", key))
        colors = data.get("colors", ["#23272A", "#5865F2"])
        card_bg = draw_theme_background((320, 160), theme, colors).resize((320, 160))
        dark = Image.new("RGBA", (320, 160), (0, 0, 0, 80))
        card_bg.alpha_composite(dark)
        mask = Image.new("L", (320, 160), 0)
        ImageDraw.Draw(mask).rounded_rectangle((0, 0, 320, 160), radius=24, fill=255)
        image.paste(card_bg, (x, y), mask)
        draw.rounded_rectangle((x, y, x + 320, y + 160), radius=24, outline=(255, 255, 255, 35), width=1)
        draw.text((x + 20, y + 92), str(data.get("name", key))[:24], font=text_font, fill=(255, 255, 255, 240))
        price = int(data.get("price", 0))
        status = "Куплено" if key in purchased else ("Бесплатно" if price <= 0 else f"{price:,} {get_currency_symbol()}".replace(',', ' '))
        draw.text((x + 20, y + 124), status, font=small_font, fill=(230, 236, 255, 220))
        if row.get("background") == key:
            draw.rounded_rectangle((x + 205, y + 16, x + 300, y + 44), radius=14, fill=(90, 220, 150, 120))
            draw.text((x + 220, y + 21), "Активен", font=tiny_font, fill=(255, 255, 255, 240))

    draw.text((width // 2 - 75, height - 42), f"Страница {page + 1}/{max_page + 1}", font=small_font, fill=(230, 236, 255, 210))
    out = io.BytesIO()
    image.save(out, format="PNG")
    out.seek(0)
    return out


def create_customization_screen(member: discord.Member) -> io.BytesIO:
    width, height = 560, 320
    image = make_ui_canvas(width, height, "sakura", ["#1f1025", "#38213f"])
    draw = ImageDraw.Draw(image)
    title_font = load_font(28, True)
    text_font = load_font(20)
    small_font = load_font(16)
    draw_glass(draw, (20, 20, width - 20, height - 20), radius=24)
    draw.text((42, 44), "🎨 Кастомизация профиля", font=title_font, fill=(255, 255, 255, 245))
    draw.text((42, 98), f"{member.display_name}, выбери раздел ниже.", font=text_font, fill=(225, 232, 255, 220))
    lines = ["• Магазин фонов", "• Инвентарь купленных фонов", "• Скоро: рамки, бейджи, титулы"]
    y = 150
    for line in lines:
        draw.text((50, y), line, font=small_font, fill=(235, 240, 255, 220))
        y += 32
    out = io.BytesIO()
    image.save(out, format="PNG")
    out.seek(0)
    return out


class OwnerOnlyView(discord.ui.View):
    def __init__(self, owner_id: int, timeout: float = 600):
        super().__init__(timeout=timeout)
        self.owner_id = owner_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("Это меню открывал другой участник.", ephemeral=True)
            return False
        return True


class ProfileMainView(OwnerOnlyView):
    def __init__(self, owner_id: int, target_id: int):
        super().__init__(owner_id)
        self.target_id = target_id

    def get_target(self, interaction: discord.Interaction) -> Optional[discord.Member]:
        if interaction.guild is None:
            return None
        return interaction.guild.get_member(self.target_id)

    @discord.ui.button(label="Кастомизация", emoji="🎨", style=discord.ButtonStyle.secondary)
    async def customization(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        member = self.get_target(interaction)
        if member is None:
            await interaction.response.send_message("Участник не найден.", ephemeral=True)
            return
        file = discord.File(create_customization_screen(member), filename="customization.png")
        await interaction.response.send_message(file=file, view=CustomizationView(interaction.user.id, member.id), ephemeral=True)

    @discord.ui.button(label="Достижения", emoji="🏆", style=discord.ButtonStyle.secondary)
    async def achievements(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        member = self.get_target(interaction)
        if member is None:
            await interaction.response.send_message("Участник не найден.", ephemeral=True)
            return
        file = discord.File(create_achievement_screen(member, 0), filename="achievements.png")
        await interaction.response.send_message(file=file, view=AchievementsView(interaction.user.id, member.id, 0), ephemeral=True)

    @discord.ui.button(label="Расходы", emoji="📉", style=discord.ButtonStyle.secondary)
    async def expenses(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        member = self.get_target(interaction)
        if member is None:
            await interaction.response.send_message("Участник не найден.", ephemeral=True)
            return
        file = discord.File(create_economy_screen(member, 0), filename="economy.png")
        await interaction.response.send_message(file=file, view=EconomyView(interaction.user.id, member.id, 0), ephemeral=True)

    @discord.ui.button(label="Магазин фонов", emoji="🛒", style=discord.ButtonStyle.primary)
    async def shop_button(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        member = self.get_target(interaction)
        if member is None:
            await interaction.response.send_message("Участник не найден.", ephemeral=True)
            return
        file = discord.File(create_shop_screen(member, 0), filename="background_shop.png")
        await interaction.response.send_message(file=file, view=BackgroundShopView(interaction.user.id, member.id, 0), ephemeral=True)


class CustomizationView(OwnerOnlyView):
    def __init__(self, owner_id: int, target_id: int):
        super().__init__(owner_id)
        self.target_id = target_id

    @discord.ui.button(label="Магазин фонов", emoji="🛒", style=discord.ButtonStyle.primary)
    async def shop(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        member = interaction.guild.get_member(self.target_id) if interaction.guild else None
        if member is None:
            await interaction.response.send_message("Участник не найден.", ephemeral=True)
            return
        file = discord.File(create_shop_screen(member, 0), filename="background_shop.png")
        await interaction.response.send_message(file=file, view=BackgroundShopView(interaction.user.id, member.id, 0), ephemeral=True)

    @discord.ui.button(label="Инвентарь фонов", emoji="🎒", style=discord.ButtonStyle.secondary)
    async def inventory(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        member = interaction.guild.get_member(self.target_id) if interaction.guild else None
        if member is None:
            await interaction.response.send_message("Участник не найден.", ephemeral=True)
            return
        purchases = bot.db.get_purchases(member.guild.id, member.id, "background")
        owned = ["default"] + [p["item_key"] for p in purchases]
        backgrounds = bot.config.get("profile_backgrounds", {})
        lines = []
        for key in owned[:25]:
            data = backgrounds.get(key, {"name": key})
            marker = "✅" if bot.db.get_user(member.guild.id, member.id).get("background") == key else "▫️"
            lines.append(f"{marker} `{key}` — {data.get('name', key)}")
        embed = discord.Embed(title="🎒 Инвентарь фонов", description="\n".join(lines) if lines else "Пока пусто.", color=discord.Color.blurple())
        await interaction.response.send_message(embed=embed, ephemeral=True)


class PagedImageView(OwnerOnlyView):
    def __init__(self, owner_id: int, target_id: int, page: int = 0):
        super().__init__(owner_id)
        self.target_id = target_id
        self.page = page

    def get_member(self, interaction: discord.Interaction) -> Optional[discord.Member]:
        return interaction.guild.get_member(self.target_id) if interaction.guild else None

    async def redraw(self, interaction: discord.Interaction) -> None:
        raise NotImplementedError

    @discord.ui.button(label="◀", style=discord.ButtonStyle.secondary)
    async def prev_page(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        self.page = max(0, self.page - 1)
        await self.redraw(interaction)

    @discord.ui.button(label="▶", style=discord.ButtonStyle.secondary)
    async def next_page(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        self.page += 1
        await self.redraw(interaction)


class AchievementsView(PagedImageView):
    async def redraw(self, interaction: discord.Interaction) -> None:
        member = self.get_member(interaction)
        if member is None:
            await interaction.response.send_message("Участник не найден.", ephemeral=True)
            return
        max_page = max(0, math.ceil(len(ACHIEVEMENT_DEFS) / 5) - 1)
        self.page = max(0, min(self.page, max_page))
        file = discord.File(create_achievement_screen(member, self.page), filename="achievements.png")
        await interaction.response.edit_message(attachments=[file], view=self)


class EconomyView(PagedImageView):
    async def redraw(self, interaction: discord.Interaction) -> None:
        member = self.get_member(interaction)
        if member is None:
            await interaction.response.send_message("Участник не найден.", ephemeral=True)
            return
        tx_count = len(bot.db.get_transactions(member.guild.id, member.id, 80))
        max_page = max(0, math.ceil(tx_count / 7) - 1)
        self.page = max(0, min(self.page, max_page))
        file = discord.File(create_economy_screen(member, self.page), filename="economy.png")
        await interaction.response.edit_message(attachments=[file], view=self)


class BackgroundSelect(discord.ui.Select):
    def __init__(self, owner_id: int, target_id: int, page: int):
        self.owner_id = owner_id
        self.target_id = target_id
        self.page = page
        items = background_items()
        per_page = 6
        page_items = items[page * per_page : (page + 1) * per_page]
        options = []
        for key, data in page_items:
            price = int(data.get("price", 0))
            options.append(discord.SelectOption(label=str(data.get("name", key))[:100], value=key, description=("Бесплатно" if price <= 0 else f"Цена: {price} {get_currency_symbol()}")[:100]))
        super().__init__(placeholder="Выберите понравившийся фон", min_values=1, max_values=1, options=options or [discord.SelectOption(label="Нет фонов", value="none")])

    async def callback(self, interaction: discord.Interaction) -> None:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("Это меню открывал другой участник.", ephemeral=True)
            return
        if interaction.guild is None:
            await interaction.response.send_message("Команда работает только на сервере.", ephemeral=True)
            return
        member = interaction.guild.get_member(self.target_id)
        if member is None:
            await interaction.response.send_message("Участник не найден.", ephemeral=True)
            return
        key = self.values[0]
        backgrounds = bot.config.get("profile_backgrounds", {})
        if key not in backgrounds:
            await interaction.response.send_message("Фон не найден.", ephemeral=True)
            return
        data = backgrounds[key]
        price = int(data.get("price", 0))
        guild_id, user_id = member.guild.id, member.id
        if price <= 0 or bot.db.has_purchase(guild_id, user_id, "background", key):
            bot.db.set_background(guild_id, user_id, key)
            await interaction.response.send_message(f"Фон **{data.get('name', key)}** установлен ✅", ephemeral=True)
            return
        row = bot.db.get_user(guild_id, user_id)
        if int(row.get("balance", 0)) < price:
            await interaction.response.send_message(f"Не хватает монет. Нужно **{price} 🪙**, у тебя **{row.get('balance', 0)} 🪙**.", ephemeral=True)
            return
        bot.db.add_balance(guild_id, user_id, -price, "shop", f"Покупка фона: {data.get('name', key)}")
        bot.db.add_purchase(guild_id, user_id, "background", key)
        bot.db.set_background(guild_id, user_id, key)
        await interaction.response.send_message(f"Куплено и установлено: **{data.get('name', key)}** за **{price} 🪙** ✅", ephemeral=True)


class BackgroundShopView(PagedImageView):
    def __init__(self, owner_id: int, target_id: int, page: int = 0):
        super().__init__(owner_id, target_id, page)
        self.rebuild_select()

    def rebuild_select(self) -> None:
        # remove old selects
        self.clear_items()
        self.add_item(BackgroundSelect(self.owner_id, self.target_id, self.page))
        prev_button = discord.ui.Button(label="◀", style=discord.ButtonStyle.secondary)
        next_button = discord.ui.Button(label="▶", style=discord.ButtonStyle.secondary)
        async def prev_cb(interaction: discord.Interaction):
            if interaction.user.id != self.owner_id:
                await interaction.response.send_message("Это меню открывал другой участник.", ephemeral=True)
                return
            self.page = max(0, self.page - 1)
            await self.redraw(interaction)
        async def next_cb(interaction: discord.Interaction):
            if interaction.user.id != self.owner_id:
                await interaction.response.send_message("Это меню открывал другой участник.", ephemeral=True)
                return
            self.page += 1
            await self.redraw(interaction)
        prev_button.callback = prev_cb
        next_button.callback = next_cb
        self.add_item(prev_button)
        self.add_item(next_button)

    async def redraw(self, interaction: discord.Interaction) -> None:
        member = self.get_member(interaction)
        if member is None:
            await interaction.response.send_message("Участник не найден.", ephemeral=True)
            return
        max_page = max(0, math.ceil(len(background_items()) / 6) - 1)
        self.page = max(0, min(self.page, max_page))
        self.rebuild_select()
        file = discord.File(create_shop_screen(member, self.page), filename="background_shop.png")
        await interaction.response.edit_message(attachments=[file], view=self)

# ------------------------- HELPERS -------------------------
def is_admin_target_valid(interaction: discord.Interaction, target: discord.Member) -> tuple[bool, str]:
    if interaction.guild is None or not isinstance(interaction.user, discord.Member):
        return False, "Команда работает только на сервере."
    if target == interaction.guild.owner:
        return False, "Нельзя применить это действие к владельцу сервера."
    if interaction.user != interaction.guild.owner and target.top_role >= interaction.user.top_role:
        return False, "Этого участника нельзя трогать: его роль равна или выше твоей."
    bot_member = interaction.guild.me
    if bot_member is None or target.top_role >= bot_member.top_role:
        return False, "Я не могу трогать этого участника: его роль выше или равна моей."
    return True, ""


async def background_autocomplete(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
    backgrounds = bot.config.get("profile_backgrounds", {})
    current_lower = current.lower()
    choices = []
    for key, data in backgrounds.items():
        label = f"{data.get('name', key)} / {key}"
        if current_lower in key.lower() or current_lower in label.lower():
            choices.append(app_commands.Choice(name=label[:100], value=key))
    return choices[:25]


async def relation_type_autocomplete(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
    choices = []
    cur = current.lower()
    for key, label in RELATIONSHIP_LABELS.items():
        if cur in key or cur in label.lower():
            choices.append(app_commands.Choice(name=f"{label} ({key})", value=key))
    return choices[:25]


async def embed_template_autocomplete(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
    templates = bot.config.get("embed_templates", {})
    cur = current.lower()
    choices = []
    for key, data in templates.items():
        title = str(data.get("title", key))
        if cur in key.lower() or cur in title.lower():
            choices.append(app_commands.Choice(name=f"{title[:70]} / {key}", value=key))
    return choices[:25]


def render_template_text(value: str, guild: discord.Guild, member: discord.Member | None = None) -> str:
    member = member or guild.me
    return str(value).format(
        server=guild.name,
        count=guild.member_count,
        bot=guild.me.mention if guild.me else "бот",
        member=member.mention if member else "участник",
        user=member.display_name if member else "участник",
    )


# ------------------------- COMMANDS -------------------------
@bot.tree.command(name="help_admin", description="Список основных функций бота")
@app_commands.guild_only()
async def help_admin(interaction: discord.Interaction) -> None:
    embed = discord.Embed(title="📘 Что умеет бот", color=discord.Color.blurple())
    embed.add_field(
        name="Модерация и защита",
        value="/clear, /purge_user, /kick, /ban, /timeout, /untimeout, /slowmode, /warn, /warnings, /clearwarnings, /lock, /unlock, /addrole, /removerole, /nickname, /antispam, /antispam_status, /security_check",
        inline=False,
    )
    embed.add_field(
        name="Роли / XP / профиль",
        value="/rolepanel, /profile, /leaderboard, /balance, /shop, /buy_background, /set_background, /voice_xp_config, /set_voice_xp, /list_level_roles, /set_level_role, /remove_level_role",
        inline=False,
    )
    embed.add_field(
        name="Связи и приветствие",
        value="/relationship_request, /relationships, /relationship_break, /embed_send, /embed_templates, /embed_template_send, /setup_welcome",
        inline=False,
    )
    embed.set_footer(text="Peach Lounge Bot • AntiSpam включён по умолчанию")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="antispam", description="Включить или настроить защиту от спама")
@app_commands.guild_only()
@app_commands.default_permissions(manage_guild=True)
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(
    enabled="Включить или выключить защиту",
    timeout_minutes="Тайм-аут за подтверждённый спам или угрозу",
    log_channel="Закрытый канал для тревог",
    moderator_role="Роль модераторов для пинга",
    administrator_role="Роль администраторов для пинга",
)
async def antispam_config_command(
    interaction: discord.Interaction,
    enabled: bool,
    timeout_minutes: app_commands.Range[int, 1, 10080] = 60,
    log_channel: Optional[discord.TextChannel] = None,
    moderator_role: Optional[discord.Role] = None,
    administrator_role: Optional[discord.Role] = None,
) -> None:
    settings = bot.antispam_settings()
    settings["enabled"] = bool(enabled)
    settings["timeout_minutes"] = int(timeout_minutes)
    if log_channel is not None:
        settings["log_channel_id"] = log_channel.id

    existing_ids = {int(x) for x in settings.get("alert_role_ids", []) if str(x).isdigit()}
    legacy_id = int(settings.get("alert_role_id", 0) or 0)
    if legacy_id:
        existing_ids.add(legacy_id)
    if moderator_role is not None:
        existing_ids.add(moderator_role.id)
        settings["alert_role_id"] = moderator_role.id
    if administrator_role is not None:
        existing_ids.add(administrator_role.id)
    settings["alert_role_ids"] = sorted(existing_ids)
    bot.save_config()

    saved_channel = interaction.guild.get_channel(int(settings.get("log_channel_id", 0) or 0))
    roles = bot.security_alert_roles(interaction.guild)
    role_text = " ".join(role.mention for role in roles) if roles else "не заданы"
    await interaction.response.send_message(
        f"🛡️ Защита: **{'включена' if enabled else 'выключена'}**\n"
        f"Тайм-аут: **{timeout_minutes} мин.**\n"
        f"Логи: {saved_channel.mention if saved_channel else 'системный канал'}\n"
        f"Пингуемые роли: {role_text}\n"
        "Одиночные неизвестные ссылки не удаляются: они уходят модерации на проверку.",
        ephemeral=True,
        allowed_mentions=discord.AllowedMentions.none(),
    )


@bot.tree.command(name="antispam_status", description="Показать состояние защиты от спама")
@app_commands.guild_only()
@app_commands.default_permissions(manage_guild=True)
@app_commands.checks.has_permissions(manage_guild=True)
async def antispam_status(interaction: discord.Interaction) -> None:
    settings = bot.antispam_settings()
    log_channel = interaction.guild.get_channel(int(settings.get("log_channel_id", 0) or 0))
    alert_roles = bot.security_alert_roles(interaction.guild)
    bot_member = interaction.guild.me
    permissions_ok = bool(
        bot_member
        and bot_member.guild_permissions.manage_messages
        and bot_member.guild_permissions.moderate_members
        and bot_member.guild_permissions.read_message_history
    )
    voice_permissions_ok = bool(bot_member and bot_member.guild_permissions.move_members)
    google_ready = bool(os.getenv("SAFE_BROWSING_API_KEY", "").strip())
    vt_ready = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip())
    embed = discord.Embed(
        title="🛡️ Peach Security",
        color=discord.Color.green() if settings.get("enabled", True) and permissions_ok else discord.Color.orange(),
    )
    embed.add_field(name="Состояние", value="✅ Включена" if settings.get("enabled", True) else "❌ Выключена")
    embed.add_field(name="Тайм-аут", value=f"{settings.get('timeout_minutes', 60)} мин.")
    embed.add_field(name="Логи", value=log_channel.mention if log_channel else "Системный канал")
    embed.add_field(
        name="Тревога",
        value=" ".join(role.mention for role in alert_roles) if alert_roles else "Роли не заданы",
        inline=False,
    )
    embed.add_field(
        name="Проверка ссылок и файлов",
        value=(
            f"Google Safe Browsing: {'✅' if google_ready else '❌ нет ключа'}\n"
            f"VirusTotal: {'✅' if vt_ready else '❌ нет ключа'}\n"
            "Без ключей бот всё равно ловит флуд и пингует модерацию, но не может надёжно подтвердить репутацию."
        ),
        inline=False,
    )
    embed.add_field(
        name="Что удаляется автоматически",
        value=(
            "• массовый флуд и рассылка по каналам\n"
            "• повтор одной ссылки\n"
            "• массовые упоминания\n"
            "• ссылка или файл, подтверждённые репутационным сервисом"
        ),
        inline=False,
    )
    embed.add_field(
        name="Голосовые каналы",
        value=(
            "✅ текстовые чаты голосовых отслеживаются\n"
            f"{'✅' if voice_permissions_ok else '⚠️'} защита от частых входов/выходов и переходов"
        ),
        inline=False,
    )
    embed.add_field(
        name="Права бота",
        value=(
            "✅ Основные права есть"
            if permissions_ok
            else "⚠️ Нужны Manage Messages, Read Message History и Moderate Members. Для отключения от голосового нужен Move Members."
        ),
        inline=False,
    )
    await interaction.response.send_message(
        embed=embed,
        ephemeral=True,
        allowed_mentions=discord.AllowedMentions.none(),
    )


@bot.tree.command(name="security_check", description="Проверить ссылку без её открытия")
@app_commands.guild_only()
@app_commands.default_permissions(manage_messages=True)
@app_commands.checks.has_permissions(manage_messages=True)
@app_commands.describe(link="Полная ссылка с http:// или https://")
async def security_check(interaction: discord.Interaction, link: str) -> None:
    await interaction.response.defer(ephemeral=True)
    verdicts = await bot.security_scanner.scan_urls([link])
    if not verdicts:
        await interaction.followup.send("Не удалось распознать HTTP/HTTPS-ссылку.", ephemeral=True)
        return
    verdict = verdicts[0]
    reasons = "\n".join(f"• {item}" for item in verdict.reasons[:8])
    providers = ", ".join(verdict.providers) if verdict.providers else "только локальная проверка"
    await interaction.followup.send(
        f"**Результат:** {verdict.status_label}\n"
        f"**Ссылка:** `{bot.defang_security_item(verdict.item)}`\n"
        f"**Источники:** {providers}\n"
        f"{reasons}",
        ephemeral=True,
        allowed_mentions=discord.AllowedMentions.none(),
    )


@bot.tree.command(name="purge_user", description="Удалить сообщения участника во всех текстовых и голосовых чатах")
@app_commands.guild_only()
@app_commands.default_permissions(manage_messages=True)
@app_commands.checks.has_permissions(manage_messages=True)
@app_commands.describe(member="Чьи сообщения удалить", minutes="За сколько последних минут искать")
async def purge_user(
    interaction: discord.Interaction,
    member: discord.Member,
    minutes: app_commands.Range[int, 1, 10080] = 120,
) -> None:
    await interaction.response.defer(ephemeral=True)
    after = discord.utils.utcnow() - timedelta(minutes=int(minutes))
    deleted_total = 0
    checked_channels = 0
    failed_channels = 0

    targets: list[discord.abc.GuildChannel] = []
    targets.extend(interaction.guild.text_channels)
    targets.extend(interaction.guild.voice_channels)
    targets.extend(thread for thread in interaction.guild.threads if not thread.archived)

    for channel in targets:
        bot_member = interaction.guild.me
        if bot_member is None or not isinstance(channel, discord.abc.Messageable):
            continue
        permissions = channel.permissions_for(bot_member)
        if not (permissions.view_channel and permissions.read_message_history and permissions.manage_messages):
            continue
        checked_channels += 1
        try:
            if isinstance(channel, (discord.TextChannel, discord.Thread)):
                deleted = await channel.purge(
                    limit=1000,
                    check=lambda msg: msg.author.id == member.id,
                    after=after,
                    reason=f"Emergency cleanup by {interaction.user}",
                )
                deleted_total += len(deleted)
            else:
                async for candidate in channel.history(limit=1000, after=after):
                    if candidate.author.id != member.id:
                        continue
                    try:
                        await candidate.delete()
                        deleted_total += 1
                    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                        continue
        except (discord.Forbidden, discord.HTTPException):
            failed_channels += 1

    await interaction.followup.send(
        f"🧹 Готово. Удалено сообщений от {member.mention}: **{deleted_total}**\n"
        f"Проверено текстовых и голосовых чатов: **{checked_channels}**"
        + (f"\nНе удалось проверить: **{failed_channels}**" if failed_channels else ""),
        ephemeral=True,
        allowed_mentions=discord.AllowedMentions.none(),
    )


@bot.tree.command(name="clear", description="Удалить сообщения в текущем канале")
@app_commands.guild_only()
@app_commands.default_permissions(manage_messages=True)
@app_commands.describe(amount="Количество сообщений: от 1 до 100")
async def clear(interaction: discord.Interaction, amount: app_commands.Range[int, 1, 100]) -> None:
    if not isinstance(interaction.channel, (discord.TextChannel, discord.Thread)):
        await interaction.response.send_message("Эта команда работает только в текстовом канале.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    deleted = await interaction.channel.purge(limit=int(amount), reason=f"Clear by {interaction.user}")
    await interaction.followup.send(f"Готово. Удалено сообщений: **{len(deleted)}**.", ephemeral=True)


@bot.tree.command(name="kick", description="Кикнуть участника")
@app_commands.guild_only()
@app_commands.default_permissions(kick_members=True)
@app_commands.describe(member="Кого кикнуть", reason="Причина")
async def kick(interaction: discord.Interaction, member: discord.Member, reason: Optional[str] = None) -> None:
    ok, message = is_admin_target_valid(interaction, member)
    if not ok:
        await interaction.response.send_message(message, ephemeral=True)
        return
    await member.kick(reason=reason or f"Kick by {interaction.user}")
    await interaction.response.send_message(f"{member.mention} кикнут. Причина: {reason or 'не указана'}", ephemeral=True)


@bot.tree.command(name="ban", description="Забанить участника")
@app_commands.guild_only()
@app_commands.default_permissions(ban_members=True)
@app_commands.describe(member="Кого забанить", reason="Причина", delete_days="Удалить сообщения за N дней, 0-7")
async def ban(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: Optional[str] = None,
    delete_days: app_commands.Range[int, 0, 7] = 0,
) -> None:
    ok, message = is_admin_target_valid(interaction, member)
    if not ok:
        await interaction.response.send_message(message, ephemeral=True)
        return
    await member.ban(reason=reason or f"Ban by {interaction.user}", delete_message_seconds=int(delete_days) * 86400)
    await interaction.response.send_message(f"{member.mention} забанен. Причина: {reason or 'не указана'}", ephemeral=True)


@bot.tree.command(name="timeout", description="Выдать таймаут участнику")
@app_commands.guild_only()
@app_commands.default_permissions(moderate_members=True)
@app_commands.describe(member="Кому выдать таймаут", minutes="На сколько минут", reason="Причина")
async def timeout(
    interaction: discord.Interaction,
    member: discord.Member,
    minutes: app_commands.Range[int, 1, 40320],
    reason: Optional[str] = None,
) -> None:
    ok, message = is_admin_target_valid(interaction, member)
    if not ok:
        await interaction.response.send_message(message, ephemeral=True)
        return
    until = discord.utils.utcnow() + timedelta(minutes=int(minutes))
    await member.timeout(until, reason=reason or f"Timeout by {interaction.user}")
    await interaction.response.send_message(
        f"{member.mention} получил таймаут на **{minutes} мин.** Причина: {reason or 'не указана'}",
        ephemeral=True,
    )


@bot.tree.command(name="untimeout", description="Снять таймаут с участника")
@app_commands.guild_only()
@app_commands.default_permissions(moderate_members=True)
@app_commands.describe(member="С кого снять таймаут", reason="Причина")
async def untimeout(interaction: discord.Interaction, member: discord.Member, reason: Optional[str] = None) -> None:
    ok, message = is_admin_target_valid(interaction, member)
    if not ok:
        await interaction.response.send_message(message, ephemeral=True)
        return
    await member.timeout(None, reason=reason or f"Untimeout by {interaction.user}")
    await interaction.response.send_message(f"Таймаут снят с {member.mention}.", ephemeral=True)


@bot.tree.command(name="slowmode", description="Поставить slowmode в канале")
@app_commands.guild_only()
@app_commands.default_permissions(manage_channels=True)
@app_commands.describe(seconds="Задержка в секундах, 0 выключает", channel="Канал, по умолчанию текущий")
async def slowmode(
    interaction: discord.Interaction,
    seconds: app_commands.Range[int, 0, 21600],
    channel: Optional[discord.TextChannel] = None,
) -> None:
    target = channel or interaction.channel
    if not isinstance(target, discord.TextChannel):
        await interaction.response.send_message("Выбери текстовый канал.", ephemeral=True)
        return
    await target.edit(slowmode_delay=int(seconds), reason=f"Slowmode by {interaction.user}")
    await interaction.response.send_message(f"Slowmode в {target.mention}: **{seconds} сек.**", ephemeral=True)


@bot.tree.command(name="lock", description="Закрыть канал для everyone")
@app_commands.guild_only()
@app_commands.default_permissions(manage_channels=True)
@app_commands.describe(channel="Канал, по умолчанию текущий")
async def lock(interaction: discord.Interaction, channel: Optional[discord.TextChannel] = None) -> None:
    target = channel or interaction.channel
    if not isinstance(target, discord.TextChannel):
        await interaction.response.send_message("Выбери текстовый канал.", ephemeral=True)
        return
    overwrite = target.overwrites_for(interaction.guild.default_role)
    overwrite.send_messages = False
    await target.set_permissions(interaction.guild.default_role, overwrite=overwrite, reason=f"Lock by {interaction.user}")
    await interaction.response.send_message(f"🔒 Канал {target.mention} закрыт.", ephemeral=True)


@bot.tree.command(name="unlock", description="Открыть канал для everyone")
@app_commands.guild_only()
@app_commands.default_permissions(manage_channels=True)
@app_commands.describe(channel="Канал, по умолчанию текущий")
async def unlock(interaction: discord.Interaction, channel: Optional[discord.TextChannel] = None) -> None:
    target = channel or interaction.channel
    if not isinstance(target, discord.TextChannel):
        await interaction.response.send_message("Выбери текстовый канал.", ephemeral=True)
        return
    overwrite = target.overwrites_for(interaction.guild.default_role)
    overwrite.send_messages = None
    await target.set_permissions(interaction.guild.default_role, overwrite=overwrite, reason=f"Unlock by {interaction.user}")
    await interaction.response.send_message(f"🔓 Канал {target.mention} открыт.", ephemeral=True)


@bot.tree.command(name="warn", description="Выдать предупреждение")
@app_commands.guild_only()
@app_commands.default_permissions(moderate_members=True)
@app_commands.describe(member="Кого предупредить", reason="Причина")
async def warn(interaction: discord.Interaction, member: discord.Member, reason: str) -> None:
    ok, message = is_admin_target_valid(interaction, member)
    if not ok:
        await interaction.response.send_message(message, ephemeral=True)
        return
    warn_id = bot.db.add_warning(interaction.guild.id, member.id, interaction.user.id, reason)
    warnings_count = len(bot.db.get_warnings(interaction.guild.id, member.id))
    await interaction.response.send_message(
        f"⚠️ {member.mention} получил предупреждение **#{warn_id}**. Всего варнов: **{warnings_count}**.",
        ephemeral=True,
    )


@bot.tree.command(name="warnings", description="Посмотреть предупреждения участника")
@app_commands.guild_only()
@app_commands.default_permissions(moderate_members=True)
@app_commands.describe(member="Чьи предупреждения посмотреть")
async def warnings(interaction: discord.Interaction, member: discord.Member) -> None:
    data = bot.db.get_warnings(interaction.guild.id, member.id)
    if not data:
        await interaction.response.send_message(f"У {member.mention} нет предупреждений.", ephemeral=True)
        return
    lines = []
    for item in data[:10]:
        moderator = interaction.guild.get_member(int(item["moderator_id"]))
        mod_name = moderator.display_name if moderator else f"ID {item['moderator_id']}"
        created = time.strftime("%d.%m.%Y", time.localtime(item["created_at"]))
        lines.append(f"**#{item['id']}** • {created} • {mod_name}\n└ {item['reason']}")
    embed = discord.Embed(title=f"⚠️ Варны {member.display_name}", description="\n".join(lines), color=discord.Color.orange())
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="clearwarnings", description="Очистить предупреждения участника")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@app_commands.describe(member="Кому очистить предупреждения")
async def clearwarnings(interaction: discord.Interaction, member: discord.Member) -> None:
    bot.db.clear_warnings(interaction.guild.id, member.id)
    await interaction.response.send_message(f"Варны для {member.mention} очищены.", ephemeral=True)


@bot.tree.command(name="addrole", description="Выдать роль участнику")
@app_commands.guild_only()
@app_commands.default_permissions(manage_roles=True)
async def addrole(interaction: discord.Interaction, member: discord.Member, role: discord.Role) -> None:
    ok, message = is_admin_target_valid(interaction, member)
    if not ok:
        await interaction.response.send_message(message, ephemeral=True)
        return
    if interaction.guild.me is None or role >= interaction.guild.me.top_role:
        await interaction.response.send_message("Я не могу выдать эту роль — она выше или равна моей.", ephemeral=True)
        return
    await member.add_roles(role, reason=f"Addrole by {interaction.user}")
    await interaction.response.send_message(f"Роль {role.mention} выдана {member.mention}.", ephemeral=True)


@bot.tree.command(name="removerole", description="Снять роль с участника")
@app_commands.guild_only()
@app_commands.default_permissions(manage_roles=True)
async def removerole(interaction: discord.Interaction, member: discord.Member, role: discord.Role) -> None:
    ok, message = is_admin_target_valid(interaction, member)
    if not ok:
        await interaction.response.send_message(message, ephemeral=True)
        return
    if interaction.guild.me is None or role >= interaction.guild.me.top_role:
        await interaction.response.send_message("Я не могу снять эту роль — она выше или равна моей.", ephemeral=True)
        return
    await member.remove_roles(role, reason=f"Removerole by {interaction.user}")
    await interaction.response.send_message(f"Роль {role.mention} снята с {member.mention}.", ephemeral=True)


@bot.tree.command(name="nickname", description="Изменить ник участнику")
@app_commands.guild_only()
@app_commands.default_permissions(manage_nicknames=True)
async def nickname(interaction: discord.Interaction, member: discord.Member, new_nickname: str) -> None:
    ok, message = is_admin_target_valid(interaction, member)
    if not ok:
        await interaction.response.send_message(message, ephemeral=True)
        return
    await member.edit(nick=new_nickname, reason=f"Nickname by {interaction.user}")
    await interaction.response.send_message(f"Ник {member.mention} изменён на **{new_nickname}**.", ephemeral=True)


@bot.tree.command(name="rolepanel", description="Отправить панель выбора ролей")
@app_commands.guild_only()
@app_commands.default_permissions(manage_roles=True)
@app_commands.describe(channel="Куда отправить панель, по умолчанию текущий канал")
async def rolepanel(interaction: discord.Interaction, channel: Optional[discord.TextChannel] = None) -> None:
    target = channel or interaction.channel
    if not isinstance(target, discord.TextChannel):
        await interaction.response.send_message("Выбери текстовый канал.", ephemeral=True)
        return
    categories = get_role_categories(bot.config)
    if not categories:
        await interaction.response.send_message("В config.json не настроены роли для панели.", ephemeral=True)
        return
    if len(categories) > 5:
        await interaction.response.send_message("В одной панели Discord максимум 5 меню. Раздели роли на 5 категорий или меньше.", ephemeral=True)
        return
    embed = discord.Embed(
        title="🎭 Выбор ролей",
        description=(
            "Выбери нужный пункт в меню ниже.\n"
            "В играх/увлечениях/позициях выбор переключает роль.\n"
            "В категории ранга новый выбор заменяет прошлый ранг."
        ),
        color=discord.Color.blurple(),
    )
    embed.add_field(name="Категории", value=" • ".join(cat.get("name", "Категория") for cat in categories), inline=False)
    await target.send(embed=embed, view=RolePanelView(bot))
    await interaction.response.send_message(f"Панель отправлена в {target.mention}.", ephemeral=True)


@bot.tree.command(name="profile", description="Показать интерактивный профиль участника")
@app_commands.guild_only()
@app_commands.describe(member="Чей профиль показать")
async def profile(interaction: discord.Interaction, member: Optional[discord.Member] = None) -> None:
    target = member or interaction.user
    if not isinstance(target, discord.Member):
        await interaction.response.send_message("Участник не найден.", ephemeral=True)
        return
    await interaction.response.defer()
    image = await create_profile_card(target)
    file = discord.File(image, filename="profile.png")
    await interaction.followup.send(file=file, view=ProfileMainView(interaction.user.id, target.id))


@bot.tree.command(name="achievements", description="Показать достижения участника")
@app_commands.guild_only()
@app_commands.describe(member="Чьи достижения показать")
async def achievements(interaction: discord.Interaction, member: Optional[discord.Member] = None) -> None:
    target = member or interaction.user
    if not isinstance(target, discord.Member):
        await interaction.response.send_message("Участник не найден.", ephemeral=True)
        return
    file = discord.File(create_achievement_screen(target, 0), filename="achievements.png")
    await interaction.response.send_message(file=file, view=AchievementsView(interaction.user.id, target.id, 0), ephemeral=True)


@bot.tree.command(name="transactions", description="Показать расходы и поступления участника")
@app_commands.guild_only()
@app_commands.describe(member="Чью экономику показать")
async def transactions(interaction: discord.Interaction, member: Optional[discord.Member] = None) -> None:
    target = member or interaction.user
    if not isinstance(target, discord.Member):
        await interaction.response.send_message("Участник не найден.", ephemeral=True)
        return
    file = discord.File(create_economy_screen(target, 0), filename="economy.png")
    await interaction.response.send_message(file=file, view=EconomyView(interaction.user.id, target.id, 0), ephemeral=True)


@bot.tree.command(name="background_shop", description="Открыть красивый магазин фонов профиля")
@app_commands.guild_only()
async def background_shop(interaction: discord.Interaction) -> None:
    if not isinstance(interaction.user, discord.Member):
        await interaction.response.send_message("Команда работает только на сервере.", ephemeral=True)
        return
    file = discord.File(create_shop_screen(interaction.user, 0), filename="background_shop.png")
    await interaction.response.send_message(file=file, view=BackgroundShopView(interaction.user.id, interaction.user.id, 0), ephemeral=True)


@bot.tree.command(name="balance", description="Показать баланс участника")
@app_commands.guild_only()
@app_commands.describe(member="Чей баланс показать")
async def balance(interaction: discord.Interaction, member: Optional[discord.Member] = None) -> None:
    target = member or interaction.user
    if not isinstance(target, discord.Member):
        await interaction.response.send_message("Участник не найден.", ephemeral=True)
        return
    row = bot.db.get_user(target.guild.id, target.id)
    await interaction.response.send_message(f"Баланс {target.mention}: **{row['balance']} 🪙**")


@bot.tree.command(name="shop", description="Магазин кастомизации профиля")
@app_commands.guild_only()
async def shop(interaction: discord.Interaction) -> None:
    backgrounds = bot.config.get("profile_backgrounds", {})
    embed = discord.Embed(title="🛒 Магазин фонов профиля", color=discord.Color.gold())
    for key, data in backgrounds.items():
        price = int(data.get("price", 0))
        theme = str(data.get("theme", key))
        embed.add_field(
            name=f"{data.get('name', key)} / `{key}`",
            value=("Бесплатно" if price <= 0 else f"Цена: **{price} 🪙**") + f"\nТема: **{theme}**",
            inline=False,
        )
    embed.set_footer(text="Купить: /buy_background | Поставить: /set_background")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="buy_background", description="Купить фон профиля")
@app_commands.guild_only()
@app_commands.describe(background="Ключ фона из /shop")
async def buy_background(interaction: discord.Interaction, background: str) -> None:
    if interaction.guild is None:
        await interaction.response.send_message("Команда работает только на сервере.", ephemeral=True)
        return
    backgrounds = bot.config.get("profile_backgrounds", {})
    if background not in backgrounds:
        await interaction.response.send_message("Такого фона нет. Посмотри /shop.", ephemeral=True)
        return
    user_id = interaction.user.id
    guild_id = interaction.guild.id
    data = backgrounds[background]
    price = int(data.get("price", 0))
    if price <= 0:
        bot.db.set_background(guild_id, user_id, background)
        await interaction.response.send_message(f"Фон **{data.get('name', background)}** установлен.", ephemeral=True)
        return
    if bot.db.has_purchase(guild_id, user_id, "background", background):
        bot.db.set_background(guild_id, user_id, background)
        await interaction.response.send_message("У тебя уже есть этот фон, я сразу поставил его в профиль.", ephemeral=True)
        return
    row = bot.db.get_user(guild_id, user_id)
    if row["balance"] < price:
        await interaction.response.send_message(f"Не хватает монет. Нужно **{price} 🪙**, у тебя **{row['balance']} 🪙**.", ephemeral=True)
        return
    bot.db.add_balance(guild_id, user_id, -price, "shop", f"Покупка фона: {data.get('name', background)}")
    bot.db.add_purchase(guild_id, user_id, "background", background)
    bot.db.set_background(guild_id, user_id, background)
    await interaction.response.send_message(f"Куплено и установлено: **{data.get('name', background)}** за **{price} 🪙**.", ephemeral=True)


@buy_background.autocomplete("background")
async def buy_background_autocomplete(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
    return await background_autocomplete(interaction, current)


@bot.tree.command(name="set_background", description="Поставить купленный фон профиля")
@app_commands.guild_only()
@app_commands.describe(background="Ключ фона из /shop")
async def set_background(interaction: discord.Interaction, background: str) -> None:
    if interaction.guild is None:
        await interaction.response.send_message("Команда работает только на сервере.", ephemeral=True)
        return
    backgrounds = bot.config.get("profile_backgrounds", {})
    if background not in backgrounds:
        await interaction.response.send_message("Такого фона нет. Посмотри /shop.", ephemeral=True)
        return
    price = int(backgrounds[background].get("price", 0))
    if price > 0 and not bot.db.has_purchase(interaction.guild.id, interaction.user.id, "background", background):
        await interaction.response.send_message("Ты ещё не купил этот фон. Используй /buy_background.", ephemeral=True)
        return
    bot.db.set_background(interaction.guild.id, interaction.user.id, background)
    await interaction.response.send_message(f"Фон профиля установлен: **{backgrounds[background].get('name', background)}**.", ephemeral=True)


@set_background.autocomplete("background")
async def set_background_autocomplete(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
    return await background_autocomplete(interaction, current)


@bot.tree.command(name="voice_xp_config", description="Показать настройки голосового XP")
@app_commands.guild_only()
@app_commands.default_permissions(manage_guild=True)
async def voice_xp_config(interaction: discord.Interaction) -> None:
    settings = bot.xp_settings()
    leveling = bot.leveling_settings()
    level_roles = leveling.get("level_roles", [])
    lines = []
    for item in sorted(level_roles, key=lambda x: int(x.get("level", 0))):
        role = interaction.guild.get_role(int(item.get("role_id", 0))) if interaction.guild else None
        lines.append(f"LVL {item.get('level')}: {role.mention if role else item.get('role_id')}")
    embed = discord.Embed(title="🎙️ Настройки XP в голосовых", color=discord.Color.blurple())
    embed.add_field(name="XP / мин", value=str(settings.get("xp_per_minute", 5)), inline=True)
    embed.add_field(name="Монеты / мин", value=str(settings.get("coins_per_minute", 1)), inline=True)
    embed.add_field(name="Мин. людей в канале", value=str(settings.get("min_members_in_channel", 1)), inline=True)
    embed.add_field(name="Формула уровня", value=f"base_xp={leveling.get('base_xp',100)}, curve={leveling.get('curve',2)}", inline=False)
    embed.add_field(name="Роли за уровни", value="\n".join(lines) if lines else "Не настроены", inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="set_voice_xp", description="Настроить XP/монеты за голосовой канал")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@app_commands.describe(xp_per_minute="Сколько XP за минуту", coins_per_minute="Сколько монет за минуту", min_members_in_channel="Минимум людей в ГС")
async def set_voice_xp(
    interaction: discord.Interaction,
    xp_per_minute: app_commands.Range[int, 0, 1000],
    coins_per_minute: app_commands.Range[int, 0, 1000],
    min_members_in_channel: app_commands.Range[int, 1, 99],
) -> None:
    settings = bot.xp_settings()
    settings["xp_per_minute"] = int(xp_per_minute)
    settings["coins_per_minute"] = int(coins_per_minute)
    settings["min_members_in_channel"] = int(min_members_in_channel)
    bot.save_config()
    await interaction.response.send_message(
        f"Настройки обновлены: XP/мин **{xp_per_minute}**, монеты/мин **{coins_per_minute}**, мин. людей **{min_members_in_channel}**.",
        ephemeral=True,
    )


@bot.tree.command(name="list_level_roles", description="Показать роли, выдаваемые за уровни")
@app_commands.guild_only()
@app_commands.default_permissions(manage_guild=True)
async def list_level_roles(interaction: discord.Interaction) -> None:
    level_roles = bot.leveling_settings().get("level_roles", [])
    if not level_roles:
        await interaction.response.send_message("Роли за уровни пока не настроены.", ephemeral=True)
        return
    lines = []
    for item in sorted(level_roles, key=lambda x: int(x.get("level", 0))):
        role = interaction.guild.get_role(int(item.get("role_id", 0))) if interaction.guild else None
        lines.append(f"**LVL {item.get('level')}** → {role.mention if role else item.get('role_id')}")
    await interaction.response.send_message("\n".join(lines), ephemeral=True)


@bot.tree.command(name="set_level_role", description="Добавить/обновить роль за уровень")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
async def set_level_role(interaction: discord.Interaction, level: app_commands.Range[int, 1, 1000], role: discord.Role) -> None:
    settings = bot.leveling_settings()
    level_roles = settings.setdefault("level_roles", [])
    updated = False
    for item in level_roles:
        if int(item.get("level", 0)) == int(level):
            item["role_id"] = role.id
            updated = True
            break
    if not updated:
        level_roles.append({"level": int(level), "role_id": role.id})
    level_roles.sort(key=lambda x: int(x.get("level", 0)))
    bot.save_config()
    await interaction.response.send_message(f"Готово: за **{level}** уровень будет выдаваться {role.mention}.", ephemeral=True)


@bot.tree.command(name="remove_level_role", description="Удалить настройку роли за уровень")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
async def remove_level_role(interaction: discord.Interaction, level: app_commands.Range[int, 1, 1000]) -> None:
    settings = bot.leveling_settings()
    level_roles = settings.setdefault("level_roles", [])
    before = len(level_roles)
    settings["level_roles"] = [item for item in level_roles if int(item.get("level", 0)) != int(level)]
    bot.save_config()
    if len(settings["level_roles"]) == before:
        await interaction.response.send_message(f"Для уровня **{level}** ничего не найдено.", ephemeral=True)
    else:
        await interaction.response.send_message(f"Настройка роли за уровень **{level}** удалена.", ephemeral=True)


@bot.tree.command(name="relationship_request", description="Отправить предложение дружбы/семьи/отношений")
@app_commands.guild_only()
@app_commands.describe(member="Кому отправить", relation_type="Тип связи", message="Дополнительное сообщение")
async def relationship_request(
    interaction: discord.Interaction,
    member: discord.Member,
    relation_type: str,
    message: Optional[str] = None,
) -> None:
    if interaction.guild is None or not isinstance(interaction.user, discord.Member):
        await interaction.response.send_message("Команда работает только на сервере.", ephemeral=True)
        return
    relation_type = relation_type.lower().strip()
    if relation_type not in RELATIONSHIP_LABELS:
        await interaction.response.send_message("Неизвестный тип связи. Доступно: friend, family, love, marriage.", ephemeral=True)
        return
    if member.bot or member.id == interaction.user.id:
        await interaction.response.send_message("Нельзя отправить предложение самому себе или боту.", ephemeral=True)
        return
    embed = discord.Embed(
        title="💌 Новое предложение!",
        description=(
            f"{member.mention}, тебе пришло предложение: **{RELATIONSHIP_LABELS[relation_type]}**\n"
            f"От: {interaction.user.mention}"
        ),
        color=discord.Color.fuchsia(),
    )
    if message:
        embed.add_field(name="Сообщение", value=message[:1024], inline=False)
    embed.set_footer(text="Нажми кнопку ниже, чтобы принять или отклонить.")
    view = RelationshipRequestView(interaction.user.id, member.id, relation_type, bot)
    await interaction.response.send_message("Предложение отправлено ✅", ephemeral=True)
    await interaction.channel.send(embed=embed, view=view)


@relationship_request.autocomplete("relation_type")
async def relationship_request_autocomplete(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
    return await relation_type_autocomplete(interaction, current)


@bot.tree.command(name="relationships", description="Показать связи участника")
@app_commands.guild_only()
@app_commands.describe(member="Чьи связи показать")
async def relationships(interaction: discord.Interaction, member: Optional[discord.Member] = None) -> None:
    target = member or interaction.user
    if not isinstance(target, discord.Member):
        await interaction.response.send_message("Участник не найден.", ephemeral=True)
        return
    rows = bot.db.relationships_for_member(target.guild.id, target.id)
    if not rows:
        await interaction.response.send_message(f"У {target.mention} пока нет активных связей.", ephemeral=True)
        return
    lines = []
    for relation in rows:
        other_id = relation["user2_id"] if relation["user1_id"] == target.id else relation["user1_id"]
        other = target.guild.get_member(other_id)
        other_name = other.mention if other else f"ID {other_id}"
        created = time.strftime("%d.%m.%Y", time.localtime(relation["created_at"]))
        lines.append(f"**{RELATIONSHIP_LABELS.get(relation['relation_type'], relation['relation_type'])}** — {other_name} (с {created})")
    embed = discord.Embed(title=f"💞 Связи {target.display_name}", description="\n".join(lines), color=discord.Color.pink())
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="relationship_break", description="Разорвать связь")
@app_commands.guild_only()
@app_commands.describe(member="С кем разорвать", relation_type="Тип связи")
async def relationship_break(interaction: discord.Interaction, member: discord.Member, relation_type: str) -> None:
    relation_type = relation_type.lower().strip()
    if relation_type not in RELATIONSHIP_LABELS:
        await interaction.response.send_message("Неизвестный тип связи.", ephemeral=True)
        return
    bot.db.delete_relationship(interaction.guild.id, interaction.user.id, member.id, relation_type)
    await interaction.response.send_message(
        f"Связь **{RELATIONSHIP_LABELS[relation_type]}** между тобой и {member.mention} удалена.", ephemeral=True
    )


@relationship_break.autocomplete("relation_type")
async def relationship_break_autocomplete(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
    return await relation_type_autocomplete(interaction, current)


@bot.tree.command(name="embed_templates", description="Показать готовые embed-шаблоны")
@app_commands.guild_only()
@app_commands.default_permissions(manage_guild=True)
async def embed_templates(interaction: discord.Interaction) -> None:
    templates = bot.config.get("embed_templates", {})
    if not templates:
        await interaction.response.send_message("В config.json нет готовых embed-шаблонов.", ephemeral=True)
        return
    lines = [f"`{key}` — **{data.get('title', key)}**" for key, data in templates.items()]
    embed = discord.Embed(title="📨 Готовые embed-шаблоны", description="\n".join(lines), color=discord.Color.blurple())
    embed.set_footer(text="Отправить шаблон: /embed_template_send")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="embed_template_send", description="Отправить готовый embed-шаблон")
@app_commands.guild_only()
@app_commands.default_permissions(manage_guild=True)
@app_commands.describe(template="Ключ шаблона", channel="Куда отправить", member="Участник для подстановки {member}/{user}")
async def embed_template_send(
    interaction: discord.Interaction,
    template: str,
    channel: discord.TextChannel,
    member: Optional[discord.Member] = None,
) -> None:
    templates = bot.config.get("embed_templates", {})
    data = templates.get(template)
    if not data:
        await interaction.response.send_message("Такого шаблона нет. Посмотри /embed_templates.", ephemeral=True)
        return
    embed = discord.Embed(
        title=render_template_text(str(data.get("title", "Без названия")), interaction.guild, member),
        description=render_template_text(str(data.get("description", "")), interaction.guild, member),
        color=parse_discord_color(str(data.get("color", "#5865F2"))),
    )
    if data.get("footer"):
        embed.set_footer(text=render_template_text(str(data.get("footer")), interaction.guild, member))
    if data.get("image_url"):
        embed.set_image(url=str(data.get("image_url")))
    if data.get("thumbnail_url"):
        embed.set_thumbnail(url=str(data.get("thumbnail_url")))
    elif interaction.guild.icon:
        embed.set_thumbnail(url=interaction.guild.icon.url)
    await channel.send(embed=embed)
    await interaction.response.send_message(f"Шаблон `{template}` отправлен в {channel.mention}.", ephemeral=True)


@embed_template_send.autocomplete("template")
async def embed_template_send_autocomplete(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
    return await embed_template_autocomplete(interaction, current)


@bot.tree.command(name="embed_send", description="Отправить красивый embed через бота")
@app_commands.guild_only()
@app_commands.default_permissions(manage_guild=True)
@app_commands.describe(channel="Куда отправить", title="Заголовок", description="Описание", color="HEX цвет, например #5865F2", footer="Текст внизу", image_url="Ссылка на картинку")
async def embed_send(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    title: str,
    description: str,
    color: Optional[str] = None,
    footer: Optional[str] = None,
    image_url: Optional[str] = None,
) -> None:
    embed = discord.Embed(title=title[:256], description=description[:4000], color=parse_discord_color(color or "#5865F2"))
    if interaction.guild.icon:
        embed.set_author(name=interaction.guild.name, icon_url=interaction.guild.icon.url)
    else:
        embed.set_author(name=interaction.guild.name)
    if footer:
        embed.set_footer(text=footer[:2048])
    if image_url:
        embed.set_image(url=image_url)
    await channel.send(embed=embed)
    await interaction.response.send_message(f"Embed отправлен в {channel.mention}.", ephemeral=True)


@bot.tree.command(name="setup_welcome", description="Настроить авто-приветствие")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@app_commands.describe(
    channel="Канал приветствия",
    enabled="Включить или выключить",
    title="Заголовок",
    message="Текст. Доступны {mention}, {user}, {server}, {count}",
    color="HEX цвет",
    image_url="Ссылка на картинку снизу",
    footer="Текст внизу embed"
)
async def setup_welcome(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    enabled: bool,
    title: str,
    message: str,
    color: Optional[str] = None,
    image_url: Optional[str] = None,
    footer: Optional[str] = None,
) -> None:
    settings = bot.welcome_settings()
    settings["enabled"] = enabled
    settings["channel_id"] = channel.id
    settings["title"] = title
    settings["message"] = message
    settings["color"] = color or "#FFB3C7"
    if image_url is not None:
        settings["image_url"] = image_url
    if footer is not None:
        settings["footer"] = footer
    bot.save_config()
    await interaction.response.send_message(f"Настройка приветствия обновлена. Канал: {channel.mention}. Включено: **{enabled}**.", ephemeral=True)


@bot.tree.command(name="givecoins", description="Выдать монеты участнику")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@app_commands.describe(member="Кому выдать монеты", amount="Сколько монет")
async def givecoins(
    interaction: discord.Interaction,
    member: discord.Member,
    amount: app_commands.Range[int, 1, 1_000_000],
) -> None:
    row = bot.db.add_balance(interaction.guild.id, member.id, int(amount), "admin", f"Выдача монет администратором: {interaction.user}")
    await interaction.response.send_message(f"{member.mention} получил **{amount} 🪙**. Новый баланс: **{row['balance']} 🪙**.", ephemeral=True)


@bot.tree.command(name="leaderboard", description="Топ участников по XP")
@app_commands.guild_only()
async def leaderboard(interaction: discord.Interaction) -> None:
    rows = bot.db.top_users(interaction.guild.id, limit=10)
    if not rows:
        await interaction.response.send_message("Пока нет статистики XP.")
        return
    lines = []
    for index, row in enumerate(rows, start=1):
        member = interaction.guild.get_member(int(row["user_id"]))
        name = member.mention if member else f"ID {row['user_id']}"
        lines.append(
            f"**{index}.** {name} — LVL **{row['level']}**, XP **{row['xp']}**, Баланс **{row['balance']} {get_currency_symbol()}**, ГС **{format_duration_minutes(int(row.get('voice_minutes', 0)))}**"
        )
    embed = discord.Embed(title="🏆 Топ XP", description="\n".join(lines), color=discord.Color.green())
    await interaction.response.send_message(embed=embed)


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
    if isinstance(error, app_commands.MissingPermissions):
        message = "У тебя нет прав для этой команды."
    elif isinstance(error, app_commands.BotMissingPermissions):
        message = "У бота не хватает прав. Проверь роли и permissions."
    else:
        message = f"Произошла ошибка: `{type(error).__name__}`. Подробности в консоли."
        print(f"Ошибка команды {interaction.command}: {error!r}")
    if interaction.response.is_done():
        await interaction.followup.send(message, ephemeral=True)
    else:
        await interaction.response.send_message(message, ephemeral=True)



# ------------------------- PROFILE ASSET OVERRIDES V5.3 -------------------------
ASSET_ROOT = Path(__file__).resolve().parent / "assets"
PROFILE_ICON_FILES = {
    "location": ASSET_ROOT / "profile_icons" / "location.png",
    "mic": ASSET_ROOT / "profile_icons" / "mic.png",
    "top": ASSET_ROOT / "profile_icons" / "top.png",
    "star": ASSET_ROOT / "profile_icons" / "top.png",
    "heart": ASSET_ROOT / "profile_icons" / "room.png",
    "room": ASSET_ROOT / "profile_icons" / "room.png",
    "pair": ASSET_ROOT / "profile_icons" / "pair.png",
    "clan": ASSET_ROOT / "profile_icons" / "achievement.png",
    "achievement": ASSET_ROOT / "profile_icons" / "achievement.png",
    "currency": ASSET_ROOT / "profile_icons" / "currency.png",
}
ACH_ICON_FILES = {
    "messages": ASSET_ROOT / "achievement_icons" / "messages.png",
    "voice": ASSET_ROOT / "achievement_icons" / "voice.png",
    "level": ASSET_ROOT / "achievement_icons" / "level.png",
    "backgrounds": ASSET_ROOT / "achievement_icons" / "backgrounds.png",
    "relations": ASSET_ROOT / "achievement_icons" / "relations.png",
    "cases": ASSET_ROOT / "achievement_icons" / "cases.png",
    "daily": ASSET_ROOT / "achievement_icons" / "daily.png",
    "balance": ASSET_ROOT / "achievement_icons" / "balance.png",
    "achievement": ASSET_ROOT / "achievement_icons" / "achievement.png",
}
THEME_ART_MAP = {
    "default": ["peach_1.png", "peach_2.png"],
    "sunset": ["peach_1.png", "peach_2.png"],
    "aurora": ["peach_2.png", "city_2.png"],
    "anime_city": ["city_1.png", "city_2.png"],
    "night": ["city_1.png", "city_2.png"],
    "sakura": ["sakura_1.png", "sakura_2.png"],
    "ocean": ["ocean_1.png", "ocean_2.png"],
    "forest": ["mountain_1.png", "mountain_2.png"],
    "mountain": ["mountain_1.png", "mountain_2.png"],
    "panda": ["panda_1.png"],
    "fox": ["fox_1.png"],
    "wolf": ["wolf_1.png"],
}

ACHIEVEMENT_DEFS = [
    {"id": "msg_50", "emoji": "💬", "title": "Первые слова", "desc": "Напиши 50 сообщений на сервере.", "metric": "messages", "target": 50, "icon": "messages"},
    {"id": "msg_250", "emoji": "📨", "title": "Общительный персик", "desc": "Напиши 250 сообщений.", "metric": "messages", "target": 250, "icon": "messages"},
    {"id": "voice_60", "emoji": "📣", "title": "Голос есть", "desc": "Проведи 1 час в голосовых каналах.", "metric": "voice", "target": 60, "icon": "voice"},
    {"id": "voice_600", "emoji": "🌙", "title": "Ночной житель", "desc": "Проведи 10 часов в голосовых.", "metric": "voice", "target": 600, "icon": "voice"},
    {"id": "level_5", "emoji": "🧸", "title": "Peach Rising", "desc": "Достигни 5 уровня профиля.", "metric": "level", "target": 5, "icon": "level"},
    {"id": "background_1", "emoji": "🎨", "title": "Своя атмосфера", "desc": "Купи первый фон профиля.", "metric": "backgrounds", "target": 1, "icon": "backgrounds"},
    {"id": "background_4", "emoji": "🎗️", "title": "Коллекционер", "desc": "Собери 4 фона профиля.", "metric": "backgrounds", "target": 4, "icon": "backgrounds"},
    {"id": "relation_1", "emoji": "❤️", "title": "Не один", "desc": "Получи первую связь / пару на сервере.", "metric": "relations", "target": 1, "icon": "relations"},
    {"id": "case_5", "emoji": "🎁", "title": "Любитель кейсов", "desc": "Открой 5 кейсов.", "metric": "cases", "target": 5, "icon": "cases"},
    {"id": "daily_7", "emoji": "⚡️", "title": "Верность серверу", "desc": "Забери daily 7 раз.", "metric": "daily", "target": 7, "icon": "daily"},
    {"id": "balance_1000", "emoji": "🍑", "title": "На стиле", "desc": "Накопи 1000 валюты сервера.", "metric": "balance", "target": 1000, "icon": "balance"},
]


def _load_asset(path: Path, size: Optional[tuple[int, int]] = None) -> Optional[Image.Image]:
    try:
        img = Image.open(path).convert("RGBA")
        if size:
            img = img.resize(size, Image.LANCZOS)
        return img
    except Exception:
        return None


def _paste_center(image: Image.Image, asset: Image.Image, box: tuple[int, int, int, int]) -> None:
    x1, y1, x2, y2 = box
    bw, bh = x2 - x1, y2 - y1
    scale = min(bw / asset.width, bh / asset.height)
    nw = max(1, int(asset.width * scale))
    nh = max(1, int(asset.height * scale))
    asset = asset.resize((nw, nh), Image.LANCZOS)
    px = x1 + (bw - nw) // 2
    py = y1 + (bh - nh) // 2
    image.alpha_composite(asset, (px, py))


def _simple_fallback_icon(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], color=(180, 220, 255, 230)) -> None:
    x1, y1, x2, y2 = box
    draw.rounded_rectangle(box, radius=max(6, (x2 - x1) // 4), fill=(255, 255, 255, 18), outline=(255, 255, 255, 45), width=1)
    draw.ellipse((x1 + 4, y1 + 4, x2 - 4, y2 - 4), outline=color, width=2)


def draw_currency_icon(image: Image.Image, draw: ImageDraw.ImageDraw, center: tuple[int, int], radius: int = 18) -> None:
    x, y = center
    box = (x - radius - 3, y - radius - 3, x + radius + 3, y + radius + 3)
    asset = _load_asset(PROFILE_ICON_FILES["currency"])
    if asset is not None:
        _paste_center(image, asset, box)
    else:
        _simple_fallback_icon(draw, box)


def draw_profile_icon(image: Image.Image, draw: ImageDraw.ImageDraw, kind: str, box: tuple[int, int, int, int]) -> None:
    asset = _load_asset(PROFILE_ICON_FILES.get(kind, PROFILE_ICON_FILES["achievement"]))
    if asset is not None:
        _paste_center(image, asset, box)
    else:
        _simple_fallback_icon(draw, box)


def draw_achievement_symbol(image: Image.Image, draw: ImageDraw.ImageDraw, xy: tuple[int, int], done: bool = False, icon_kind: str = "achievement") -> None:
    x, y = xy
    box = (x, y, x + 46, y + 46)
    asset = _load_asset(ACH_ICON_FILES.get(icon_kind, ACH_ICON_FILES["achievement"]))
    if asset is not None:
        # dim locked icons a bit
        if not done:
            dim = Image.new("RGBA", asset.size, (40, 55, 75, 90))
            asset = asset.copy()
            asset.alpha_composite(dim)
        _paste_center(image, asset, box)
    else:
        _simple_fallback_icon(draw, box, color=(255, 215, 90, 220) if done else (120, 170, 255, 210))


def draw_profile_art(image: Image.Image, draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], theme: str, colors: list[str]) -> None:
    theme_key = str(theme or "default").lower()
    art_files = THEME_ART_MAP.get(theme_key) or THEME_ART_MAP.get("default", [])
    if not art_files:
        return
    chosen = random.choice(art_files)
    asset = _load_asset(ASSET_ROOT / "profile_arts" / chosen)
    x1, y1, x2, y2 = box
    if asset is None:
        draw.rounded_rectangle(box, radius=26, fill=(255, 255, 255, 12), outline=(255, 255, 255, 28), width=1)
        return
    target_w, target_h = x2 - x1, y2 - y1
    asset = asset.resize((target_w, target_h), Image.LANCZOS)
    # rounded mask to fit existing panel
    mask = Image.new("L", (target_w, target_h), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, target_w, target_h), radius=26, fill=255)
    image.paste(asset, (x1, y1), mask)
    shadow = Image.new("RGBA", (target_w, target_h), (0, 0, 0, 35))
    image.alpha_composite(shadow, (x1, y1))
    draw.rounded_rectangle(box, radius=26, outline=(255, 255, 255, 32), width=1)


def user_achievement_metrics(member: discord.Member) -> dict[str, int]:
    row = bot.db.get_user(member.guild.id, member.id)
    backgrounds_owned = len(bot.db.get_purchases(member.guild.id, member.id, "background"))
    relations = bot.db.relationships_for_member(member.guild.id, member.id)
    return {
        "messages": int(row.get("message_count", 0)),
        "voice": int(row.get("voice_minutes", 0)),
        "level": int(row.get("level", 0)),
        "backgrounds": int(backgrounds_owned),
        "relations": int(len(relations)),
        "cases": int(row.get("case_opened", 0)),
        "daily": int(row.get("daily_count", 0)),
        "balance": int(row.get("balance", 0)),
    }


def achievement_progress(member: discord.Member) -> list[dict[str, Any]]:
    metrics = user_achievement_metrics(member)
    result = []
    for item in ACHIEVEMENT_DEFS:
        value = int(metrics.get(item["metric"], 0))
        target = int(item["target"])
        result.append({**item, "value": value, "done": value >= target, "completed": value >= target, "percent": min(value / max(target, 1), 1.0)})
    return result


def calculate_achievements(member: discord.Member) -> list[dict[str, Any]]:
    return achievement_progress(member)


def create_achievement_screen(member: discord.Member, page: int = 0) -> io.BytesIO:
    width, height = 1200, 720
    image = make_ui_canvas(width, height, "night", ["#0f172a", "#1e293b"])
    draw = ImageDraw.Draw(image)
    title_font = load_font(36, True)
    text_font = load_font(22)
    small_font = load_font(18)
    tiny_font = load_font(14)

    draw_text_with_shadow(draw, (42, 34), "Достижения Peach Lounge", title_font)
    metrics = achievement_progress(member)
    done_count = sum(1 for x in metrics if x["done"])
    draw.text(
        (46, 82),
        f"{member.display_name} • выполнено {done_count}/{len(metrics)}",
        font=text_font,
        fill=(225, 232, 255, 220),
    )

    per_page = 5
    max_page = max(0, math.ceil(len(metrics) / per_page) - 1)
    page = max(0, min(page, max_page))
    items = metrics[page * per_page : (page + 1) * per_page]

    # Без квадратных иконок слева: emoji теперь идет прямо в заголовке достижения.
    y = 128
    for item in items:
        done = bool(item["done"])
        draw_glass(
            draw,
            (40, y, width - 40, y + 104),
            radius=22,
            fill=(255, 255, 255, 28 if done else 20),
        )

        # Small status dot only, not a big icon tile.
        status_color = (255, 190, 90, 230) if done else (125, 155, 210, 170)
        draw.ellipse((60, y + 22, 72, y + 34), fill=status_color)

        title_text = f"{item.get('emoji', '🏅')} {item['title']}"
        draw_rich_text(image, draw, (88, y + 16), title_text, text_font, fill=(255, 255, 255, 242))
        draw.text((88, y + 46), item["desc"], font=small_font, fill=(210, 220, 255, 205))

        progress_text = "Получено" if done else f"{item['value']}/{item['target']}"
        draw.text((width - 220, y + 20), progress_text, font=small_font, fill=(255, 255, 255, 235))

        bar_x, bar_y, bar_w, bar_h = 88, y + 78, width - 305, 12
        draw.rounded_rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), radius=6, fill=(10, 12, 20, 175))
        fill_w = int(bar_w * float(item["percent"]))
        if fill_w:
            fill_color = (255, 165, 120, 230) if done else (130, 170, 255, 230)
            draw.rounded_rectangle((bar_x, bar_y, bar_x + fill_w, bar_y + bar_h), radius=6, fill=fill_color)

        if done:
            draw.text((width - 115, y + 48), "✓", font=text_font, fill=(255, 210, 120, 230))

        y += 112

    draw.text(
        (width // 2 - 80, height - 50),
        f"Страница {page + 1}/{max_page + 1}",
        font=small_font,
        fill=(230, 236, 255, 210),
    )

    # Tiny hint so users understand it is a paged achievement menu.
    draw.text(
        (44, height - 50),
        "Полученные достижения отображаются в профиле",
        font=tiny_font,
        fill=(210, 220, 245, 135),
    )

    out = io.BytesIO()
    image.save(out, format="PNG")
    out.seek(0)
    return out


def main() -> None:
    load_dotenv()
    # Bothost может передавать токен как BOT_TOKEN, а локально мы используем DISCORD_TOKEN.
    token = os.getenv("DISCORD_TOKEN") or os.getenv("BOT_TOKEN")
    if not token or token == "PASTE_YOUR_BOT_TOKEN_HERE":
        raise RuntimeError("Не найден токен. В .env/переменных окружения укажи DISCORD_TOKEN или BOT_TOKEN.")
    bot.run(token)


if __name__ == "__main__":
    main()
