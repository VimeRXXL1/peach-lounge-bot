import asyncio
import io
import json
import math
import os
import random
import sqlite3
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional

import discord
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv
from PIL import Image, ImageDraw, ImageFilter, ImageFont

CONFIG_PATH = Path("config.json")


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

        if not self._column_exists("users", "voice_minutes"):
            with self.conn:
                self.conn.execute("ALTER TABLE users ADD COLUMN voice_minutes INTEGER NOT NULL DEFAULT 0")

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

    def add_voice_reward(
        self, guild_id: int, user_id: int, xp: int, coins: int, minutes: int, new_level: int
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
        return self.get_user(guild_id, user_id)

    def add_balance(self, guild_id: int, user_id: int, amount: int) -> dict[str, Any]:
        self.ensure_user(guild_id, user_id)
        with self.conn:
            self.conn.execute(
                "UPDATE users SET balance = MAX(balance + ?, 0) WHERE guild_id = ? AND user_id = ?",
                (amount, guild_id, user_id),
            )
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

    def save_config(self) -> None:
        save_config(self.config)

    def xp_settings(self) -> dict[str, Any]:
        return self.config.setdefault("voice_xp", {})

    def leveling_settings(self) -> dict[str, Any]:
        return self.config.setdefault("leveling", {})

    def welcome_settings(self) -> dict[str, Any]:
        return self.config.setdefault("welcome", {})

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
        after = self.db.add_voice_reward(member.guild.id, member.id, xp, coins, minutes, new_level)
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

    async def on_voice_state_update(self, member: discord.Member, before: discord.VoiceState, after: discord.VoiceState) -> None:
        if member.bot:
            return
        before_earning = self.is_earning_voice_channel(before.channel)
        after_earning = self.is_earning_voice_channel(after.channel)
        key = (member.guild.id, member.id)
        now = time.time()

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


def load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


async def create_profile_card(member: discord.Member) -> io.BytesIO:
    row = bot.db.get_user(member.guild.id, member.id)
    backgrounds = bot.config.get("profile_backgrounds", {})
    background_key = row.get("background", "default")
    bg_data = backgrounds.get(background_key, backgrounds.get("default", {}))
    theme = str(bg_data.get("theme", background_key))
    colors = bg_data.get("colors", ["#23272A", "#5865F2"])

    width, height = 1200, 620
    image = draw_theme_background((width, height), theme, colors)
    draw = ImageDraw.Draw(image)

    # Main glass panels
    draw.rounded_rectangle((28, 28, width - 28, height - 28), radius=34, fill=(10, 12, 20, 124), outline=(255, 255, 255, 42), width=2)
    draw.rounded_rectangle((52, 56, 330, height - 56), radius=30, fill=(255, 255, 255, 28), outline=(255, 255, 255, 28), width=1)
    draw.rounded_rectangle((356, 56, width - 52, 345), radius=30, fill=(255, 255, 255, 24), outline=(255, 255, 255, 24), width=1)
    draw.rounded_rectangle((356, 365, width - 52, height - 56), radius=30, fill=(255, 255, 255, 22), outline=(255, 255, 255, 20), width=1)

    avatar_bytes = await member.display_avatar.replace(size=256, static_format="png").read()
    avatar = Image.open(io.BytesIO(avatar_bytes)).convert("RGBA").resize((184, 184))
    mask = Image.new("L", (184, 184), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, 184, 184), fill=255)
    image.paste(avatar, (99, 78), mask)
    draw.ellipse((92, 71, 290, 269), outline=(255, 255, 255, 220), width=5)

    title_font = load_font(46, True)
    medium_bold = load_font(29, True)
    text_font = load_font(23)
    small_font = load_font(18)
    tiny_font = load_font(16)

    # Core stats
    level = int(row["level"])
    xp = int(row["xp"])
    balance = int(row["balance"])
    voice_minutes = int(row.get("voice_minutes", 0))
    rank = bot.db.get_rank(member.guild.id, member.id)
    warnings_count = len(bot.db.get_warnings(member.guild.id, member.id))
    current_level_xp = bot.xp_for_level(level)
    next_level_xp = bot.xp_for_level(level + 1)
    progress = 0 if next_level_xp == current_level_xp else (xp - current_level_xp) / (next_level_xp - current_level_xp)
    progress = max(0, min(1, progress))

    display_name = truncate_text(member.display_name, 22)
    draw_text_with_shadow(draw, (380, 78), display_name, title_font)
    draw.text((382, 130), f"@{truncate_text(member.name, 28)}", font=small_font, fill=(224, 230, 255, 215))

    # Left panel data
    joined = member.joined_at.strftime("%d.%m.%Y") if member.joined_at else "—"
    created = member.created_at.strftime("%d.%m.%Y") if member.created_at else "—"
    left_lines = [
        ("LVL", str(level)),
        ("TOP", f"#{rank or '-'}"),
        ("ГС", format_duration_minutes(voice_minutes)),
        ("Вход", joined),
        ("Акк", created),
    ]
    y = 292
    for label, value in left_lines:
        draw.rounded_rectangle((78, y, 304, y + 42), radius=16, fill=(255, 255, 255, 28))
        draw.text((96, y + 10), label, font=tiny_font, fill=(210, 220, 255, 195))
        draw.text((160, y + 8), value, font=small_font, fill=(255, 255, 255, 232))
        y += 50

    # Stat blocks
    stat_blocks = [
        ("Уровень", str(level)),
        ("XP", f"{xp:,}".replace(",", " ")),
        ("Баланс", f"{balance:,} 🪙".replace(",", " ")),
        ("Варны", str(warnings_count)),
        ("До LVL", f"{max(next_level_xp - xp, 0):,} XP".replace(",", " ")),
    ]
    sx, sy = 380, 172
    for label, value in stat_blocks:
        draw.rounded_rectangle((sx, sy, sx + 144, sy + 74), radius=18, fill=(255, 255, 255, 30))
        draw.text((sx + 14, sy + 12), label, font=tiny_font, fill=(210, 220, 255, 200))
        draw.text((sx + 14, sy + 37), truncate_text(value, 14), font=small_font, fill=(255, 255, 255, 242))
        sx += 156

    # Progress bar
    bar_x, bar_y, bar_w, bar_h = 380, 278, 724, 34
    draw.text((bar_x, bar_y - 30), f"Прогресс: {xp:,}/{next_level_xp:,} XP".replace(",", " "), font=small_font, fill=(235, 240, 255, 220))
    draw.rounded_rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), radius=17, fill=(20, 22, 34, 185))
    fill_w = int(bar_w * progress)
    if fill_w > 0:
        fill_color = parse_hex_color(colors[-1] if colors else "#FFFFFF", default=(255, 255, 255))
        draw.rounded_rectangle((bar_x, bar_y, bar_x + fill_w, bar_y + bar_h), radius=17, fill=(*fill_color, 255))
    pct = int(progress * 100)
    draw.text((bar_x + bar_w - 62, bar_y + 7), f"{pct}%", font=tiny_font, fill=(255, 255, 255, 235))

    # Roles with config emoji labels
    role_display = build_role_display_map(bot.config)
    member_roles = [role for role in reversed(member.roles) if role.name != "@everyone"]
    known_roles = [role for role in member_roles if role.id in role_display]
    other_roles = [role for role in member_roles if role.id not in role_display and not role.managed]
    ordered_roles = known_roles + other_roles

    draw.text((382, 386), "Роли участника", font=medium_bold, fill=(255, 255, 255, 242))
    chip_x, chip_y = 382, 430
    shown = 0
    max_chips = 12
    for role in ordered_roles[:max_chips]:
        label = truncate_text(role_display.get(role.id, role.name), 22)
        bbox = draw.textbbox((0, 0), label, font=small_font)
        chip_w = min(max(110, bbox[2] - bbox[0] + 32), 245)
        if chip_x + chip_w > width - 84:
            chip_x = 382
            chip_y += 44
        if chip_y > height - 118:
            break
        color = role.color.to_rgb() if role.color.value else parse_hex_color(colors[-1] if colors else "#5865F2")
        draw.rounded_rectangle((chip_x, chip_y, chip_x + chip_w, chip_y + 34), radius=17, fill=(*color, 82), outline=(255, 255, 255, 36), width=1)
        draw.text((chip_x + 16, chip_y + 7), label, font=small_font, fill=(255, 255, 255, 238))
        chip_x += chip_w + 10
        shown += 1
    hidden_count = max(0, len(ordered_roles) - shown)
    if hidden_count:
        if chip_x + 90 > width - 84:
            chip_x = 382
            chip_y += 44
        draw.rounded_rectangle((chip_x, chip_y, chip_x + 90, chip_y + 34), radius=17, fill=(255, 255, 255, 32))
        draw.text((chip_x + 16, chip_y + 7), f"+{hidden_count}", font=small_font, fill=(255, 255, 255, 230))

    # Relationships and current background
    relations = bot.db.relationships_for_member(member.guild.id, member.id)[:3]
    relation_parts = []
    for relation in relations:
        other_id = relation["user2_id"] if relation["user1_id"] == member.id else relation["user1_id"]
        other = member.guild.get_member(other_id)
        other_name = truncate_text(other.display_name if other else str(other_id), 16)
        relation_parts.append(f"{RELATIONSHIP_LABELS.get(relation['relation_type'], relation['relation_type'])}: {other_name}")
    relation_text = "  •  ".join(relation_parts) if relation_parts else "Связей пока нет"
    draw.text((382, height - 88), f"Связи: {truncate_text(relation_text, 74)}", font=small_font, fill=(235, 240, 255, 220))
    draw.text((382, height - 62), f"Фон: {bg_data.get('name', background_key)}", font=tiny_font, fill=(220, 226, 255, 190))

    output = io.BytesIO()
    image.save(output, format="PNG")
    output.seek(0)
    return output


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
        name="Модерация",
        value="/clear, /kick, /ban, /timeout, /untimeout, /slowmode, /warn, /warnings, /clearwarnings, /lock, /unlock, /addrole, /removerole, /nickname",
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
    embed.set_footer(text="Если хочешь — потом добавим ещё тикеты, логи, антиспам и т.д.")
    await interaction.response.send_message(embed=embed, ephemeral=True)


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


@bot.tree.command(name="profile", description="Показать профиль участника картинкой")
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
    # По твоей просьбе: без текста и embed — только сама карточка.
    await interaction.followup.send(file=file)


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
    bot.db.add_balance(guild_id, user_id, -price)
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
    row = bot.db.add_balance(interaction.guild.id, member.id, int(amount))
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
            f"**{index}.** {name} — LVL **{row['level']}**, XP **{row['xp']}**, Баланс **{row['balance']} 🪙**, ГС **{format_duration_minutes(int(row.get('voice_minutes', 0)))}**"
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


def main() -> None:
    load_dotenv()
    # Bothost может передавать токен как BOT_TOKEN, а локально мы используем DISCORD_TOKEN.
    token = os.getenv("DISCORD_TOKEN") or os.getenv("BOT_TOKEN")
    if not token or token == "PASTE_YOUR_BOT_TOKEN_HERE":
        raise RuntimeError("Не найден токен. В .env/переменных окружения укажи DISCORD_TOKEN или BOT_TOKEN.")
    bot.run(token)


if __name__ == "__main__":
    main()
