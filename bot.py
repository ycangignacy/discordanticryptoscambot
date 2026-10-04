"""Discord anti-scam moderation bot. Run with DISCORD_TOKEN in .env."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

import discord
import yaml
from discord.ext import commands
from dotenv import load_dotenv
from PIL import UnidentifiedImageError

from detection import check_text, read_image_text
from scam_learning import ScamLearning, SUPPORTED_EXTENSIONS, open_image

LOG = logging.getLogger("scam_bot")
ROOT = Path(__file__).resolve().parent


def load_config(path: Path) -> dict:
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("config.yaml must be a mapping")
    defaults = {"log_channel_id": 0, "scam_keywords": [], "scam_domains": [],
                "bad_words": [], "learning": {}, "enable_ocr": True,
                "max_image_size_mb": 8, "action": "ban", "ban_reason": "Scam",
                "delete_message_days": 1}
    defaults.update(config)
    learning = {"enable_ai_layer": True, "hash_threshold": 8,
                "similarity_threshold": 0.90,
                "training_folder": "training_data/scam_examples"}
    learning.update(defaults["learning"] or {})
    defaults["learning"] = learning
    for key in ("scam_keywords", "scam_domains", "bad_words"):
        if not isinstance(defaults[key], list):
            raise ValueError(f"{key} must be a list")
    if defaults["action"] not in ("ban", "kick"):
        raise ValueError("action must be 'ban' or 'kick'")
    if not 0 <= int(defaults["delete_message_days"]) <= 7:
        raise ValueError("delete_message_days must be 0-7")
    if not 0 <= int(learning["hash_threshold"]) <= 64:
        raise ValueError("hash_threshold must be 0-64")
    if not 0 <= float(learning["similarity_threshold"]) <= 1:
        raise ValueError("similarity_threshold must be 0-1")
    if float(defaults["max_image_size_mb"]) <= 0:
        raise ValueError("max_image_size_mb must be positive")
    return defaults


def is_image(attachment: discord.Attachment) -> bool:
    return (attachment.content_type or "").lower().startswith("image/") or \
        Path(attachment.filename).suffix.lower() in SUPPORTED_EXTENSIONS


class ScamBot(commands.Bot):
    def __init__(self, config: dict):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        super().__init__(command_prefix="!", intents=intents, help_command=None,
                         allowed_mentions=discord.AllowedMentions.none())
        self.config = config
        learning = config["learning"]
        self.learning = ScamLearning(
            ROOT / "data", bool(learning["enable_ai_layer"]),
            int(learning["hash_threshold"]), float(learning["similarity_threshold"]))
        self._folder_scanned = False

    async def on_ready(self) -> None:
        await self.change_presence(activity=discord.Game(name="Watching for scams | made by ycangignacy"))
        if not self._folder_scanned:
            self._folder_scanned = True
            folder = ROOT / self.config["learning"]["training_folder"]
            added, failed = await asyncio.to_thread(self.learning.learn_folder, folder)
            LOG.info("Logged in as %s; training folder: %s added, %s failed", self.user, added, failed)

    def is_moderator(self, message: discord.Message) -> bool:
        member = message.author
        return isinstance(member, discord.Member) and (
            member.guild_permissions.administrator or
            message.channel.permissions_for(member).manage_messages)

    async def inspect(self, message: discord.Message) -> str | None:
        cfg = self.config
        result = check_text(message.content, cfg["scam_keywords"],
                            cfg["scam_domains"], cfg["bad_words"])
        if result:
            return result
        max_bytes = int(float(cfg["max_image_size_mb"]) * 1024 * 1024)
        for attachment in message.attachments:
            if not is_image(attachment) or attachment.size > max_bytes:
                continue
            try:
                raw = await attachment.read()
                if len(raw) > max_bytes:
                    continue
                matched = await asyncio.to_thread(self.learning.match, raw)
                if matched:
                    return matched
                if cfg["enable_ocr"]:
                    image = await asyncio.to_thread(open_image, raw)
                    text = await asyncio.to_thread(read_image_text, image)
                    if match := check_text(text, cfg["scam_keywords"],
                                           cfg["scam_domains"], cfg["bad_words"]):
                        return "OCR: " + match
            except (discord.HTTPException, OSError, ValueError, UnidentifiedImageError):
                LOG.exception("Could not inspect attachment %s", attachment.id)
            except Exception:
                # A missing OCR installation or failed model download should not stop text checks.
                LOG.exception("Image analysis unavailable for attachment %s", attachment.id)
        return None

    async def log_action(self, message: discord.Message, reason: str,
                         delete_result: str, action_result: str) -> None:
        channel_id = int(self.config["log_channel_id"] or 0)
        if not channel_id:
            LOG.warning("log_channel_id is 0; no Discord moderation log channel configured")
            return
        channel = self.get_channel(channel_id)
        if channel is None:
            try:
                channel = await self.fetch_channel(channel_id)
            except discord.HTTPException:
                LOG.exception("Cannot find log channel %s", channel_id)
                return
        if not hasattr(channel, "send"):
            LOG.error("Log channel %s cannot receive messages", channel_id)
            return
        content = (f"Moderation: member {message.author} (`{message.author.id}`), "
                   f"channel <#{message.channel.id}>, reason: {reason[:300]}; "
                   f"message deletion: {delete_result}; {self.config['action']}: {action_result}.")
        try:
            await channel.send(content, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            LOG.exception("Cannot post moderation log")

    async def moderate(self, message: discord.Message, reason: str) -> None:
        deletion = "succeeded"
        try:
            await message.delete()
        except discord.HTTPException as exc:
            deletion = f"failed ({type(exc).__name__})"
            LOG.warning("Could not delete message %s: %s", message.id, exc)
        outcome = "succeeded"
        try:
            if self.config["action"] == "ban":
                await message.guild.ban(
                    message.author, reason=self.config["ban_reason"],
                    delete_message_seconds=int(self.config["delete_message_days"]) * 86400)
            else:
                await message.guild.kick(message.author, reason=self.config["ban_reason"])
        except discord.HTTPException as exc:
            outcome = f"failed ({type(exc).__name__})"
            LOG.warning("Could not %s member %s: %s", self.config["action"], message.author.id, exc)
        await self.log_action(message, reason, deletion, outcome)

    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.author.bot:
            return
        if self.is_moderator(message):
            await self.process_commands(message)
            return
        reason = await self.inspect(message)
        if reason:
            await self.moderate(message, reason)
            return
        await self.process_commands(message)

    async def on_command_error(self, ctx: commands.Context, error: commands.CommandError) -> None:
        if isinstance(error, commands.CommandNotFound):
            return
        if isinstance(error, commands.MissingPermissions):
            await ctx.send("This command requires Manage Messages permission.")
            return
        if isinstance(error, commands.MissingRequiredArgument):
            await ctx.send("This command needs an argument.")
            return
        LOG.error("Command failed", exc_info=(type(error), error, error.__traceback__))
        await ctx.send("The command failed. Check the bot logs.")


def register_commands(bot: ScamBot) -> None:
    @bot.command(name="learnscam")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def learnscam(ctx: commands.Context) -> None:
        attachments = ctx.message.attachments
        if not attachments and ctx.message.reference:
            try:
                original = ctx.message.reference.resolved
                if not isinstance(original, discord.Message):
                    original = await ctx.channel.fetch_message(ctx.message.reference.message_id)
                attachments = original.attachments
            except (discord.HTTPException, AttributeError):
                await ctx.send("I could not read the replied-to message.")
                return
        attachment = next((item for item in attachments if is_image(item)), None)
        if attachment is None:
            await ctx.send("Attach an image or reply to a message containing one.")
            return
        if attachment.size > int(float(bot.config["max_image_size_mb"]) * 1024 * 1024):
            await ctx.send("The image exceeds the size limit in config.yaml.")
            return
        try:
            raw = await attachment.read()
            if len(raw) > int(float(bot.config["max_image_size_mb"]) * 1024 * 1024):
                await ctx.send("The image exceeds the size limit in config.yaml.")
                return
            identifier, created = await asyncio.to_thread(
                bot.learning.learn, raw, f"Discord: {ctx.guild.name} / {ctx.channel} / {ctx.author}",
                f"discord:{attachment.id}")
            await ctx.send(("Saved example" if created else "Example already exists") + f" (`{identifier}`).")
        except Exception:
            LOG.exception("Could not learn attachment")
            await ctx.send("Could not save the image. Check the file and bot logs.")

    @bot.command(name="listscams")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def listscams(ctx: commands.Context) -> None:
        rows = bot.learning.list_recent(20)
        if not rows:
            await ctx.send("No learned examples yet.")
            return
        lines = [f"`{row['id']}` — {discord.utils.escape_markdown(row['source'])[:90]}" for row in rows]
        await ctx.send("Recent examples:\n" + "\n".join(lines),
                       allowed_mentions=discord.AllowedMentions.none())

    @bot.command(name="unlearnscam")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def unlearnscam(ctx: commands.Context, identifier: str) -> None:
        if await asyncio.to_thread(bot.learning.unlearn, identifier):
            await ctx.send(f"Removed example `{identifier}`.")
        else:
            await ctx.send("No example found with that ID.")

    @bot.command(name="testword")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def testword(ctx: commands.Context, *, text: str) -> None:
        cfg = bot.config
        reason = check_text(text, cfg["scam_keywords"], cfg["scam_domains"], cfg["bad_words"])
        await ctx.send(f"Match: {reason}" if reason else "No match.")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    load_dotenv(ROOT / ".env")
    token = os.getenv("DISCORD_TOKEN")
    if not token or token == "put_your_bot_token_here":
        raise SystemExit("Set DISCORD_TOKEN in .env before starting the bot")
    bot = ScamBot(load_config(ROOT / "config.yaml"))
    register_commands(bot)
    bot.run(token, log_handler=None)


if __name__ == "__main__":
    main()
