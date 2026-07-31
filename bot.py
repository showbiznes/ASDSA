# =============================================================================
# bot.py — Discord Anti-Spam бот (ЛЁГКАЯ ВЕРСИЯ для bothost.ru)
# =============================================================================
# Без torch, без CLIP — работает на bothost.ru Basic (1 GB RAM)
# Методы детекции: OCR + анализ цвета + перцептивное хеширование
# =============================================================================

import asyncio
import logging
import logging.handlers
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiohttp
import discord
from discord.ext import commands

import config
import database as db
from detector import ImageDetector

# ---------------------------------------------------------------------------
# Логирование
# ---------------------------------------------------------------------------
Path(config.LOGS_DIR).mkdir(parents=True, exist_ok=True)
Path(config.REVIEW_DIR).mkdir(parents=True, exist_ok=True)

log_formatter = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

file_handler = logging.handlers.TimedRotatingFileHandler(
    config.LOG_FILE, when="D", interval=7, backupCount=4, encoding="utf-8",
)
file_handler.setFormatter(log_formatter)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

logging.basicConfig(level=logging.INFO, handlers=[file_handler, console_handler])
logger = logging.getLogger("antispam.bot")


# ---------------------------------------------------------------------------
# Бот
# ---------------------------------------------------------------------------
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

# Детектор (без нейросетей — лёгкий)
detector = ImageDetector()


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

async def send_log(guild: discord.Guild, message: str) -> None:
    """Отправляет лог в канал сервера (каждый сервер настраивает свой)."""
    channel_id = db.get_log_channel(guild.id)
    if not channel_id:
        channel_id = config.LOG_CHANNEL_ID
    if not channel_id:
        return
    channel = guild.get_channel(channel_id)
    if channel:
        try:
            await channel.send(message)
        except discord.Forbidden:
            logger.warning("Нет доступа к лог-каналу %s на %s", channel_id, guild.name)


async def download_attachment(attachment: discord.Attachment) -> bytes | None:
    """Скачивает вложение из Discord."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(attachment.url) as resp:
                if resp.status == 200:
                    return await resp.read()
    except Exception as e:
        logger.error("Ошибка скачивания: %s", e)
    return None


def save_for_review(image_data: bytes, filename: str) -> Path:
    """Сохраняет подозрительное изображение для ручной проверки."""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_name = Path(filename).name
    out_path = Path(config.REVIEW_DIR) / f"{timestamp}_{safe_name}"
    out_path.write_bytes(image_data)
    return out_path


def is_image(filename: str) -> bool:
    return Path(filename).suffix.lower() in config.SUPPORTED_FORMATS


# ---------------------------------------------------------------------------
# События
# ---------------------------------------------------------------------------

@bot.event
async def on_ready() -> None:
    db.init_db()
    logger.info("Бот запущен: %s (ID: %s) | Серверов: %d",
                bot.user, bot.user.id, len(bot.guilds))
    logger.info("Сервера: %s", [g.name for g in bot.guilds])
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name=f"за спамом в {len(bot.guilds)} серверах 🔍",
        )
    )


@bot.event
async def on_guild_join(guild: discord.Guild) -> None:
    logger.info("Бот добавлен на сервер: %s (ID: %s)", guild.name, guild.id)
    for channel in guild.text_channels:
        if channel.permissions_for(guild.me).send_messages:
            embed = discord.Embed(
                title="🔐 Anti-Spam Бот подключён!",
                description=(
                    "Я автоматически удаляю рекламу казино и гемблинга.\n\n"
                    "⭐ **Настройка:**\n"
                    "▸ `!setlogchannel #канал` — канал для уведомлений\n"
                    "▸ `!help` — список всех команд\n\n"
                    "⚠️ Нужны права: **Manage Messages** + **Moderate Members**"
                ),
                color=discord.Color.blurple(),
            )
            await channel.send(embed=embed)
            break
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name=f"за спамом в {len(bot.guilds)} серверах 🔍",
        )
    )


# ---------------------------------------------------------------------------
# Обработка сообщений
# ---------------------------------------------------------------------------

@bot.event
async def on_message(message: discord.Message) -> None:
    # Игнорируем ботов и DM
    if message.author.bot or not message.guild:
        return

    # Проверяем изображения
    if message.attachments:
        for attachment in message.attachments:
            if not is_image(attachment.filename):
                continue

            # Скачиваем
            image_data = await download_attachment(attachment)
            if not image_data:
                continue

            db.increment_stat("images_checked")

            # Анализируем
            is_spam, confidence, method = detector.predict(image_data)

            logger.info(
                "Проверка: %s | файл=%s | спам=%s | conf=%.2f | метод=%s",
                message.author, attachment.filename, is_spam, confidence, method,
            )

            if is_spam and confidence >= config.CONFIDENCE_THRESHOLD:
                await _handle_violation(
                    message, attachment, image_data, confidence, method
                )
                return  # Не проверяем остальные вложения

            elif confidence >= config.CONFIDENCE_THRESHOLD * 0.7:
                # Серая зона — на ручную проверку
                review_path = save_for_review(image_data, attachment.filename)
                await send_log(
                    message.guild,
                    config.MSG_REVIEW.format(
                        mention=message.author.mention,
                        confidence=confidence,
                    ),
                )

    # Обрабатываем команды
    await bot.process_commands(message)


async def _handle_violation(
    message: discord.Message,
    attachment: discord.Attachment,
    image_data: bytes,
    confidence: float,
    method: str,
) -> None:
    """Обрабатывает нарушение: удаление, предупреждение, мут."""
    guild = message.guild
    member = message.author

    # Удаляем сообщение
    try:
        await message.delete()
    except discord.Forbidden:
        logger.warning("Нет прав удалять сообщения в %s", guild.name)
        return
    except discord.NotFound:
        pass

    # Добавляем предупреждение
    warnings_count = db.add_warning(member.id, guild.id)
    db.increment_stat("violations_found")

    # Логируем нарушение
    db.log_violation(
        user_id=member.id,
        guild_id=guild.id,
        username=str(member),
        filename=attachment.filename,
        confidence=confidence,
        method=method,
        action="mute" if warnings_count >= config.MAX_WARNINGS else "warn",
    )

    # Сохраняем для ревью
    save_for_review(image_data, attachment.filename)

    if warnings_count >= config.MAX_WARNINGS:
        # Мут
        duration_minutes = config.MUTE_DURATION // 60
        try:
            await member.timeout(
                timedelta(seconds=config.MUTE_DURATION),
                reason=f"Спам-рассылка казино ({warnings_count} предупреждений)",
            )
            db.increment_stat("users_muted")
        except discord.Forbidden:
            logger.warning("Нет прав для мута %s", member)

        db.reset_warnings(member.id, guild.id)

        mute_msg = config.MSG_MUTED.format(
            mention=member.mention,
            duration=duration_minutes,
            warnings=warnings_count,
        )
        try:
            await message.channel.send(mute_msg)
        except Exception:
            pass
        await send_log(guild, f"🔇 {member} замучен на {duration_minutes} мин.")
    else:
        # Предупреждение
        warn_msg = config.MSG_WARNING.format(
            mention=member.mention,
            warnings=warnings_count,
            max_warnings=config.MAX_WARNINGS,
            confidence=confidence,
            method=method,
        )
        try:
            await message.channel.send(warn_msg, delete_after=15)
        except Exception:
            pass
        await send_log(
            guild,
            f"⚠️ {member} | предупреждение {warnings_count}/{config.MAX_WARNINGS} "
            f"| {method} ({confidence:.0%})",
        )


# ---------------------------------------------------------------------------
# Команды администратора
# ---------------------------------------------------------------------------

def is_admin():
    async def predicate(ctx: commands.Context) -> bool:
        return (
            ctx.author.guild_permissions.administrator
            or ctx.author.guild_permissions.manage_messages
        )
    return commands.check(predicate)


@bot.command(name="warnings")
@is_admin()
async def cmd_warnings(ctx, member: discord.Member):
    """!warnings @user — количество предупреждений."""
    count = db.get_warnings(member.id, ctx.guild.id)
    embed = discord.Embed(title="📋 Предупреждения", color=discord.Color.orange())
    embed.add_field(name="Пользователь", value=member.mention)
    embed.add_field(name="Предупреждений", value=f"**{count}** / {config.MAX_WARNINGS}")
    await ctx.send(embed=embed)


@bot.command(name="clearwarnings")
@is_admin()
async def cmd_clearwarnings(ctx, member: discord.Member):
    """!clearwarnings @user — сброс предупреждений."""
    db.reset_warnings(member.id, ctx.guild.id)
    embed = discord.Embed(
        title="✅ Предупреждения сброшены",
        description=f"Предупреждения {member.mention} очищены.",
        color=discord.Color.green(),
    )
    await ctx.send(embed=embed)


@bot.command(name="testdetect")
@is_admin()
async def cmd_testdetect(ctx):
    """!testdetect — тест детекции (прикрепи картинку)."""
    if not ctx.message.attachments:
        await ctx.send("❌ Прикрепи изображение к сообщению с командой `!testdetect`")
        return

    attachment = ctx.message.attachments[0]
    if not is_image(attachment.filename):
        await ctx.send("❌ Файл не является изображением.")
        return

    msg = await ctx.send("⏳ Анализирую...")
    image_data = await download_attachment(attachment)
    if not image_data:
        await msg.edit(content="❌ Не удалось скачать.")
        return

    is_spam, confidence, method = detector.predict(image_data)

    color = discord.Color.red() if is_spam else discord.Color.green()
    verdict = "🚫 СПАМ" if is_spam else "✅ Чисто"

    embed = discord.Embed(title=f"🔍 Тест: {verdict}", color=color)
    embed.add_field(name="Уверенность", value=f"{confidence:.0%}", inline=True)
    embed.add_field(name="Метод", value=method or "—", inline=True)
    embed.add_field(name="Порог", value=f"{config.CONFIDENCE_THRESHOLD:.0%}", inline=True)
    embed.add_field(name="Файл", value=attachment.filename, inline=False)

    if is_spam:
        embed.add_field(
            name="Действие",
            value="⚠️ Это изображение БУДЕТ удалено при обычной отправке",
            inline=False,
        )
    else:
        embed.add_field(
            name="Действие",
            value="✅ Это изображение НЕ будет удалено",
            inline=False,
        )

    await msg.edit(content=None, embed=embed)


@bot.command(name="addspam")
@is_admin()
async def cmd_addspam(ctx):
    """!addspam — добавить изображение в базу спама (прикрепи картинку)."""
    if not ctx.message.attachments:
        await ctx.send("❌ Прикрепи изображение к `!addspam`")
        return

    attachment = ctx.message.attachments[0]
    if not is_image(attachment.filename):
        await ctx.send("❌ Не изображение.")
        return

    image_data = await download_attachment(attachment)
    if not image_data:
        await ctx.send("❌ Не удалось скачать.")
        return

    try:
        import imagehash
        from PIL import Image
        import io
        image = Image.open(io.BytesIO(image_data)).convert("RGB")
        phash = str(imagehash.phash(image, hash_size=12))
        detector._save_hash(phash)

        embed = discord.Embed(
            title="✅ Спам-хеш добавлен",
            description=(
                f"Хеш: `{phash}`\n"
                f"Всего в базе: **{len(detector.known_hashes)}** хешей\n\n"
                "Теперь это изображение и похожие будут автоматически удаляться."
            ),
            color=discord.Color.green(),
        )
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"❌ Ошибка: {e}")


@bot.command(name="reloadmodel")
@is_admin()
async def cmd_reloadmodel(ctx):
    """!reloadmodel — перезагрузить базу хешей."""
    detector.reload()
    embed = discord.Embed(
        title="✅ Детектор перезагружен",
        description=f"Известных спам-хешей: **{len(detector.known_hashes)}**",
        color=discord.Color.green(),
    )
    await ctx.send(embed=embed)


@bot.command(name="setlogchannel")
@is_admin()
async def cmd_setlogchannel(ctx, channel: discord.TextChannel):
    """!setlogchannel #канал — настроить канал для логов."""
    db.set_log_channel(ctx.guild.id, channel.id)
    embed = discord.Embed(
        title="✅ Лог-канал настроен",
        description=f"Уведомления → {channel.mention}",
        color=discord.Color.green(),
    )
    await ctx.send(embed=embed)
    await channel.send("🔍 Этот канал выбран для логов Anti-Spam бота.")


@bot.command(name="stats")
@is_admin()
async def cmd_stats(ctx):
    """!stats — статистика бота."""
    stats = db.get_stats()
    embed = discord.Embed(
        title="📊 Статистика Anti-Spam",
        color=discord.Color.blurple(),
        timestamp=datetime.utcnow(),
    )
    embed.add_field(name="🖼️ Проверено", value=stats.get("images_checked", 0))
    embed.add_field(name="🚫 Нарушений", value=stats.get("violations_found", 0))
    embed.add_field(name="🔇 Мутов", value=stats.get("users_muted", 0))
    embed.add_field(name="📦 Спам-хешей", value=len(detector.known_hashes))
    embed.add_field(name="⚙️ Порог", value=f"{config.CONFIDENCE_THRESHOLD:.0%}")
    embed.add_field(name="🏢 Серверов", value=len(bot.guilds))
    await ctx.send(embed=embed)


@bot.command(name="help")
async def cmd_help(ctx):
    """!help — список команд."""
    embed = discord.Embed(
        title="🤖 Anti-Spam Bot — Команды",
        color=discord.Color.blurple(),
    )
    embed.add_field(name="!testdetect", value="Тест детекции (прикрепи картинку)", inline=False)
    embed.add_field(name="!addspam", value="Добавить картинку в базу спама", inline=False)
    embed.add_field(name="!warnings @user", value="Предупреждения пользователя", inline=False)
    embed.add_field(name="!clearwarnings @user", value="Сбросить предупреждения", inline=False)
    embed.add_field(name="!setlogchannel #канал", value="Канал для уведомлений", inline=False)
    embed.add_field(name="!reloadmodel", value="Перезагрузить базу хешей", inline=False)
    embed.add_field(name="!stats", value="Статистика бота", inline=False)
    embed.set_footer(text="Только для администраторов (manage_messages)")
    await ctx.send(embed=embed)


# ---------------------------------------------------------------------------
# Ошибки
# ---------------------------------------------------------------------------

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ Не хватает аргумента: `{error.param.name}`. Используй `!help`.")
    elif isinstance(error, commands.MemberNotFound):
        await ctx.send("❌ Пользователь не найден.")
    elif isinstance(error, commands.CheckFailure):
        await ctx.send("❌ Нет прав для этой команды.")
    elif isinstance(error, commands.CommandNotFound):
        pass
    else:
        logger.error("Ошибка: %s: %s", ctx.command, error, exc_info=True)


# ---------------------------------------------------------------------------
# Запуск
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if config.TOKEN == "YOUR_BOT_TOKEN_HERE":
        logger.error(
            "Токен не настроен! Установите DISCORD_TOKEN в Environment Variables."
        )
        raise SystemExit(1)

    logger.info("Запуск бота...")
    bot.run(config.TOKEN, log_handler=None)
