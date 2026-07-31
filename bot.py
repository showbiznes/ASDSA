# =============================================================================
# bot.py — Discord Anti-Spam бот (v3 — обучение на примерах)
# =============================================================================
# Администратор добавляет примеры спама через !addspam
# Бот запоминает "отпечаток" и ловит все ПОХОЖИЕ изображения
# Без torch, без CLIP — работает на bothost.ru Basic
# =============================================================================

import logging
import logging.handlers
from datetime import datetime, timedelta
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

log_fmt = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
fh = logging.handlers.TimedRotatingFileHandler(
    config.LOG_FILE, when="D", interval=7, backupCount=4, encoding="utf-8",
)
fh.setFormatter(log_fmt)
ch = logging.StreamHandler()
ch.setFormatter(log_fmt)
logging.basicConfig(level=logging.INFO, handlers=[fh, ch])
logger = logging.getLogger("antispam.bot")

# ---------------------------------------------------------------------------
# Бот
# ---------------------------------------------------------------------------
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)
detector = ImageDetector()


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

async def send_log(guild, msg):
    ch_id = db.get_log_channel(guild.id) or config.LOG_CHANNEL_ID
    if not ch_id:
        return
    ch = guild.get_channel(ch_id)
    if ch:
        try:
            await ch.send(msg)
        except discord.Forbidden:
            pass


async def download(att: discord.Attachment) -> bytes | None:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(att.url) as r:
                if r.status == 200:
                    return await r.read()
    except Exception as e:
        logger.error("Скачивание: %s", e)
    return None


def is_image(fn: str) -> bool:
    return Path(fn).suffix.lower() in config.SUPPORTED_FORMATS


# ---------------------------------------------------------------------------
# События
# ---------------------------------------------------------------------------

@bot.event
async def on_ready():
    db.init_db()
    logger.info("Бот: %s | Серверов: %d | Примеров спама: %d",
                bot.user, len(bot.guilds), len(detector.examples))
    await bot.change_presence(activity=discord.Activity(
        type=discord.ActivityType.watching,
        name=f"за спамом | {len(detector.examples)} примеров",
    ))


@bot.event
async def on_guild_join(guild):
    logger.info("Новый сервер: %s", guild.name)
    for ch in guild.text_channels:
        if ch.permissions_for(guild.me).send_messages:
            embed = discord.Embed(
                title="🔐 Anti-Spam Бот подключён!",
                description=(
                    "Я удаляю рекламу казино и гемблинга.\n\n"
                    "**Быстрый старт:**\n"
                    "1. `!addspam` — прикрепи спам-картинку (бот запомнит)\n"
                    "2. `!testdetect` — проверь детекцию на картинке\n"
                    "3. `!help` — все команды\n\n"
                    "⚠️ Нужны права: **Manage Messages** + **Moderate Members**"
                ),
                color=discord.Color.blurple(),
            )
            await ch.send(embed=embed)
            break


# ---------------------------------------------------------------------------
# Обработка сообщений
# ---------------------------------------------------------------------------

@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    if message.attachments:
        for att in message.attachments:
            if not is_image(att.filename):
                continue

            data = await download(att)
            if not data:
                continue

            db.increment_stat("images_checked")
            is_spam, confidence, method = detector.predict(data)

            logger.info("%s | %s | spam=%s | %.0f%% | %s",
                        message.author, att.filename, is_spam,
                        confidence * 100, method)

            if is_spam:
                await handle_violation(message, att, data, confidence, method)
                return

    await bot.process_commands(message)


async def handle_violation(message, att, data, confidence, method):
    guild = message.guild
    member = message.author

    try:
        await message.delete()
    except discord.Forbidden:
        logger.warning("Нет прав удалять в %s", guild.name)
        return
    except discord.NotFound:
        pass

    count = db.add_warning(member.id, guild.id)
    db.increment_stat("violations_found")
    db.log_violation(member.id, guild.id, str(member), att.filename,
                     confidence, method, "mute" if count >= config.MAX_WARNINGS else "warn")

    if count >= config.MAX_WARNINGS:
        try:
            await member.timeout(
                timedelta(seconds=config.MUTE_DURATION),
                reason=f"Спам ({count} предупреждений)",
            )
            db.increment_stat("users_muted")
        except discord.Forbidden:
            pass
        db.reset_warnings(member.id, guild.id)
        msg = config.MSG_MUTED.format(
            mention=member.mention,
            duration=config.MUTE_DURATION // 60,
            warnings=count,
        )
        try:
            await message.channel.send(msg)
        except Exception:
            pass
        await send_log(guild, f"🔇 {member} замучен | {method}")
    else:
        msg = config.MSG_WARNING.format(
            mention=member.mention,
            warnings=count,
            max_warnings=config.MAX_WARNINGS,
            confidence=confidence,
            method=method,
        )
        try:
            await message.channel.send(msg, delete_after=15)
        except Exception:
            pass
        await send_log(guild, f"⚠️ {member} | {count}/{config.MAX_WARNINGS} | {method}")


# ---------------------------------------------------------------------------
# Команды
# ---------------------------------------------------------------------------

def is_admin():
    async def pred(ctx):
        return (ctx.author.guild_permissions.administrator
                or ctx.author.guild_permissions.manage_messages)
    return commands.check(pred)


@bot.command(name="addspam")
@is_admin()
async def cmd_addspam(ctx):
    """Добавить пример спама (прикрепи 1+ картинок)."""
    images = [a for a in ctx.message.attachments if is_image(a.filename)]
    if not images:
        await ctx.send("❌ Прикрепи одну или несколько спам-картинок к `!addspam`")
        return

    msg = await ctx.send(f"⏳ Обрабатываю {len(images)} изображений...")
    results = []

    for att in images:
        data = await download(att)
        if not data:
            results.append(f"❌ {att.filename} — не удалось скачать")
            continue
        result = detector.add_example(data, att.filename, str(ctx.author))
        results.append(f"📎 **{att.filename}** — {result}")

    embed = discord.Embed(
        title=f"📦 Добавление примеров спама ({len(images)} шт)",
        description="\n".join(results),
        color=discord.Color.green(),
    )
    embed.add_field(name="Всего примеров в базе", value=f"**{len(detector.examples)}**")
    embed.set_footer(text=f"Добавил: {ctx.author}")
    await msg.edit(content=None, embed=embed)

    # Обновляем статус
    await bot.change_presence(activity=discord.Activity(
        type=discord.ActivityType.watching,
        name=f"за спамом | {len(detector.examples)} примеров",
    ))


@bot.command(name="testdetect")
@is_admin()
async def cmd_testdetect(ctx):
    """Тест детекции (прикрепи картинку)."""
    if not ctx.message.attachments:
        await ctx.send("❌ Прикрепи изображение к `!testdetect`")
        return

    att = ctx.message.attachments[0]
    if not is_image(att.filename):
        await ctx.send("❌ Не изображение.")
        return

    msg = await ctx.send("⏳ Анализирую...")
    data = await download(att)
    if not data:
        await msg.edit(content="❌ Не скачалось.")
        return

    result = detector.predict_detailed(data)

    if result["examples_count"] == 0:
        embed = discord.Embed(
            title="⚠️ Нет примеров спама!",
            description=(
                "Бот не знает что считать спамом.\n\n"
                "**Добавь примеры:**\n"
                "`!addspam` + прикрепи спам-картинку"
            ),
            color=discord.Color.orange(),
        )
        await msg.edit(content=None, embed=embed)
        return

    is_spam = result["is_spam"]
    best_sim = result["best_sim"]
    color = discord.Color.red() if is_spam else discord.Color.green()
    verdict = "🚫 СПАМ" if is_spam else "✅ Чисто"

    embed = discord.Embed(title=f"🔍 Тест: {verdict}", color=color)
    embed.add_field(name="Файл", value=att.filename, inline=False)
    embed.add_field(name="Лучшее совпадение", value=f"{best_sim:.0%}", inline=True)
    embed.add_field(name="Порог", value=f"{detector.SIMILARITY_THRESHOLD:.0%}", inline=True)
    embed.add_field(name="Похож на", value=result["best_example"] or "—", inline=True)

    # Топ-5 совпадений
    top = result["matches"][:5]
    if top:
        lines = []
        for m in top:
            icon = "🔴" if m["is_match"] else "⚪"
            lines.append(f"{icon} #{m['index']} `{m['filename']}` — **{m['similarity']:.0%}**")
        embed.add_field(name="Сравнение с примерами", value="\n".join(lines), inline=False)

    if is_spam:
        embed.add_field(name="Действие", value="⚠️ БУДЕТ удалено", inline=False)
    else:
        embed.add_field(name="Действие", value="✅ НЕ будет удалено", inline=False)

    await msg.edit(content=None, embed=embed)


@bot.command(name="spamlist")
@is_admin()
async def cmd_spamlist(ctx):
    """Показать все примеры спама в базе."""
    if not detector.examples:
        await ctx.send("📦 База пуста. Добавь примеры через `!addspam`")
        return

    lines = []
    for i, ex in enumerate(detector.examples):
        fn = ex.get("filename", "?")
        by = ex.get("added_by", "?")
        at = ex.get("added_at", "?")[:10]
        lines.append(f"**#{i+1}** `{fn}` — добавил {by} ({at})")

    embed = discord.Embed(
        title=f"📦 Примеры спама ({len(detector.examples)} шт)",
        description="\n".join(lines),
        color=discord.Color.blurple(),
    )
    embed.set_footer(text="Удалить: !removespam <номер>")
    await ctx.send(embed=embed)


@bot.command(name="removespam")
@is_admin()
async def cmd_removespam(ctx, number: int):
    """!removespam 3 — удалить пример #3."""
    result = detector.remove_example(number)
    await ctx.send(result)


@bot.command(name="warnings")
@is_admin()
async def cmd_warnings(ctx, member: discord.Member):
    count = db.get_warnings(member.id, ctx.guild.id)
    embed = discord.Embed(title="📋 Предупреждения", color=discord.Color.orange())
    embed.add_field(name="Пользователь", value=member.mention)
    embed.add_field(name="Предупреждений", value=f"**{count}** / {config.MAX_WARNINGS}")
    await ctx.send(embed=embed)


@bot.command(name="clearwarnings")
@is_admin()
async def cmd_clearwarnings(ctx, member: discord.Member):
    db.reset_warnings(member.id, ctx.guild.id)
    await ctx.send(f"✅ Предупреждения {member.mention} сброшены.")


@bot.command(name="setlogchannel")
@is_admin()
async def cmd_setlogchannel(ctx, channel: discord.TextChannel):
    db.set_log_channel(ctx.guild.id, channel.id)
    await ctx.send(f"✅ Логи → {channel.mention}")
    await channel.send("🔍 Этот канал для логов Anti-Spam бота.")


@bot.command(name="reloadmodel")
@is_admin()
async def cmd_reload(ctx):
    detector.reload()
    await ctx.send(f"✅ Перезагружено. Примеров: **{len(detector.examples)}**")


@bot.command(name="stats")
@is_admin()
async def cmd_stats(ctx):
    stats = db.get_stats()
    embed = discord.Embed(title="📊 Статистика", color=discord.Color.blurple(),
                          timestamp=datetime.utcnow())
    embed.add_field(name="🖼️ Проверено", value=stats.get("images_checked", 0))
    embed.add_field(name="🚫 Нарушений", value=stats.get("violations_found", 0))
    embed.add_field(name="🔇 Мутов", value=stats.get("users_muted", 0))
    embed.add_field(name="📦 Примеров спама", value=len(detector.examples))
    embed.add_field(name="🏢 Серверов", value=len(bot.guilds))
    await ctx.send(embed=embed)


@bot.command(name="help")
async def cmd_help(ctx):
    embed = discord.Embed(
        title="🤖 Anti-Spam Bot",
        description="Обучается на примерах — покажи ему спам, он запомнит!",
        color=discord.Color.blurple(),
    )
    embed.add_field(name="📌 Основные", value=(
        "`!addspam` — добавить пример спама (прикрепи картинки)\n"
        "`!testdetect` — тест на картинке\n"
        "`!spamlist` — все примеры в базе\n"
        "`!removespam <N>` — удалить пример #N"
    ), inline=False)
    embed.add_field(name="⚙️ Управление", value=(
        "`!warnings @user` — предупреждения\n"
        "`!clearwarnings @user` — сбросить\n"
        "`!setlogchannel #канал` — канал для логов\n"
        "`!reloadmodel` — перезагрузить базу\n"
        "`!stats` — статистика"
    ), inline=False)
    embed.set_footer(text="Только для администраторов")
    await ctx.send(embed=embed)


# ---------------------------------------------------------------------------
# Ошибки
# ---------------------------------------------------------------------------

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ Не хватает аргумента. Используй `!help`.")
    elif isinstance(error, commands.MemberNotFound):
        await ctx.send("❌ Пользователь не найден.")
    elif isinstance(error, commands.CheckFailure):
        await ctx.send("❌ Нет прав.")
    elif isinstance(error, commands.CommandNotFound):
        pass
    else:
        logger.error("Ошибка: %s", error, exc_info=True)


# ---------------------------------------------------------------------------
# Запуск
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if config.TOKEN == "YOUR_BOT_TOKEN_HERE":
        logger.error("DISCORD_TOKEN не установлен!")
        raise SystemExit(1)
    logger.info("Запуск...")
    bot.run(config.TOKEN, log_handler=None)

