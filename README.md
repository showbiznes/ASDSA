# Discord Anti-Spam Bot

## Обзор

Discord-бот для автоматической модерации изображений казино, гемблинга и мошеннических схем.

### Что распознаёт

| Тип | Пример |
|-----|--------|
| Скриншоты казино-сайтов | Rasowin, Mellgams — страницы Slots/Bonuses/Withdraw |
| Скриншоты "Withdrawal Success" | Сообщения об успешном выводе крипты |
| Фейковые новости | Скриншоты «РИА Новости» с рекламой казино |
| Балансы казино | Скрин баланса с кнопкой «Пополнить» |
| Криптовалютные выводы | USDT, BEP20, TRC20 переводы с казино |

### Технологии

```
CLIP (ViT-B/32)    — zero-shot детекция, работает БЕЗ обучения
EfficientNet-B0    — дообучается на вашем датасете
OCR (pytesseract)  — поиск ключевых слов в тексте на изображении
```

---

## Быстрый старт (Linux / Bothost.ru)

### 1. Установка Python 3.11

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y python3.11 python3.11-venv python3-pip

# Проверка
python3.11 --version
```

### 2. Клонирование / загрузка проекта

```bash
# Загрузите файлы проекта в папку
mkdir ~/discord_antispam && cd ~/discord_antispam
# Скопируйте все файлы проекта сюда
```

### 3. Создание виртуального окружения

```bash
python3.11 -m venv venv
source venv/bin/activate
```

### 4. Установка зависимостей

```bash
# Основные зависимости
pip install --upgrade pip
pip install discord.py==2.3.2 aiohttp==3.9.5 Pillow==10.3.0 pytesseract==0.3.10

# PyTorch (CPU)
pip install torch==2.3.1 torchvision==0.18.1 --index-url https://download.pytorch.org/whl/cpu

# CLIP (zero-shot детекция — работает без обучения!)
pip install openai-clip ftfy regex

# Tesseract OCR (вспомогательный)
sudo apt install -y tesseract-ocr tesseract-ocr-rus
```

### 5. Создание Discord-приложения

1. Откройте [discord.com/developers/applications](https://discord.com/developers/applications)
2. Нажмите **New Application** → введите название
3. Перейдите в **Bot** → нажмите **Add Bot**
4. Скопируйте **токен** (Reset Token)
5. Включите в разделе **Privileged Gateway Intents**:
   - ✅ `Message Content Intent`
   - ✅ `Server Members Intent`
6. В разделе **OAuth2 → URL Generator** выберите:
   - Scopes: `bot`
   - Bot Permissions: `Manage Messages`, `Moderate Members`, `Send Messages`, `Read Message History`, `View Channels`
7. Перейдите по сгенерированной ссылке и добавьте бота на сервер

### 6. Настройка config.py

Откройте `config.py` и заполните:

```python
TOKEN = "ВАШ_ТОКЕН_ЗДЕСЬ"
GUILD_ID = 123456789          # ID вашего сервера (правая кнопка → Скопировать ID)
LOG_CHANNEL_ID = 987654321    # ID канала для уведомлений (0 = отключить)
```

Или используйте переменные окружения:

```bash
export DISCORD_TOKEN="ВАШ_ТОКЕН"
export GUILD_ID="123456789"
export LOG_CHANNEL_ID="987654321"
```

### 7. Заполнение датасета

```
dataset/
  spam/    ← скриншоты казино, фейковых новостей, withdrawal, балансов
  normal/  ← мемы, фото, скрины игр, обычные изображения
```

**Рекомендуемое количество:**
- Минимум: 50 изображений на класс
- Хорошо: 200+ на класс
- Отлично: 500+ на класс

> **Важно:** CLIP работает **без датасета**! Он распознаёт казино-изображения с первого запуска.
> EfficientNet нужен только для повышения точности на вашем конкретном датасете.

### 8. Обучение модели (опционально)

```bash
# Базовый запуск
python train.py

# Расширенный запуск
python train.py --epochs 30 --batch-size 16 --lr 0.0001

# Проверить аргументы
python train.py --help
```

После обучения модель сохранится в `model/model.pt`.

### 9. Запуск бота

```bash
python bot.py
```

---

## Запуск через screen (рекомендуется для Bothost.ru)

```bash
# Создаём сессию
screen -S antispam_bot

# Запускаем бота
cd ~/discord_antispam
source venv/bin/activate
python bot.py

# Отключаемся (бот продолжает работать)
# Нажмите: Ctrl+A → D

# Подключиться обратно
screen -r antispam_bot

# Список сессий
screen -ls
```

## Запуск через systemd (для VPS/хостинга)

Создайте файл `/etc/systemd/system/antispam-bot.service`:

```ini
[Unit]
Description=Discord Anti-Spam Bot
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/discord_antispam
Environment=DISCORD_TOKEN=ВАШ_ТОКЕН
ExecStart=/home/YOUR_USERNAME/discord_antispam/venv/bin/python bot.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable antispam-bot
sudo systemctl start antispam-bot
sudo systemctl status antispam-bot

# Просмотр логов
journalctl -u antispam-bot -f
```

---

## Обновление модели без остановки бота

```bash
# 1. Добавьте новые изображения в dataset/spam/ и dataset/normal/
# 2. Обучите новую модель
python train.py

# 3. В Discord-чате выполните команду:
# !reloadmodel

# Бот перезагрузит model/model.pt без перезапуска
```

---

## Команды администратора

| Команда | Описание |
|---------|----------|
| `!warnings @user` | Показать предупреждения пользователя |
| `!clearwarnings @user` | Сбросить предупреждения |
| `!reloadmodel` | Перезагрузить модель с диска |
| `!stats` | Статистика: проверено/нарушений/мутов |
| `!help` | Список команд |

> Команды доступны пользователям с правами `Administrator` или `Manage Messages`.

---

## Система наказаний

```
1-е нарушение → Удаление + Предупреждение 1/3
2-е нарушение → Удаление + Предупреждение 2/3
3-е нарушение → Удаление + Мут 1 час + Сброс счётчика
```

После окончания мута предупреждения автоматически обнуляются.

---

## "Серая зона" — ручная проверка

Если уверенность модели между `CONFIDENCE_THRESHOLD * 0.7` и `CONFIDENCE_THRESHOLD`:
- Изображение сохраняется в `logs/review/`
- Событие записывается в лог
- В лог-канал отправляется уведомление для администраторов

---

## Структура проекта

```
discord_antispam/
├── bot.py          ← Основной файл бота
├── train.py        ← Обучение модели
├── detector.py     ← Детектор (CLIP + EfficientNet + OCR)
├── database.py     ← SQLite: предупреждения и статистика
├── config.py       ← Все настройки
├── requirements.txt
├── README.md
│
├── dataset/
│   ├── spam/       ← Изображения казино/гемблинга
│   └── normal/     ← Обычные изображения
│
├── model/
│   └── model.pt    ← Обученная модель (после train.py)
│
├── logs/
│   ├── violations.log   ← Лог нарушений
│   └── review/          ← Изображения на ручную проверку
│
└── warnings.db     ← SQLite база данных
```

---

## Частые проблемы

**Бот не видит сообщения:**
> Включите `Message Content Intent` в настройках приложения Discord.

**CLIP не загружается:**
> `pip install openai-clip ftfy` — первый запуск скачает ~350 МБ весов.

**Tesseract не найден:**
> `sudo apt install tesseract-ocr tesseract-ocr-rus`
> OCR — вспомогательный метод, бот работает и без него.

**Мало изображений для обучения:**
> CLIP работает без датасета! Добавьте хотя бы 50 изображений на класс для EfficientNet.

**Ошибка Permission: Missing Access:**
> Выдайте боту права `Moderate Members` (для мута) и `Manage Messages` (для удаления).
