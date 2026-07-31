# =============================================================================
# detector.py — Детекция спам-изображений БЕЗ нейросетей
# =============================================================================
# Работает на bothost.ru Basic (1 GB RAM, 5 GB SSD)
# Методы:
#   1. OCR (pytesseract) — ищет ключевые слова казино/гемблинга
#   2. Анализ цвета (PIL) — тёмно-синие казино-интерфейсы
#   3. Перцептивный хеш (imagehash) — сравнение с известным спамом
#   4. Комбо-скоринг — URL + зелёные кнопки + жёлтые акценты
# =============================================================================

import colorsys
import io
import json
import logging
import re
from pathlib import Path

from PIL import Image

import config

logger = logging.getLogger("antispam.detector")


# ---------------------------------------------------------------------------
# Ключевые слова для OCR
# ---------------------------------------------------------------------------
SPAM_KEYWORDS_HIGH = [
    # Прямые упоминания казино (высокий приоритет — сразу спам)
    "казино", "casino", "слоты", "slots", "джекпот", "jackpot",
    "рулетка", "roulette", "букмекер", "bookmaker", "1xbet", "1хбет",
    "мелбет", "melbet", "winline", "betwinner", "fonbet", "фонбет",
    "rasowin", "mellgams", "mellgames", "bwin", "betway",
    "withdrawal success", "withdrawal of $",
    "vip-club", "vip club", "rakeback",
    "mellgams.com", "mell coins",
]

SPAM_KEYWORDS_MEDIUM = [
    # Подозрительные слова (нужно 2+ совпадения)
    "бонус", "bonus", "фриспин", "freespin", "free spin",
    "пополнить", "deposit", "вывод", "withdraw", "cashback",
    "промокод", "promo code", "промо код",
    "ставки", "betting", "гемблинг", "gambling", "покер", "poker",
    "выигрыш", "выиграй", "заработай", "халява",
    "usdt", "trc20", "bep20", "erc20", "tether",
    "раздаёт", "раздает", "на баланс", "регистрации деньги",
    "t.me/", "телеграм",
]

# URL в изображениях — подозрительно
URL_PATTERN = re.compile(
    r"(https?://|t\.me/|www\.|\w+\.(com|ru|net|io|me|cc|org)/)\S*",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Цветовые диапазоны казино-интерфейсов (HSV)
# ---------------------------------------------------------------------------
# Тёмно-синий/фиолетовый фон (Rasowin, Mellgams, большинство казино-сайтов)
CASINO_DARK_BLUE = {
    "hue_min": 190, "hue_max": 280,   # синий→фиолетовый
    "sat_min": 30,                      # не серый
    "val_max": 130,                     # тёмный
}

# Ярко-зелёные кнопки (Пополнить, Claim, Activate, Play)
CASINO_GREEN = {
    "hue_min": 80, "hue_max": 160,
    "sat_min": 40,
    "val_min": 120,
}

# Золотой/жёлтый акцент (VIP, джекпот, монеты)
CASINO_GOLD = {
    "hue_min": 30, "hue_max": 60,
    "sat_min": 50,
    "val_min": 150,
}


class ImageDetector:
    """
    Детектор спам-изображений без нейросетей.
    Работает на любом хостинге с 256+ МБ RAM.
    """

    def __init__(self) -> None:
        self._load_known_hashes()
        logger.info(
            "ImageDetector запущен (OCR=✓, Цвет=✓, Хеши=%d шт)",
            len(self.known_hashes),
        )

    def _load_known_hashes(self) -> None:
        """Загружает известные хеши спам-изображений из JSON."""
        self.known_hashes = set()
        hash_path = Path(config.HASH_DB_PATH)
        if hash_path.exists():
            try:
                data = json.loads(hash_path.read_text(encoding="utf-8"))
                self.known_hashes = set(data.get("hashes", []))
                logger.info("Загружено %d известных спам-хешей", len(self.known_hashes))
            except Exception as e:
                logger.error("Ошибка загрузки хешей: %s", e)

    def _save_hash(self, phash_str: str) -> None:
        """Сохраняет новый хеш в базу известных спам-изображений."""
        self.known_hashes.add(phash_str)
        hash_path = Path(config.HASH_DB_PATH)
        try:
            data = {"hashes": list(self.known_hashes)}
            hash_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.error("Ошибка сохранения хеша: %s", e)

    def reload(self) -> bool:
        """Перезагрузка (для совместимости с командой !reloadmodel)."""
        self._load_known_hashes()
        return True

    # -----------------------------------------------------------------------
    # Основной метод
    # -----------------------------------------------------------------------

    def predict(self, image_data: bytes) -> tuple:
        """
        Анализирует изображение и определяет, является ли оно спамом.

        Returns:
            (is_spam, confidence, method_description)
        """
        scores = {}  # метод → (is_spam, confidence, details)

        # --- 1. Перцептивный хеш (быстрая проверка) ---
        hash_result = self._check_hash(image_data)
        if hash_result:
            return True, 0.95, "hash (известный спам)"

        # --- 2. Анализ цвета ---
        color_spam, color_conf, color_details = self._analyze_color(image_data)
        scores["color"] = (color_spam, color_conf, color_details)

        # --- 3. OCR ---
        ocr_spam, ocr_conf, ocr_details = self._analyze_ocr(image_data)
        scores["ocr"] = (ocr_spam, ocr_conf, ocr_details)

        # --- Агрегация ---
        return self._aggregate(scores, image_data)

    # -----------------------------------------------------------------------
    # Метод 1: Перцептивный хеш
    # -----------------------------------------------------------------------

    def _check_hash(self, image_data: bytes) -> bool:
        """Сравнивает изображение с базой известного спама по pHash."""
        try:
            import imagehash
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
            phash = imagehash.phash(image, hash_size=12)
            phash_str = str(phash)

            # Точное совпадение
            if phash_str in self.known_hashes:
                logger.info("Хеш-совпадение: %s", phash_str)
                return True

            # Похожий хеш (расстояние Хэмминга <= 8)
            for known in self.known_hashes:
                try:
                    known_hash = imagehash.hex_to_hash(known)
                    if phash - known_hash <= 8:
                        logger.info(
                            "Похожий хеш: %s ≈ %s (dist=%d)",
                            phash_str, known, phash - known_hash,
                        )
                        return True
                except Exception:
                    continue

        except ImportError:
            logger.debug("imagehash не установлен")
        except Exception as e:
            logger.debug("Ошибка хеширования: %s", e)

        return False

    # -----------------------------------------------------------------------
    # Метод 2: Анализ цвета
    # -----------------------------------------------------------------------

    def _analyze_color(self, image_data: bytes) -> tuple:
        """
        Анализирует цветовой состав изображения.

        Казино-сайты имеют характерную палитру:
        - Тёмно-синий/фиолетовый фон (>30% пикселей)
        - Ярко-зелёные кнопки (2-10%)
        - Золотые/жёлтые акценты (VIP, джекпот)

        Returns:
            (is_spam, confidence, details_string)
        """
        try:
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
            thumb = image.resize((100, 100))
            pixels = list(thumb.getdata())
            total = len(pixels)

            dark_blue = 0
            green = 0
            gold = 0
            very_dark = 0  # почти чёрный

            for r, g, b in pixels:
                h, s, v = colorsys.rgb_to_hsv(r / 255, g / 255, b / 255)
                hue = h * 360
                sat = s * 100
                val = v * 255

                # Тёмно-синий/фиолетовый
                if (CASINO_DARK_BLUE["hue_min"] <= hue <= CASINO_DARK_BLUE["hue_max"]
                        and sat >= CASINO_DARK_BLUE["sat_min"]
                        and val <= CASINO_DARK_BLUE["val_max"]):
                    dark_blue += 1

                # Ярко-зелёный
                if (CASINO_GREEN["hue_min"] <= hue <= CASINO_GREEN["hue_max"]
                        and sat >= CASINO_GREEN["sat_min"]
                        and val >= CASINO_GREEN["val_min"]):
                    green += 1

                # Золотой/жёлтый
                if (CASINO_GOLD["hue_min"] <= hue <= CASINO_GOLD["hue_max"]
                        and sat >= CASINO_GOLD["sat_min"]
                        and val >= CASINO_GOLD["val_min"]):
                    gold += 1

                # Очень тёмный (фон казино-сайтов)
                if val <= 40:
                    very_dark += 1

            db_ratio = dark_blue / total
            gr_ratio = green / total
            gd_ratio = gold / total
            vd_ratio = very_dark / total

            details = (
                f"dark_blue={db_ratio:.0%} green={gr_ratio:.0%} "
                f"gold={gd_ratio:.0%} dark={vd_ratio:.0%}"
            )

            confidence = 0.0

            # Паттерн 1: Классический казино-сайт (синий фон + зелёные кнопки)
            if db_ratio >= 0.30 and gr_ratio >= 0.02:
                confidence = min(0.50 + db_ratio * 0.8, 0.85)
                return True, confidence, details

            # Паттерн 2: Очень тёмный + синий (withdrawal screens)
            if db_ratio >= 0.25 and vd_ratio >= 0.20:
                confidence = min(0.45 + db_ratio * 0.7, 0.80)
                return True, confidence, details

            # Паттерн 3: Синий + золотой (VIP, джекпот-страницы)
            if db_ratio >= 0.25 and gd_ratio >= 0.03:
                confidence = min(0.45 + db_ratio * 0.7, 0.80)
                return True, confidence, details

            # Паттерн 4: Подавляющий тёмно-синий (>45%)
            if db_ratio >= 0.45:
                confidence = min(db_ratio * 1.2, 0.80)
                return True, confidence, details

            # Подозрительный, но не спам
            confidence = db_ratio * 0.5
            return False, confidence, details

        except Exception as e:
            logger.debug("Ошибка анализа цвета: %s", e)
            return False, 0.0, "error"

    # -----------------------------------------------------------------------
    # Метод 3: OCR
    # -----------------------------------------------------------------------

    def _analyze_ocr(self, image_data: bytes) -> tuple:
        """
        Ищет ключевые слова казино/гемблинга в тексте на изображении.

        Returns:
            (is_spam, confidence, found_keywords_string)
        """
        try:
            import pytesseract
        except ImportError:
            logger.debug("pytesseract не установлен")
            return False, 0.0, "no_ocr"

        try:
            image = Image.open(io.BytesIO(image_data)).convert("RGB")

            # Пробуем русский+английский, если нет — только английский
            try:
                text = pytesseract.image_to_string(image, lang="rus+eng").lower()
            except Exception:
                text = pytesseract.image_to_string(image, lang="eng").lower()

            if not text.strip():
                return False, 0.0, "no_text"

            # Ищем высокоприоритетные слова (одного достаточно)
            high_found = []
            for kw in SPAM_KEYWORDS_HIGH:
                if kw.lower() in text:
                    high_found.append(kw)

            if high_found:
                confidence = min(0.65 + len(high_found) * 0.08, 0.95)
                details = "HIGH: " + ", ".join(high_found[:5])
                logger.info("OCR нашёл HIGH-слова: %s", details)
                return True, confidence, details

            # Ищем среднеприоритетные (нужно 2+)
            medium_found = []
            for kw in SPAM_KEYWORDS_MEDIUM:
                if kw.lower() in text:
                    medium_found.append(kw)

            if len(medium_found) >= 2:
                confidence = min(0.50 + len(medium_found) * 0.10, 0.90)
                details = "MED: " + ", ".join(medium_found[:5])
                logger.info("OCR нашёл MEDIUM-слова: %s", details)
                return True, confidence, details

            # URL в изображении
            urls = URL_PATTERN.findall(text)
            if urls and medium_found:
                details = f"URL+{medium_found[0]}"
                return True, 0.70, details

            return False, 0.0, "clean"

        except Exception as e:
            logger.debug("Ошибка OCR: %s", e)
            return False, 0.0, "error"

    # -----------------------------------------------------------------------
    # Агрегация
    # -----------------------------------------------------------------------

    def _aggregate(self, scores: dict, image_data: bytes) -> tuple:
        """
        Объединяет результаты всех методов.

        Логика:
        - OCR HIGH → сразу спам
        - Цвет + OCR → бустим уверенность
        - Только цвет → нужна высокая уверенность
        """
        color_spam, color_conf, color_det = scores.get("color", (False, 0.0, ""))
        ocr_spam, ocr_conf, ocr_det = scores.get("ocr", (False, 0.0, ""))

        methods = []
        max_conf = 0.0

        if ocr_spam:
            methods.append(f"ocr({ocr_det})")
            max_conf = max(max_conf, ocr_conf)

        if color_spam:
            methods.append(f"color({color_det})")
            max_conf = max(max_conf, color_conf)

        method_str = " + ".join(methods) if methods else "none"

        # Оба метода сработали — бустим
        if ocr_spam and color_spam:
            boosted = min(max_conf * 1.2, 0.98)
            logger.info("МУЛЬТИ-ДЕТЕКТ: %s → %.0f%%", method_str, boosted * 100)

            # Сохраняем хеш для будущего быстрого распознавания
            self._auto_save_hash(image_data)

            return True, boosted, method_str

        # Один метод сработал
        if methods:
            is_spam = max_conf >= config.CONFIDENCE_THRESHOLD
            if is_spam:
                logger.info("ДЕТЕКТ: %s → %.0f%%", method_str, max_conf * 100)
                self._auto_save_hash(image_data)
            return is_spam, max_conf, method_str

        # Ничего не сработало
        return False, 0.0, "clean"

    def _auto_save_hash(self, image_data: bytes) -> None:
        """Автоматически сохраняет хеш подтверждённого спама."""
        try:
            import imagehash
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
            phash = str(imagehash.phash(image, hash_size=12))
            if phash not in self.known_hashes:
                self._save_hash(phash)
                logger.info("Новый спам-хеш сохранён: %s", phash)
        except Exception:
            pass
