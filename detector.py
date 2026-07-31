# =============================================================================
# detector.py — Детекция спам-изображений БЕЗ нейросетей (v2 — без фолзов)
# =============================================================================
# ПРАВИЛО: Цвет НИКОГДА не блокирует сам по себе!
# Блокируют только:
#   1. OCR HIGH (нашли слово "казино", "rasowin", "1xbet" и т.д.)
#   2. OCR MEDIUM (2+ подозрительных слова)
#   3. Хеш (совпадение с известным спамом)
#   4. OCR + Цвет вместе (комбо-буст)
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
# Ключевые слова OCR — ВЫСОКИЙ приоритет (одного достаточно для блокировки)
# ---------------------------------------------------------------------------
SPAM_KEYWORDS_HIGH = [
    # Названия казино-сайтов и букмекеров
    "rasowin", "mellgams", "mellgames", "mell coins",
    "1xbet", "1хбет", "1xstavka", "1хставка",
    "melbet", "мелбет", "fonbet", "фонбет",
    "winline", "betwinner", "bwin", "betway", "pin-up", "пин-ап",
    "вулкан казино", "vulkan casino", "joycasino", "cat casino",
    # Прямые слова
    "казино", "casino",
    "игровые автоматы", "slot machine",
    "withdrawal success", "withdrawal of $",
    "вывод средств успешен",
    "rakeback", "vip-club",
    "mellgams.com",
]

# ---------------------------------------------------------------------------
# Ключевые слова OCR — СРЕДНИЙ приоритет (нужно 3+ совпадения)
# ---------------------------------------------------------------------------
SPAM_KEYWORDS_MEDIUM = [
    "слоты", "slots", "джекпот", "jackpot",
    "рулетка", "roulette", "букмекер", "bookmaker",
    "фриспин", "freespin", "free spin",
    "промокод", "promo code",
    "ставки на спорт", "sports betting",
    "покер онлайн", "poker online",
    "usdt", "trc20", "bep20",
    "выигрыш гарантирован", "гарантированный выигрыш",
    "раздаёт 10000", "раздает рублей",
    "регистрации деньги", "на баланс при регистрации",
    "cashback casino", "кэшбек казино",
]

# URL-паттерны
URL_PATTERN = re.compile(
    r"(https?://|www\.)\S+\.(com|ru|net|io|me|cc|org)\S*",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Цветовые диапазоны казино (используются ТОЛЬКО для буста, не для блокировки)
# ---------------------------------------------------------------------------
CASINO_DARK_BLUE = {
    "hue_min": 200, "hue_max": 270,
    "sat_min": 40,
    "val_max": 120,
}

CASINO_GREEN = {
    "hue_min": 90, "hue_max": 150,
    "sat_min": 50,
    "val_min": 130,
}


class ImageDetector:
    """
    Детектор спам-изображений без нейросетей.
    Цвет НИКОГДА не блокирует сам по себе — только OCR и хеши.
    """

    def __init__(self) -> None:
        self._load_known_hashes()
        logger.info(
            "ImageDetector v2 запущен (OCR=✓, Цвет=буст, Хеши=%d шт)",
            len(self.known_hashes),
        )

    def _load_known_hashes(self) -> None:
        """Загружает известные хеши спам-изображений."""
        self.known_hashes = set()
        hash_path = Path(config.HASH_DB_PATH)
        if hash_path.exists():
            try:
                data = json.loads(hash_path.read_text(encoding="utf-8"))
                self.known_hashes = set(data.get("hashes", []))
                logger.info("Загружено %d спам-хешей", len(self.known_hashes))
            except Exception as e:
                logger.error("Ошибка загрузки хешей: %s", e)

    def _save_hash(self, phash_str: str) -> None:
        """Сохраняет хеш в базу."""
        self.known_hashes.add(phash_str)
        try:
            data = {"hashes": list(self.known_hashes)}
            Path(config.HASH_DB_PATH).write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
        except Exception as e:
            logger.error("Ошибка сохранения хеша: %s", e)

    def reload(self) -> bool:
        self._load_known_hashes()
        return True

    # -----------------------------------------------------------------------
    # Основной метод
    # -----------------------------------------------------------------------

    def predict(self, image_data: bytes) -> tuple:
        """
        Returns: (is_spam, confidence, method_description)
        """
        # --- 1. Хеш (мгновенная проверка) ---
        hash_match = self._check_hash(image_data)
        if hash_match:
            return True, 0.95, "hash (известный спам)"

        # --- 2. OCR ---
        ocr_spam, ocr_conf, ocr_details = self._analyze_ocr(image_data)

        # --- 3. Цвет (только для буста OCR, не блокирует сам) ---
        has_casino_colors = self._has_casino_palette(image_data)

        # --- Решение ---

        # OCR нашёл спам
        if ocr_spam:
            if has_casino_colors:
                # OCR + цвет = бустим уверенность
                boosted = min(ocr_conf * 1.25, 0.98)
                method = f"ocr+color({ocr_details})"
                logger.info("КОМБО: %s → %.0f%%", method, boosted * 100)
                self._auto_save_hash(image_data)
                return True, boosted, method
            else:
                # Только OCR
                logger.info("OCR: %s → %.0f%%", ocr_details, ocr_conf * 100)
                if ocr_conf >= config.CONFIDENCE_THRESHOLD:
                    self._auto_save_hash(image_data)
                return ocr_conf >= config.CONFIDENCE_THRESHOLD, ocr_conf, f"ocr({ocr_details})"

        # Ничего не нашли — НЕ спам
        return False, 0.0, "clean"

    # -----------------------------------------------------------------------
    # Метод 1: Перцептивный хеш
    # -----------------------------------------------------------------------

    def _check_hash(self, image_data: bytes) -> bool:
        try:
            import imagehash
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
            phash = imagehash.phash(image, hash_size=12)
            phash_str = str(phash)

            if phash_str in self.known_hashes:
                logger.info("Хеш-совпадение: %s", phash_str)
                return True

            for known in self.known_hashes:
                try:
                    known_hash = imagehash.hex_to_hash(known)
                    if phash - known_hash <= 8:
                        logger.info("Похожий хеш: %s ≈ %s (dist=%d)",
                                    phash_str, known, phash - known_hash)
                        return True
                except Exception:
                    continue

        except ImportError:
            logger.debug("imagehash не установлен")
        except Exception as e:
            logger.debug("Ошибка хеша: %s", e)
        return False

    # -----------------------------------------------------------------------
    # Метод 2: OCR
    # -----------------------------------------------------------------------

    def _analyze_ocr(self, image_data: bytes) -> tuple:
        """
        Returns: (is_spam, confidence, details)
        """
        try:
            import pytesseract
        except ImportError:
            return False, 0.0, "no_ocr"

        try:
            image = Image.open(io.BytesIO(image_data)).convert("RGB")

            try:
                text = pytesseract.image_to_string(image, lang="rus+eng").lower()
            except Exception:
                text = pytesseract.image_to_string(image, lang="eng").lower()

            if not text or len(text.strip()) < 5:
                return False, 0.0, "no_text"

            # HIGH — одного слова достаточно
            high_found = [kw for kw in SPAM_KEYWORDS_HIGH if kw.lower() in text]
            if high_found:
                confidence = min(0.70 + len(high_found) * 0.07, 0.95)
                details = "HIGH: " + ", ".join(high_found[:3])
                logger.info("OCR HIGH: %s", details)
                return True, confidence, details

            # MEDIUM — нужно 3+ совпадения (было 2, увеличил чтобы убрать фолзы)
            medium_found = [kw for kw in SPAM_KEYWORDS_MEDIUM if kw.lower() in text]
            if len(medium_found) >= 3:
                confidence = min(0.55 + len(medium_found) * 0.08, 0.90)
                details = "MED: " + ", ".join(medium_found[:3])
                logger.info("OCR MEDIUM: %s", details)
                return True, confidence, details

            return False, 0.0, "clean"

        except Exception as e:
            logger.debug("OCR ошибка: %s", e)
            return False, 0.0, "error"

    # -----------------------------------------------------------------------
    # Цветовой анализ (только буст, НЕ блокирует)
    # -----------------------------------------------------------------------

    def _has_casino_palette(self, image_data: bytes) -> bool:
        """
        Проверяет, похожа ли палитра на казино-сайт.
        Возвращает True/False — используется ТОЛЬКО для буста OCR.
        Сам по себе НИКОГДА не блокирует!
        """
        try:
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
            thumb = image.resize((80, 80))
            pixels = list(thumb.getdata())
            total = len(pixels)

            dark_blue = 0
            green = 0

            for r, g, b in pixels:
                h, s, v = colorsys.rgb_to_hsv(r / 255, g / 255, b / 255)
                hue = h * 360
                sat = s * 100
                val = v * 255

                if (CASINO_DARK_BLUE["hue_min"] <= hue <= CASINO_DARK_BLUE["hue_max"]
                        and sat >= CASINO_DARK_BLUE["sat_min"]
                        and val <= CASINO_DARK_BLUE["val_max"]):
                    dark_blue += 1

                if (CASINO_GREEN["hue_min"] <= hue <= CASINO_GREEN["hue_max"]
                        and sat >= CASINO_GREEN["sat_min"]
                        and val >= CASINO_GREEN["val_min"]):
                    green += 1

            db_ratio = dark_blue / total
            gr_ratio = green / total

            # Строгий порог: >40% тёмно-синего + есть зелёный
            return db_ratio >= 0.40 and gr_ratio >= 0.03

        except Exception:
            return False

    # -----------------------------------------------------------------------
    # Авто-сохранение хеша
    # -----------------------------------------------------------------------

    def _auto_save_hash(self, image_data: bytes) -> None:
        try:
            import imagehash
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
            phash = str(imagehash.phash(image, hash_size=12))
            if phash not in self.known_hashes:
                self._save_hash(phash)
                logger.info("Спам-хеш сохранён: %s", phash)
        except Exception:
            pass

