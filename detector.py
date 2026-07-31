# =============================================================================
# detector.py — Детекция спам-изображений по ПРИМЕРАМ (few-shot)
# =============================================================================
# Принцип: администратор добавляет примеры спама через !addspam
# Бот запоминает "отпечаток" каждого примера (хеши + гистограмма + сетка цвета)
# Новые изображения сравниваются со ВСЕМИ примерами
# Если похоже на ЛЮБОЙ пример → спам
#
# Работает без torch/CLIP — только PIL + imagehash (~50 МБ RAM)
# =============================================================================

import io
import json
import logging
import math
from datetime import datetime
from pathlib import Path

from PIL import Image, ImageFilter

import config

logger = logging.getLogger("antispam.detector")

# Путь к базе примеров спама
SPAM_DB_PATH = Path(config.HASH_DB_PATH)


class SpamFingerprint:
    """
    «Отпечаток» изображения — набор признаков для сравнения похожести.

    Признаки:
      1. phash (перцептивный хеш) — общая структура
      2. dhash (разностный хеш) — локальные градиенты
      3. ahash (средний хеш) — яркость
      4. color_hist — гистограмма цвета (48 бинов: 16R + 16G + 16B)
      5. grid_colors — средний цвет в сетке 4x4 (пространственная раскладка)
    """

    def __init__(self, image: Image.Image):
        import imagehash

        img = image.convert("RGB")

        # Хеши (разные алгоритмы ловят разные типы похожести)
        self.phash = str(imagehash.phash(img, hash_size=16))
        self.dhash = str(imagehash.dhash(img, hash_size=16))
        self.ahash = str(imagehash.average_hash(img, hash_size=16))

        # Гистограмма цвета (48 бинов — компактно но информативно)
        self.color_hist = self._compute_histogram(img)

        # Сетка цветов 4×4 (сохраняет пространственную раскладку)
        self.grid_colors = self._compute_grid(img)

    def _compute_histogram(self, img: Image.Image) -> list:
        """Вычисляет нормализованную цветовую гистограмму (48 бинов)."""
        thumb = img.resize((64, 64))
        pixels = list(thumb.getdata())
        total = len(pixels)

        # 16 бинов на каждый канал (R, G, B)
        bins = [0] * 48
        for r, g, b in pixels:
            bins[r * 16 // 256] += 1           # R: бины 0-15
            bins[16 + g * 16 // 256] += 1      # G: бины 16-31
            bins[32 + b * 16 // 256] += 1      # B: бины 32-47

        # Нормализация → сумма = 1.0
        s = sum(bins) or 1
        return [round(b / s, 6) for b in bins]

    def _compute_grid(self, img: Image.Image) -> list:
        """Средний цвет в каждой ячейке сетки 4×4 (16 ячеек)."""
        thumb = img.resize((64, 64))
        pixels = thumb.load()
        grid = []
        cell = 16  # 64 / 4

        for gy in range(4):
            for gx in range(4):
                r_sum = g_sum = b_sum = 0
                count = 0
                for y in range(gy * cell, (gy + 1) * cell):
                    for x in range(gx * cell, (gx + 1) * cell):
                        r, g, b = pixels[x, y]
                        r_sum += r
                        g_sum += g
                        b_sum += b
                        count += 1
                grid.append([
                    round(r_sum / count),
                    round(g_sum / count),
                    round(b_sum / count),
                ])

        return grid

    def to_dict(self) -> dict:
        """Сериализация для JSON."""
        return {
            "phash": self.phash,
            "dhash": self.dhash,
            "ahash": self.ahash,
            "color_hist": self.color_hist,
            "grid_colors": self.grid_colors,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SpamFingerprint":
        """Десериализация из JSON."""
        fp = object.__new__(cls)
        fp.phash = data["phash"]
        fp.dhash = data["dhash"]
        fp.ahash = data["ahash"]
        fp.color_hist = data["color_hist"]
        fp.grid_colors = data["grid_colors"]
        return fp

    def similarity(self, other: "SpamFingerprint") -> float:
        """
        Вычисляет похожесть с другим отпечатком.

        Returns:
            Число от 0.0 (совсем не похоже) до 1.0 (идентично)
        """
        import imagehash

        # --- 1. Хеш-сходство (30% веса) ---
        hash_scores = []
        for attr in ("phash", "dhash", "ahash"):
            try:
                h1 = imagehash.hex_to_hash(getattr(self, attr))
                h2 = imagehash.hex_to_hash(getattr(other, attr))
                max_dist = h1.hash.size  # максимальное расстояние
                dist = h1 - h2
                score = 1.0 - (dist / max_dist)
                hash_scores.append(max(score, 0.0))
            except Exception:
                hash_scores.append(0.0)

        hash_sim = sum(hash_scores) / len(hash_scores) if hash_scores else 0.0

        # --- 2. Гистограмма (40% веса) ---
        hist_sim = self._histogram_similarity(self.color_hist, other.color_hist)

        # --- 3. Сетка цветов (30% веса) ---
        grid_sim = self._grid_similarity(self.grid_colors, other.grid_colors)

        # --- Взвешенный итог ---
        total = hash_sim * 0.30 + hist_sim * 0.40 + grid_sim * 0.30

        return total

    @staticmethod
    def _histogram_similarity(h1: list, h2: list) -> float:
        """
        Histogram intersection — классическая метрика сравнения гистограмм.
        Возвращает 0.0 - 1.0 (1.0 = идентичны).
        """
        if not h1 or not h2 or len(h1) != len(h2):
            return 0.0
        return sum(min(a, b) for a, b in zip(h1, h2))

    @staticmethod
    def _grid_similarity(g1: list, g2: list) -> float:
        """
        Сравнивает сетки цветов — евклидово расстояние, нормализованное.
        """
        if not g1 or not g2 or len(g1) != len(g2):
            return 0.0

        total_dist = 0.0
        for c1, c2 in zip(g1, g2):
            dr = c1[0] - c2[0]
            dg = c1[1] - c2[1]
            db = c1[2] - c2[2]
            total_dist += math.sqrt(dr * dr + dg * dg + db * db)

        # Максимальное расстояние = 16 ячеек × sqrt(255²×3) ≈ 16 × 441 = 7065
        max_dist = len(g1) * 441.67
        return max(1.0 - total_dist / max_dist, 0.0)


class ImageDetector:
    """
    Детектор спам-изображений на основе примеров.

    Администратор добавляет примеры спама через !addspam.
    Бот сравнивает каждое новое изображение со ВСЕМИ примерами.
    Если похоже на ЛЮБОЙ пример → удаляет.
    """

    # Порог похожести — если выше, считается спамом
    SIMILARITY_THRESHOLD = 0.55

    def __init__(self) -> None:
        self.examples: list[dict] = []  # [{fingerprint, filename, added_by, ...}]
        self._load_examples()
        logger.info(
            "ImageDetector v3 (few-shot) | примеров спама: %d | порог: %.0f%%",
            len(self.examples), self.SIMILARITY_THRESHOLD * 100,
        )

    def _load_examples(self) -> None:
        """Загружает базу примеров спама из JSON."""
        self.examples = []
        if not SPAM_DB_PATH.exists():
            return
        try:
            data = json.loads(SPAM_DB_PATH.read_text(encoding="utf-8"))
            for ex in data.get("examples", []):
                ex["fingerprint"] = SpamFingerprint.from_dict(ex["fingerprint"])
                self.examples.append(ex)
            logger.info("Загружено %d примеров спама", len(self.examples))
        except Exception as e:
            logger.error("Ошибка загрузки примеров: %s", e)

    def _save_examples(self) -> None:
        """Сохраняет базу примеров."""
        try:
            data = {"examples": []}
            for ex in self.examples:
                data["examples"].append({
                    "filename": ex.get("filename", ""),
                    "added_by": ex.get("added_by", ""),
                    "added_at": ex.get("added_at", ""),
                    "fingerprint": ex["fingerprint"].to_dict(),
                })
            SPAM_DB_PATH.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as e:
            logger.error("Ошибка сохранения примеров: %s", e)

    def add_example(self, image_data: bytes, filename: str = "", added_by: str = "") -> str:
        """
        Добавляет изображение как пример спама.

        Returns:
            Сообщение о результате.
        """
        try:
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
            fp = SpamFingerprint(image)

            # Проверяем, не добавлен ли уже похожий пример
            for ex in self.examples:
                sim = fp.similarity(ex["fingerprint"])
                if sim >= 0.85:
                    return (
                        f"⚠️ Похожий пример уже есть (сходство {sim:.0%}). "
                        f"Не добавлено."
                    )

            self.examples.append({
                "filename": filename,
                "added_by": added_by,
                "added_at": datetime.utcnow().isoformat(),
                "fingerprint": fp,
            })
            self._save_examples()

            return (
                f"✅ Пример добавлен! Всего в базе: **{len(self.examples)}** примеров.\n"
                f"Бот теперь будет ловить похожие изображения."
            )

        except Exception as e:
            logger.error("Ошибка добавления примера: %s", e)
            return f"❌ Ошибка: {e}"

    def remove_example(self, index: int) -> str:
        """Удаляет пример по номеру (1-based)."""
        idx = index - 1
        if 0 <= idx < len(self.examples):
            removed = self.examples.pop(idx)
            self._save_examples()
            return f"✅ Пример #{index} удалён ({removed.get('filename', '?')})"
        return f"❌ Нет примера #{index}. Всего примеров: {len(self.examples)}"

    def reload(self) -> bool:
        """Перезагрузка базы примеров."""
        self._load_examples()
        return True

    # -----------------------------------------------------------------------
    # Основной метод
    # -----------------------------------------------------------------------

    def predict(self, image_data: bytes) -> tuple:
        """
        Сравнивает изображение со всеми примерами спама.

        Returns:
            (is_spam, confidence, method_description)
        """
        if not self.examples:
            return False, 0.0, "no_examples (добавьте спам через !addspam)"

        try:
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
            fp = SpamFingerprint(image)
        except Exception as e:
            logger.error("Ошибка создания отпечатка: %s", e)
            return False, 0.0, "error"

        # Сравниваем с каждым примером, берём МАКСИМАЛЬНУЮ похожесть
        best_sim = 0.0
        best_example = ""

        for ex in self.examples:
            sim = fp.similarity(ex["fingerprint"])
            if sim > best_sim:
                best_sim = sim
                best_example = ex.get("filename", "пример")

        is_spam = best_sim >= self.SIMILARITY_THRESHOLD
        method = f"similar to '{best_example}' ({best_sim:.0%})"

        if is_spam:
            logger.info("СПАМ: %s | похожесть=%.2f", method, best_sim)
        else:
            logger.debug("Чисто: лучшее совпадение %s (%.2f)", best_example, best_sim)

        return is_spam, best_sim, method

    def predict_detailed(self, image_data: bytes) -> dict:
        """
        Детальный анализ — для команды !testdetect.

        Returns:
            dict с подробностями по каждому примеру.
        """
        result = {
            "examples_count": len(self.examples),
            "matches": [],
            "is_spam": False,
            "best_sim": 0.0,
            "best_example": "",
        }

        if not self.examples:
            return result

        try:
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
            fp = SpamFingerprint(image)
        except Exception:
            return result

        for i, ex in enumerate(self.examples):
            sim = fp.similarity(ex["fingerprint"])
            result["matches"].append({
                "index": i + 1,
                "filename": ex.get("filename", "?"),
                "similarity": sim,
                "is_match": sim >= self.SIMILARITY_THRESHOLD,
            })
            if sim > result["best_sim"]:
                result["best_sim"] = sim
                result["best_example"] = ex.get("filename", "?")

        result["is_spam"] = result["best_sim"] >= self.SIMILARITY_THRESHOLD
        result["matches"].sort(key=lambda m: m["similarity"], reverse=True)

        return result

