"""Persistent examples and image matching for the moderation bot."""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from io import BytesIO
from pathlib import Path

import imagehash
from PIL import Image, ImageOps, UnidentifiedImageError

LOG = logging.getLogger(__name__)
MODEL_NAME = "openai/clip-vit-base-patch32"
SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}


def open_image(raw: bytes) -> Image.Image:
    """Decode a downloaded attachment and bound decompression work."""
    Image.MAX_IMAGE_PIXELS = 25_000_000
    with Image.open(BytesIO(raw)) as source:
        if source.width * source.height > 25_000_000:
            raise ValueError("Image exceeds pixel limit")
        image = ImageOps.exif_transpose(source)
        image.load()
        return image.convert("RGB")


class ScamLearning:
    def __init__(self, data_dir: Path, enable_ai: bool, hash_threshold: int,
                 similarity_threshold: float):
        self.data_dir = Path(data_dir)
        self.examples_dir = self.data_dir / "examples"
        self.db_path = self.data_dir / "scam_db.json"
        self.enable_ai = enable_ai
        self.hash_threshold = hash_threshold
        self.similarity_threshold = similarity_threshold
        self._lock = threading.RLock()
        self._model = None
        self._processor = None
        self._examples: list[dict] = []
        self.examples_dir.mkdir(parents=True, exist_ok=True)
        self._load()

    def _load(self) -> None:
        if not self.db_path.exists():
            return
        try:
            payload = json.loads(self.db_path.read_text(encoding="utf-8"))
            if not isinstance(payload, list):
                raise ValueError("Database must contain a list")
            self._examples = [row for row in payload if isinstance(row, dict)
                              and {"id", "hash", "source", "file"} <= row.keys()]
        except (OSError, ValueError, json.JSONDecodeError):
            LOG.exception("Cannot load %s; starting with no examples", self.db_path)

    def _save(self) -> None:
        temporary = self.db_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._examples, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, self.db_path)

    def _embedding(self, image: Image.Image) -> list[float]:
        if self._model is None:
            from transformers import CLIPModel, CLIPProcessor
            self._processor = CLIPProcessor.from_pretrained(MODEL_NAME)
            self._model = CLIPModel.from_pretrained(MODEL_NAME).eval()
        import torch
        inputs = self._processor(images=image, return_tensors="pt")
        with torch.inference_mode():
            features = self._model.get_image_features(**inputs)
        if not isinstance(features, torch.Tensor):
            features = features.pooler_output
        features = features / features.norm(dim=-1, keepdim=True)
        return features[0].cpu().tolist()

    def learn(self, raw: bytes, source: str, source_key: str | None = None) -> tuple[str, bool]:
        image = open_image(raw)
        fingerprint = str(imagehash.phash(image))
        with self._lock:
            if source_key:
                existing = next((row for row in self._examples if row.get("source_key") == source_key), None)
                if existing:
                    return existing["id"], False
            # The feature vector is saved so later boots do not have to encode every example.
            embedding = None
            if self.enable_ai:
                try:
                    embedding = self._embedding(image)
                except Exception:
                    LOG.exception("CLIP unavailable; saving example for hash matching")
            identifier = uuid.uuid4().hex[:12]
            filename = f"{identifier}.png"
            image.save(self.examples_dir / filename, format="PNG")
            row = {"id": identifier, "hash": fingerprint, "source": source[:200],
                   "source_key": source_key, "file": filename, "embedding": embedding}
            self._examples.append(row)
            self._save()
            return identifier, True

    def match(self, raw: bytes) -> str | None:
        image = open_image(raw)
        fingerprint = imagehash.phash(image)
        with self._lock:
            examples = list(self._examples)
            for row in examples:
                try:
                    if fingerprint - imagehash.hex_to_hash(row["hash"]) <= self.hash_threshold:
                        return f"image matches example {row['id']} (hash)"
                except (ValueError, TypeError):
                    LOG.warning("Invalid hash in example %s", row.get("id"))
            if not self.enable_ai or not examples:
                return None
            try:
                candidate = self._embedding(image)
            except Exception:
                LOG.exception("CLIP unavailable; continuing with hash matching only")
                return None
            for row in examples:
                reference = row.get("embedding")
                if reference is None:
                    try:
                        with Image.open(self.examples_dir / row["file"]) as saved:
                            reference = self._embedding(saved.convert("RGB"))
                        row["embedding"] = reference
                        self._save()
                    except Exception:
                        LOG.warning("Cannot read saved image for %s", row.get("id"))
                        continue
                if len(candidate) == len(reference):
                    similarity = sum(a * b for a, b in zip(candidate, reference))
                    if similarity >= self.similarity_threshold:
                        return f"image matches example {row['id']} (CLIP: {similarity:.3f})"
        return None

    def list_recent(self, count: int = 20) -> list[dict]:
        with self._lock:
            return [dict(row) for row in self._examples[-count:]][::-1]

    def unlearn(self, identifier: str) -> bool:
        with self._lock:
            row = next((row for row in self._examples if row["id"] == identifier), None)
            if row is None:
                return False
            self._examples.remove(row)
            self._save()
            # Stored names are generated by this application, not accepted from commands.
            filename = row.get("file", "")
            if filename == f"{identifier}.png":
                (self.examples_dir / filename).unlink(missing_ok=True)
            return True

    def learn_folder(self, folder: Path) -> tuple[int, int]:
        folder = Path(folder)
        folder.mkdir(parents=True, exist_ok=True)
        added = failed = 0
        for path in sorted(folder.iterdir()):
            if not path.is_file() or path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            try:
                _, created = self.learn(path.read_bytes(), f"folder: {path.name}",
                                        f"folder:{path.resolve()}")
                added += int(created)
            except Exception:
                failed += 1
                LOG.exception("Cannot learn %s", path)
        return added, failed
