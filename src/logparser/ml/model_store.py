"""Model persistence — save/load ML models to ~/.logparser/models/."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MODEL_DIR = Path.home() / ".logparser" / "models"
MODEL_FILE = MODEL_DIR / "anomaly_v1.pkl"
METADATA_FILE = MODEL_DIR / "anomaly_v1_meta.json"


def save_model(model: Any, baseline_stats: dict, feature_names: list[str]) -> Path:
    """Save trained model + metadata."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    import pickle
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)

    metadata = {
        "version": 1,
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "baseline_mean": baseline_stats["mean"].tolist(),
        "baseline_std": baseline_stats["std"].tolist(),
        "anomaly_threshold": -0.3,
        "training_samples": baseline_stats.get("n_samples", 0),
    }
    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f, indent=2)

    return MODEL_FILE


def load_model() -> tuple[Any, dict] | None:
    """Load trained model + metadata. Returns None if not found."""
    if not MODEL_FILE.exists() or not METADATA_FILE.exists():
        return None

    try:
        import pickle
        with open(MODEL_FILE, "rb") as f:
            model = pickle.load(f)
        with open(METADATA_FILE) as f:
            metadata = json.load(f)

        # Version check
        if metadata.get("version", 0) != 1:
            return None

        return model, metadata
    except Exception:
        return None


def delete_model() -> bool:
    """Remove existing model files."""
    deleted = False
    for f in (MODEL_FILE, METADATA_FILE):
        if f.exists():
            f.unlink()
            deleted = True
    return deleted
