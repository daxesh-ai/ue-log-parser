"""ML Anomaly Detection — IsolationForest-based session outlier detection.

Requires: pip install scikit-learn (optional dependency)

Usage:
  Training: logparser-cli --train-model file1.hdf file2.hdf file3.hdf
  Inference: automatically runs in analyze_session() if model exists

The model compares the current session's 30-feature vector against
the training baseline and flags anomalous metrics.
"""

from __future__ import annotations

import numpy as np

from logparser.core.session import LogSession


def ml_analyze_session(session: LogSession) -> list:
    """Run ML anomaly detection. Returns 0-3 Recommendation entries.

    Returns empty list if:
    - scikit-learn not installed
    - No trained model exists
    - Session has insufficient data
    """
    try:
        from logparser.ml.model_store import load_model
        from logparser.ml.feature_extractor import extract_features, FEATURE_NAMES
        from logparser.analysis.recommendations import Recommendation
    except ImportError:
        return []

    model_data = load_model()
    if model_data is None:
        return []

    model, metadata = model_data

    # Extract features
    features = extract_features(session)
    if np.all(features == 0):
        return []  # Empty session

    # Run anomaly detection
    try:
        score = model.decision_function(features.reshape(1, -1))[0]
    except Exception:
        return []

    threshold = metadata.get("anomaly_threshold", -0.3)
    if score >= threshold:
        return []  # Normal session

    # ── Anomaly detected — identify top deviating features ────────────────
    baseline_mean = np.array(metadata.get("baseline_mean", [0] * 30))
    baseline_std = np.array(metadata.get("baseline_std", [1] * 30))

    # Z-scores: how many standard deviations from training mean
    std_safe = np.where(baseline_std > 0, baseline_std, 1.0)
    z_scores = np.abs((features - baseline_mean) / std_safe)

    # Top 3 most anomalous features
    top_indices = np.argsort(z_scores)[-3:][::-1]
    top_features = []
    for idx in top_indices:
        if z_scores[idx] > 2.0:  # At least 2 sigma deviation
            name = FEATURE_NAMES[idx] if idx < len(FEATURE_NAMES) else f"feature_{idx}"
            val = features[idx]
            mean = baseline_mean[idx]
            std = baseline_std[idx]
            direction = "above" if val > mean else "below"
            top_features.append(
                f"{name}={val:.1f} ({z_scores[idx]:.1f}σ {direction} baseline {mean:.1f}±{std:.1f})"
            )

    if not top_features:
        return []

    # Determine severity from anomaly score
    if score < -0.5:
        severity = "Critical"
    elif score < threshold:
        severity = "Major"
    else:
        severity = "Minor"

    recs = [Recommendation(
        rank=0,
        category="ML",
        issue=f"ML Anomaly Detected (score={score:.3f}, {len(top_features)} features deviate)",
        severity=severity,
        count=len(top_features),
        msg_indices=[session.messages[0].index] if session.messages else [],
        root_cause=(
            f"Machine learning model (IsolationForest) flagged this session as anomalous "
            f"(score={score:.3f}, threshold={threshold}). "
            f"Top deviating features:\n" + "\n".join(f"  • {f}" for f in top_features)
        ),
        recommendation=(
            "1. Review the flagged metrics against normal baseline\n"
            "2. Check if a known event (maintenance, outage) explains the anomaly\n"
            "3. Cross-reference with rule-based recommendations for root cause\n"
            "4. If false positive: add this session to training set and retrain"
        ),
        parameter=", ".join(FEATURE_NAMES[i] for i in top_indices if z_scores[i] > 2.0),
    )]

    return recs


def train_model(sessions: list[LogSession], contamination: float = 0.05) -> dict:
    """Train IsolationForest on a set of sessions.

    Args:
        sessions: List of LogSession objects (typically 5-100 "normal" sessions)
        contamination: Expected proportion of anomalies in training data (0.01-0.1)

    Returns:
        dict with 'model_path' and 'stats' on success

    Raises:
        ImportError if scikit-learn not installed
    """
    from sklearn.ensemble import IsolationForest
    from logparser.ml.feature_extractor import extract_features, FEATURE_NAMES, NUM_FEATURES
    from logparser.ml.model_store import save_model

    # Extract feature matrix
    X = np.zeros((len(sessions), NUM_FEATURES))
    for i, session in enumerate(sessions):
        X[i] = extract_features(session)

    # Remove zero-variance features (constant across all sessions)
    feature_std = np.std(X, axis=0)
    feature_std[feature_std == 0] = 1.0  # Avoid division by zero

    # Train IsolationForest
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)

    # Compute baseline statistics
    baseline_stats = {
        "mean": np.mean(X, axis=0),
        "std": feature_std,
        "n_samples": len(sessions),
    }

    # Save model
    model_path = save_model(model, baseline_stats, FEATURE_NAMES)

    return {
        "model_path": str(model_path),
        "n_sessions": len(sessions),
        "n_features": NUM_FEATURES,
        "feature_names": FEATURE_NAMES,
    }
