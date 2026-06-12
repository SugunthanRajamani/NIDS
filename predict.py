"""
predict.py — Load trained model and run per-request DoS prediction.
No logic changes — kept identical to original, just cleaned up comments.
"""

import os, joblib
import numpy as np
from config import FEATURE_COLUMNS, MODEL_PATH, SCALER_PATH, ATTACK_CONFIDENCE_THRESHOLD


class DoSDetector:
    def __init__(self):
        self.model  = None
        self.scaler = None
        self.ready  = False

    def load(self):
        if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
            print(f"⚠️  Model files not found ({MODEL_PATH}). Run train_model.py first.")
            return
        self.model  = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.ready  = True
        print(f"✅ DoS Detector loaded from {MODEL_PATH}")

    def predict(self, features_dict: dict) -> dict:
        """
        features_dict: keys matching FEATURE_COLUMNS
        Returns: { label, confidence, is_attack }
        """
        if not self.ready:
            return {"label": "Unknown", "confidence": 0.0, "is_attack": False}

        vec = np.array([features_dict.get(col, 0) for col in FEATURE_COLUMNS],
                       dtype=float)
        vec = self.scaler.transform(vec.reshape(1, -1))

        prob      = float(self.model.predict_proba(vec)[0][1])
        is_attack = prob >= ATTACK_CONFIDENCE_THRESHOLD
        label     = "DoS Attack" if is_attack else "Normal"

        return {
            "label":      label,
            "confidence": round(prob, 4),
            "is_attack":  is_attack,
        }
