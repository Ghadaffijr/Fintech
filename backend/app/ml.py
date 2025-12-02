"""ml.py
"""
import random
from typing import Dict, Any

def predict_risk_from_features(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a dictionary with 'score' (0-100) and a small explainability detail.
    """
    anomaly = float(features.get("anomalyRate", 0.02))
    tx = float(features.get("transactions", 1000))
    amount = float(features.get("amount", 0.0))

    # heuristic score
    base_score = (anomaly * 100.0) * (tx / 1000.0)
    amount_influence = (amount / 1000.0) * random.uniform(0.5, 2.0)
    score = base_score + amount_influence + random.uniform(-5, 5)
    score = max(0.0, min(100.0, score))

    detail = {
        "score": round(score, 2),
        "reason": "High anomaly rate" if anomaly > 0.04 else "Amount/volume pattern",
        "features": {
            "anomalyRate": anomaly,
            "transactions": tx,
            "amount": amount,
            "noise": round(random.random(), 3)
        }
    }
    return {"score": score, "detail": detail}
