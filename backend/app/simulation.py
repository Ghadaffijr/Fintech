"""
Simulation.py

"""
import random
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional
from .ml import predict_risk_from_features
import hashlib

RiskPrediction = Dict[str, Any]

# Candidate, more granular labels
RISK_LABELS = [
    "card_present_fraud",
    "card_not_present_fraud",
    "chargeback",
    "identity_theft",
    "account_takeover",
    "money_laundering",
    "high_value_fraud",
    "suspicious_activity",
    "bot_activity",
    "merchant_fraud",
    "payment_gateway_failure",
    "delayed_payment",
    "loan_default",
    "policy_violation",
    "other"
]

# Broad groups for analytics
RISK_GROUPS = {
    "card_present_fraud": "financial_fraud",
    "card_not_present_fraud": "financial_fraud",
    "chargeback": "financial_fraud",
    "identity_theft": "identity_abuse",
    "account_takeover": "identity_abuse",
    "money_laundering": "financial_fraud",
    "high_value_fraud": "financial_fraud",
    "suspicious_activity": "suspicious",
    "bot_activity": "automation_abuse",
    "merchant_fraud": "merchant_risk",
    "payment_gateway_failure": "operational",
    "delayed_payment": "credit_risk",
    "loan_default": "credit_risk",
    "policy_violation": "compliance",
    "other": "other"
}

def _choose_label_from_model_output(res: Any) -> Optional[str]:
    """
    If model returns a ready label or class-probabilities, use that.
    Accepts many possible shapes: string label, dict with 'label', 'predicted', 'classes'/'probs'.
    """
    if res is None:
        return None

    # If the model already returned a label
    if isinstance(res, str):
        return res if res in RISK_LABELS else None

    if isinstance(res, dict):
        # common keys
        for k in ("label", "predicted_label", "predicted"):
            lbl = res.get(k)
            if isinstance(lbl, str) and lbl in RISK_LABELS:
                return lbl

        # If the model returned class probabilities, pick the highest (if matches known labels)
        probs = res.get("probs") or res.get("probabilities") or res.get("class_probs")
        if isinstance(probs, dict):
            # find best known label
            sorted_probs = sorted(probs.items(), key=lambda kv: kv[1], reverse=True)
            for label, _ in sorted_probs:
                if label in RISK_LABELS:
                    return label

        # some models return classes list + scores list
        classes = res.get("classes") or res.get("labels")
        class_scores = res.get("scores") or res.get("probs")
        if isinstance(classes, (list, tuple)) and classes:
            if isinstance(class_scores, (list, tuple)) and len(class_scores) == len(classes):
                # choose argmax
                idx = int(max(range(len(class_scores)), key=lambda i: class_scores[i]))
                lbl = classes[idx]
                if lbl in RISK_LABELS:
                    return lbl
            else:
                # fallback to first known class
                for c in classes:
                    if c in RISK_LABELS:
                        return c

    return None

def _heuristic_label(score: float, features: Dict[str, Any], detail: str, anomaly: float) -> str:
    """
    Heuristic mapping when model does not provide a ready label.
    Tune thresholds to your domain.
    """
    amount = float(features.get("amount", 0.0))
    card_present = bool(features.get("card_present", False))
    merchant = str(features.get("merchant_category", "")).lower()
    ip_risk = float(features.get("ip_risk", 0.0))  # 0..1

    # Check detail text for explicit hints
    detail_l = (detail or "").lower()
    if "chargeback" in detail_l:
        return "chargeback"
    if "account takeover" in detail_l or "takeover" in detail_l:
        return "account_takeover"
    if "money launder" in detail_l or "structuring" in detail_l:
        return "money_laundering"
    if "bot" in detail_l or "automation" in detail_l:
        return "bot_activity"

    # Strong high-amount & high-score => money laundering / high_value_fraud
    if score >= 90 and amount >= 10000:
        return "money_laundering"
    if score >= 80 and amount >= 2000:
        return "high_value_fraud"

    # Score-based but use card_present to separate CNP vs CP fraud
    if score >= 70:
        return "card_present_fraud" if card_present else "card_not_present_fraud"

    # Mid scores: suspicious, possible merchant fraud if merchant category is unusual
    if 50 <= score < 70:
        if "merchant" in merchant or "service" in merchant:
            return "merchant_fraud"
        if ip_risk > 0.7 or anomaly > 0.05:
            return "suspicious_activity"
        return "suspicious_activity"

    # Lower scores may still be chargeback/delayed payments or loan defaults depending on context
    if score >= 40:
        if features.get("is_credit", False) or "loan" in merchant:
            return "loan_default"
        return "delayed_payment"

    # fallback
    return "other"

def _map_to_group(label: str) -> str:
    return RISK_GROUPS.get(label, "other")

def _make_abuse_signature(prediction: Dict[str, Any]) -> str:
    """
    Create an irreversible signature from non-PII combination of features.
    Use user_id (or fingerprint) + normalized risk_type + amount bucket + merchant category.
    Hash with sha256 and return hex.
    """
    # choose stable pieces - ensure None -> empty string
    user = str(prediction.get("user_id") or "")
    risk = str(prediction.get("risk_type") or "").lower()
    # amount bucket - reduces precision to reduce accidental PII matching
    amt = prediction.get("amount") or 0.0
    # bucket e.g., round to nearest 100 or power-of-two bins; tune as needed
    if amt <= 100:
        amt_bucket = "0-100"
    elif amt <= 1000:
        amt_bucket = "101-1000"
    elif amt <= 5000:
        amt_bucket = "1001-5000"
    else:
        amt_bucket = "5001+"
    merchant = str(prediction.get("features", {}).get("merchant_category") or "").lower()
    device = str(prediction.get("features", {}).get("device_id") or "")  # if present

    raw = "|".join([user, risk, amt_bucket, merchant, device])
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return h

# def run_simulation(parameters: Dict[str, Any]) -> Tuple[Dict[str, Any], List[RiskPrediction]]:
def run_simulation(parameters: Dict[str, Any], *, platform_id: int = None, intelligence_on: bool = False) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    tx_count = int(parameters.get("transactions", 1000))
    anomaly = float(parameters.get("anomalyRate", 0.02))

    days = 7
    labels = []
    values = []
    for i in range(days):
        jitter = random.uniform(0.85, 1.25)
        val = int(max(0, tx_count * (0.7 + (i / (days * 2))) * jitter))
        if random.random() < anomaly:
            val = int(val * random.uniform(1.3, 2.0))
        labels.append((datetime.utcnow() - timedelta(days=(days - 1 - i))).strftime("%Y-%m-%d"))
        values.append(val)

    summary = {
        "labels": labels,
        "values": values,
        "total": sum(values),
        "peak": max(values),
        "avg": sum(values) / len(values)
    }

    # pick a slightly larger sample, capped for performance
    sample_count = max(1, min(200, int(tx_count * 0.02)))
    predictions: List[RiskPrediction] = []
    for _ in range(sample_count):
        amount = round(random.uniform(5.0, 50000.0), 2)  # wider range for high-value cases
        # synthetic, richer features for model + heuristics
        features: Dict[str, Any] = {
            "transactions": tx_count,
            "anomalyRate": anomaly,
            "amount": amount,
            "merchant_category": random.choice(["retail", "digital_goods", "travel", "loan", "crypto", "utilities", "food"]),
            "card_present": random.random() < 0.6,
            "ip_risk": round(random.uniform(0.0, 1.0), 2),
            "is_credit": random.random() < 0.15
        }

        # ask model (model may return various shapes)
        res = predict_risk_from_features(features)

        # Normalize score & detail
        score = None
        detail = ""
        if isinstance(res, dict):
            # find a numeric score if present
            for k in ("score", "risk_score", "probability", "risk"):
                if k in res and isinstance(res[k], (int, float)):
                    score = float(res[k])
                    break
            # fallback if model returns a raw float
            if score is None and isinstance(res.get("score"), str):
                try:
                    score = float(res.get("score"))
                except Exception:
                    score = None
            detail = str(res.get("detail", "")) if res.get("detail") is not None else ""
        elif isinstance(res, (int, float)):
            score = float(res)

        # ensure numeric score
        score = float(score) if score is not None else random.uniform(0, 50)

        # label selection: prefer model-provided label if available
        label = _choose_label_from_model_output(res)
        if label is None:
            label = _heuristic_label(score, features, detail, anomaly)

        pred: RiskPrediction = {
            "timestamp": datetime.utcnow().isoformat(),
            "transaction_id": f"tx-{random.randint(100000,999999)}",
            "user_id": f"user-{random.randint(1000,9999)}",
            "amount": amount,
            "features": features,
            "model_raw": res,          # include raw model output for auditing
            "risk_score": round(score, 2),
            "risk_type": label,
            "risk_group": _map_to_group(label),
            "detail": detail
        }
        predictions.append(pred)

    return summary, predictions
