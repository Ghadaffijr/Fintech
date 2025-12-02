"""
routes.py
"""
from flask import Blueprint, request, jsonify, send_file, current_app
from .db import db
from .simulation import run_simulation, _make_abuse_signature
from datetime import datetime
import json, io, csv, traceback

import hashlib
from .models import Scenario, Simulation, Prediction, AbuseSignature, Platform
from sqlalchemy import func


bp = Blueprint("api", __name__)

@bp.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat()})

@bp.route("/dashboard", methods=["GET"])
def dashboard():
    try:
        # KPIs
        fraud_count = Prediction.query.filter_by(risk_type="fraud").count()
        loan_count = Prediction.query.filter_by(risk_type="loan_default").count()
        total_preds = Prediction.query.count()
        loan_pct = round(100.0 * (loan_count / total_preds), 2) if total_preds else 0.0

        # transactions timeseries from last N simulations (most recent)
        sims = Simulation.query.order_by(Simulation.created_at.desc()).limit(7).all()
        labels = []
        values = []
        for s in reversed(sims):
            res = s.result or {}
            lbl = res.get("labels", ["-"])[-1] if isinstance(res.get("labels"), list) else "-"
            val = int(res.get("values", [0])[-1]) if res.get("values") else 0
            labels.append(lbl)
            values.append(val)

        kpis = {
            "transactions": sum(values) if values else 0,
            "fraudAlerts": fraud_count,
            "loanDefaultPct": loan_pct
        }
        transactions = {"labels": labels, "data": values}
        risks = {"labels": ["fraud", "loan_default", "other"],
                 "data": [
                     Prediction.query.filter_by(risk_type="fraud").count(),
                     Prediction.query.filter_by(risk_type="loan_default").count(),
                     Prediction.query.filter_by(risk_type="other").count()
                 ]}

        sims_list = [s.to_dict() for s in Simulation.query.order_by(Simulation.created_at.desc()).limit(20).all()]
        return jsonify({"kpis": kpis, "transactions": transactions, "risks": risks, "simulations": sims_list})
    except Exception:
        current_app.logger.error("Dashboard error:\n" + traceback.format_exc())
        return jsonify({"error": "internal"}), 500

@bp.route("/compare", methods=["GET"])
def compare():
    try:
        # optional query params
        platform_id = request.args.get("platform_id", type=int)
        normalize = request.args.get("normalize", "false").lower() in ("1", "true", "yes")

        def metrics_for(flag: bool):
            # base simulation query for this flag (may be filtered by platform)
            sims_q = Simulation.query.filter_by(intelligence_on=flag)
            if platform_id:
                sims_q = sims_q.filter_by(platform_id=platform_id)

            num_simulations = sims_q.count()

            # join Prediction -> Simulation, filter by intelligence flag and platform if provided
            pred_filter = db.session.query(func.count(Prediction.id)).join(
                Simulation, Prediction.simulation_id == Simulation.id
            ).filter(Simulation.intelligence_on == flag)

            if platform_id:
                pred_filter = pred_filter.filter(Simulation.platform_id == platform_id)

            num_predictions = int(pred_filter.scalar() or 0)

            avg_score_q = db.session.query(func.avg(Prediction.risk_score)).join(
                Simulation, Prediction.simulation_id == Simulation.id
            ).filter(Simulation.intelligence_on == flag)

            if platform_id:
                avg_score_q = avg_score_q.filter(Simulation.platform_id == platform_id)

            avg_score = float(avg_score_q.scalar() or 0.0)

            fraud_count_q = db.session.query(func.count(Prediction.id)).join(
                Simulation, Prediction.simulation_id == Simulation.id
            ).filter(Simulation.intelligence_on == flag, Prediction.risk_type.ilike('%fraud%'))

            if platform_id:
                fraud_count_q = fraud_count_q.filter(Simulation.platform_id == platform_id)

            fraud_count = int(fraud_count_q.scalar() or 0)

            preds_per_sim = None
            if normalize and num_simulations:
                preds_per_sim = num_predictions / num_simulations

            return {
                "intelligence_on": bool(flag),
                "num_simulations": int(num_simulations),
                "num_predictions": int(num_predictions),
                "avg_risk_score": float(avg_score),
                "fraud_count": int(fraud_count),
                "predictions_per_simulation": float(preds_per_sim) if preds_per_sim is not None else None
            }

        on_metrics = metrics_for(True)
        off_metrics = metrics_for(False)

        # Build aggregated time-series by summing simulation.result.values for each label
        def aggregate_timeseries(flag: bool):
            sims_q = Simulation.query.filter_by(intelligence_on=flag)
            if platform_id:
                sims_q = sims_q.filter_by(platform_id=platform_id)
            sims_list = sims_q.all()

            label_set = set()
            for s in sims_list:
                lbls = (s.result or {}).get("labels") or []
                label_set.update(lbls)
            labels = sorted(list(label_set))

            label_map = {l: 0.0 for l in labels}
            for s in sims_list:
                lbls = (s.result or {}).get("labels") or []
                vals = (s.result or {}).get("values") or []
                for i, l in enumerate(lbls):
                    try:
                        v = float(vals[i])
                    except Exception:
                        v = 0.0
                    label_map[l] = label_map.get(l, 0.0) + v

            series = [label_map[l] for l in labels] if labels else []
            return {"labels": labels, "series": series}

        trend_on = aggregate_timeseries(True)
        trend_off = aggregate_timeseries(False)

        response = {
            "compare": [on_metrics, off_metrics],
            "trend": {"on": trend_on, "off": trend_off},
        }

        # per-platform breakdown when no platform filter is provided
        if not platform_id:
            platforms = Platform.query.order_by(Platform.name).all()
            per_platform = []
            for p in platforms:
                sims_count = Simulation.query.filter_by(platform_id=p.id).count()
                num_predictions = db.session.query(func.count(Prediction.id)).join(
                    Simulation, Prediction.simulation_id == Simulation.id
                ).filter(Simulation.platform_id == p.id).scalar() or 0
                avg_score = db.session.query(func.avg(Prediction.risk_score)).join(
                    Simulation, Prediction.simulation_id == Simulation.id
                ).filter(Simulation.platform_id == p.id).scalar() or 0.0
                per_platform.append({
                    "platform_id": p.id,
                    "platform_name": p.name,
                    "num_simulations": int(sims_count),
                    "num_predictions": int(num_predictions),
                    "avg_risk_score": float(avg_score) if avg_score else 0.0
                })
            response["per_platform"] = per_platform

        return jsonify(response)
    except Exception:
        current_app.logger.error("Compare error:\n" + traceback.format_exc())
        return jsonify({"error": "internal"}), 500

# --- Platforms endpoints -------------------------------------------------
@bp.route("/platforms", methods=["GET", "POST"])
def platforms():
    """
    GET -> list all platforms
    POST -> create a platform { "name": "platform-a" }
    """
    if request.method == "GET":
        try:
            plats = Platform.query.order_by(Platform.name).all()
            return jsonify([p.to_dict() for p in plats])
        except Exception:
            current_app.logger.error("Platforms GET error:\n" + traceback.format_exc())
            return jsonify({"error": "internal"}), 500

    # POST
    try:
        body = request.get_json() or {}
        name = (body.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400

        # try to reuse existing platform (name unique)
        existing = Platform.query.filter_by(name=name).first()
        if existing:
            return jsonify(existing.to_dict()), 200

        p = Platform(name=name)
        db.session.add(p)
        db.session.commit()
        return jsonify(p.to_dict()), 201
    except Exception:
        current_app.logger.error("Platforms POST error:\n" + traceback.format_exc())
        db.session.rollback()
        return jsonify({"error": "internal"}), 500

@bp.route("/platforms/<int:platform_id>", methods=["DELETE"])
def delete_platform(platform_id):
    try:
        p = Platform.query.get(platform_id)
        if not p:
            return jsonify({"error": "not found"}), 404
        db.session.delete(p)
        db.session.commit()
        return jsonify({"ok": True})
    except Exception:
        current_app.logger.error("Platforms DELETE error:\n" + traceback.format_exc())
        db.session.rollback()
        return jsonify({"error": "internal"}), 500
# ------------------------------------------------------------------------


def _resolve_platform_id(raw) -> int | None:
    """
    Accepts raw platform identifier from client and returns integer platform.id or None.
    - If raw is int or numeric string -> cast to int and verify exists.
    - If raw is non-numeric string -> try lookup by name, then create a Platform with that name.
    """
    if raw is None or raw == '':
        return None

    # Try direct integer
    try:
        pid = int(raw)
        p = Platform.query.get(pid)
        if p:
            return p.id
        # If numeric but not found, return None (or create? here we return None)
        return None
    except (ValueError, TypeError):
        # not an int -> try to lookup by name
        text = str(raw).strip()
        p = Platform.query.filter_by(name=text).first()
        if p:
            return p.id
        # Option: create a new Platform row for this slug/name so we always have a numeric id
        try:
            p_new = Platform(name=text)
            db.session.add(p_new)
            db.session.commit()
            return p_new.id
        except Exception:
            # If create fails, rollback and return None
            db.session.rollback()
            current_app.logger.exception("Could not create Platform for name=%s", text)
            return None
@bp.route("/run_simulation", methods=["POST"])
def run_simulation_route():
    try:
        body = request.get_json() or {}
        params = body.get("parameters") or {}
        scenario_id = body.get("scenarioId")

        raw_platform = body.get("platformId")
        platform_id = _resolve_platform_id(raw_platform)

        intelligence_on = bool(body.get("intelligenceOn", False))

        # if scenarioId given, load scenario parameters
        if scenario_id:
            sc = Scenario.query.get(int(scenario_id))
            if sc:
                params = sc.parameters

        summary, predictions = run_simulation(params)

        sim = Simulation(platform_id=platform_id, intelligence_on=intelligence_on, parameters=params, result=summary)
        db.session.add(sim)
        db.session.commit()

        created = []
        suppressed_count = 0
        signatures_inserted = 0
        abuse_objs = []
        pred_objs = []

        DUPLICATE_CHECK_LABELS = {
            "card_present_fraud",
            "card_not_present_fraud",
            "money_laundering",
            "high_value_fraud",
            "merchant_fraud"
        }

        # **Load existing risk types from DB for intelligence ON platforms**
        existing_risks = set()
        if intelligence_on:
            query = db.session.query(Prediction.risk_type)\
                .join(Simulation, Prediction.simulation_id == Simulation.id)\
                .filter(Simulation.intelligence_on == True)
            existing_risks = {r[0] for r in query.all() if r[0]}

        for p in predictions:
            sig = _make_abuse_signature(p)
            label = p.get("risk_type")

            # Skip duplicate risk_type for intelligence ON for high-priority labels
            if intelligence_on and label in DUPLICATE_CHECK_LABELS:
                if label in existing_risks:
                    suppressed_count += 1
                    continue
                existing_risks.add(label)  # mark as used within this run

            # Check signature for all predictions
            if intelligence_on:
                existing_sig = AbuseSignature.query.filter_by(signature=sig).first()
                if existing_sig:
                    suppressed_count += 1
                    continue
                abuse_objs.append(AbuseSignature(signature=sig, platform_id=platform_id, simulation_id=sim.id))
                signatures_inserted += 1

            pred = Prediction(
                timestamp=datetime.utcnow(),
                transaction_id=p.get("transaction_id"),
                user_id=p.get("user_id"),
                amount=p.get("amount"),
                risk_type=label,
                risk_score=p.get("risk_score"),
                reviewed=False,
                detail=p.get("detail"),
                simulation_id=sim.id,
                platform_id=platform_id
            )
            pred_objs.append(pred)

        # Bulk insert
        try:
            if abuse_objs:
                db.session.add_all(abuse_objs)
            if pred_objs:
                db.session.add_all(pred_objs)
            db.session.commit()
        except Exception:
            current_app.logger.exception("Could not persist predictions/abuses")
            db.session.rollback()
            return jsonify({"error": "could not persist predictions"}), 500

        created = [p.to_dict() for p in pred_objs]

        sim.result = {**summary, "created_predictions_count": len(created), "suppressed": suppressed_count}
        db.session.commit()

        return jsonify({
            "id": sim.id,
            "summary": summary,
            "created_predictions": created,
            "suppressed_count": suppressed_count,
            "signatures_inserted": signatures_inserted
        }), 201

    except Exception:
        current_app.logger.error("Run simulation error:\n" + traceback.format_exc())
        db.session.rollback()
        return jsonify({"error": "internal"}), 500


@bp.route("/scenarios", methods=["GET", "POST"])
def scenarios():
    if request.method == "GET":
        scs = Scenario.query.order_by(Scenario.created_at.desc()).all()
        return jsonify([s.to_dict() for s in scs])

    # POST -> create scenario
    try:
        body = request.get_json() or {}
        name = body.get("name")
        description = body.get("description", "")
        parameters = body.get("parameters", {})

        if not name:
            return jsonify({"error": "name required"}), 400

        sc = Scenario(name=name, description=description, parameters=parameters)
        db.session.add(sc)
        db.session.commit()
        return jsonify(sc.to_dict()), 201
    except Exception:
        current_app.logger.error("Create scenario error:\n" + traceback.format_exc())
        return jsonify({"error": "internal"}), 500

@bp.route("/scenarios/<int:sc_id>", methods=["DELETE"])
def delete_scenario(sc_id):
    try:
        sc = Scenario.query.get(sc_id)
        if not sc:
            return jsonify({"error": "not found"}), 404
        db.session.delete(sc)
        db.session.commit()
        return jsonify({"ok": True})
    except Exception:
        current_app.logger.error("Delete scenario error:\n" + traceback.format_exc())
        return jsonify({"error": "internal"}), 500

@bp.route("/predictions", methods=["GET"])
def get_predictions():
    try:
        limit = min(1000, int(request.args.get("limit", 500)))
        preds = Prediction.query.order_by(Prediction.timestamp.desc()).limit(limit).all()
        return jsonify([p.to_dict() for p in preds])
    except Exception:
        current_app.logger.error("Get predictions error:\n" + traceback.format_exc())
        return jsonify({"error": "internal"}), 500

@bp.route("/predictions/<int:pred_id>", methods=["GET"])
def get_prediction(pred_id):
    try:
        p = Prediction.query.get(pred_id)
        if not p:
            return jsonify({"error": "not found"}), 404
        return jsonify(p.to_dict(include_detail=True))
    except Exception:
        current_app.logger.error("Get prediction error:\n" + traceback.format_exc())
        return jsonify({"error": "internal"}), 500

@bp.route("/predictions/<int:pred_id>/review", methods=["POST"])
def review_prediction(pred_id):
    try:
        p = Prediction.query.get(pred_id)
        if not p:
            return jsonify({"error": "not found"}), 404
        p.reviewed = True
        db.session.commit()
        return jsonify({"ok": True})
    except Exception:
        current_app.logger.error("Review error:\n" + traceback.format_exc())
        return jsonify({"error": "internal"}), 500

@bp.route("/predictions/export", methods=["POST"])
def export_predictions():
    try:
        preds = Prediction.query.order_by(Prediction.timestamp.desc()).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "timestamp", "transaction_id", "user_id", "amount", "risk_type", "risk_score", "reviewed"])
        for p in preds:
            writer.writerow([p.id, p.timestamp.isoformat(), p.transaction_id, p.user_id, p.amount, p.risk_type, p.risk_score, p.reviewed])
        output.seek(0)
        mem = io.BytesIO()
        mem.write(output.getvalue().encode("utf-8"))
        mem.seek(0)
        filename = f"predictions_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.csv"
        return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=filename)
    except Exception:
        current_app.logger.error("Export error:\n" + traceback.format_exc())
        return jsonify({"error": "internal"}), 500

@bp.route("/contact", methods=["POST"])
def contact():
    try:
        body = request.get_json() or {}
        name = body.get("name")
        email = body.get("email")
        message = body.get("message")
        # In production, persist or send email; for now just log
        current_app.logger.info(f"[CONTACT] {name} <{email}>: {message}")
        return jsonify({"ok": True})
    except Exception:
        current_app.logger.error("Contact error:\n" + traceback.format_exc())
        return jsonify({"error": "internal"}), 500
