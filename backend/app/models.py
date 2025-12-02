"""
models.py
"""
from .db import db
from datetime import datetime

class Scenario(db.Model):
    __tablename__ = "scenarios"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    parameters = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "created_at": self.created_at.isoformat(),
        }



class Prediction(db.Model):
    __tablename__ = "predictions"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_id = db.Column(db.String(120), nullable=True)
    user_id = db.Column(db.String(120), nullable=True)
    amount = db.Column(db.Float, nullable=True)
    risk_type = db.Column(db.String(50), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)  # 0-100
    reviewed = db.Column(db.Boolean, default=False)
    detail = db.Column(db.JSON, nullable=True)

    # NEW: relation to simulation and platform
    simulation_id = db.Column(db.Integer, db.ForeignKey("simulations.id"), nullable=True)
    platform_id = db.Column(db.Integer, db.ForeignKey("platforms.id"), nullable=True)

    def to_dict(self, include_detail=False):
        d = {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat(),
            "transaction_id": self.transaction_id,
            "user_id": self.user_id,
            "amount": self.amount,
            "risk_type": self.risk_type,
            "risk_score": round(self.risk_score, 2),
            "reviewed": self.reviewed,
            "simulation_id": str(self.simulation_id) if self.simulation_id else None,
            "platform_id": str(self.platform_id) if self.platform_id else None,
        }
        if include_detail:
            d["detail"] = self.detail or {}
        return d





class Platform(db.Model):
    __tablename__ = "platforms"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {"id": str(self.id), "name": self.name, "created_at": self.created_at.isoformat()}

class AbuseSignature(db.Model):
    __tablename__ = "abuse_signatures"
    id = db.Column(db.Integer, primary_key=True)
    signature = db.Column(db.String(128), nullable=False, unique=True, index=True)  # store sha256 hex
    platform_id = db.Column(db.Integer, db.ForeignKey("platforms.id"), nullable=True)
    simulation_id = db.Column(db.Integer, db.ForeignKey("simulations.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": str(self.id),
            "signature": self.signature,
            "platform_id": self.platform_id,
            "simulation_id": self.simulation_id,
            "created_at": self.created_at.isoformat()
        }

class Simulation(db.Model):
    __tablename__ = "simulations"
    id = db.Column(db.Integer, primary_key=True)
    platform_id = db.Column(db.Integer, db.ForeignKey("platforms.id"), nullable=True)   # new
    intelligence_on = db.Column(db.Boolean, default=False)                               # new
    parameters = db.Column(db.JSON, nullable=True)
    result = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": str(self.id),
            "platform_id": str(self.platform_id) if self.platform_id else None,
            "intelligence_on": bool(self.intelligence_on),
            "parameters": self.parameters or {},
            "result": self.result or {},
            "created_at": self.created_at.isoformat(),
        }