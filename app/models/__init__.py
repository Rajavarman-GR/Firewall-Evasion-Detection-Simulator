from datetime import datetime, timezone
from app.extensions import db

def utc_now():
    """UTC timestamp stored consistently for SQLite compatibility."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TimestampMixin:
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)


class User(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="VIEWER")
    status = db.Column(db.String(20), nullable=False, default="ACTIVE")
    last_login = db.Column(db.DateTime)


class Incident(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_number = db.Column(db.String(20), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="OPEN")
    first_seen = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False)
    event_count = db.Column(db.Integer, nullable=False, default=0)
    source_ip = db.Column(db.String(64), nullable=False)
    attack_category = db.Column(db.String(100), nullable=False)
    mitre_techniques = db.Column(db.String(255), default="")
    assigned_to = db.Column(db.String(80))
    events = db.relationship("Event", backref="incident", lazy=True)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
    source_ip = db.Column(db.String(64), nullable=False, index=True)
    destination_ip = db.Column(db.String(64), nullable=False)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(12), nullable=False)
    country = db.Column(db.String(80), nullable=False)
    event_type = db.Column(db.String(40), nullable=False)
    attack_type = db.Column(db.String(80), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    action = db.Column(db.String(40), nullable=False, default="LOG")
    status = db.Column(db.String(30), nullable=False, default="NORMAL")
    scenario_id = db.Column(db.String(50))
    incident_id = db.Column(db.Integer, db.ForeignKey("incident.id"))
    description = db.Column(db.Text, nullable=False)
    metadata_json = db.Column(db.Text, default="{}")


class FirewallRule(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    source_ip = db.Column(db.String(64), default="*")
    destination_ip = db.Column(db.String(64), default="*")
    protocol = db.Column(db.String(12), default="*")
    source_port = db.Column(db.String(20), default="*")
    destination_port = db.Column(db.String(20), default="*")
    action = db.Column(db.String(30), nullable=False)
    priority = db.Column(db.Integer, nullable=False, default=100)
    enabled = db.Column(db.Boolean, nullable=False, default=True)


class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), unique=True, nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    expires_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), nullable=False, default="ACTIVE")
    incident_id = db.Column(db.Integer, db.ForeignKey("incident.id"))
    whitelisted = db.Column(db.Boolean, nullable=False, default=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utc_now, nullable=False)
    user = db.Column(db.String(80), nullable=False, default="system")
    action = db.Column(db.String(60), nullable=False)
    target_type = db.Column(db.String(50), nullable=False)
    target_id = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, default="")


class InvestigationNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incident.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=utc_now, nullable=False)
    content = db.Column(db.Text, nullable=False)
    incident = db.relationship("Incident", backref=db.backref("notes", lazy=True, cascade="all, delete-orphan"))
    user = db.relationship("User")


class SystemSetting(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False, default="")
