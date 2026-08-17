"""Central server-side authorization policy for the simulator."""
from functools import wraps
from flask import jsonify, session
from app.extensions import db
from app.models import User

VIEW_DASHBOARD = "VIEW_DASHBOARD"
VIEW_EVENTS = "VIEW_EVENTS"
VIEW_INCIDENTS = "VIEW_INCIDENTS"
RUN_SIMULATION = "RUN_SIMULATION"
INVESTIGATE_INCIDENT = "INVESTIGATE_INCIDENT"
BLOCK_IP = "BLOCK_IP"
MANAGE_RULES = "MANAGE_RULES"
MANAGE_WHITELIST = "MANAGE_WHITELIST"
MANAGE_USERS = "MANAGE_USERS"
VIEW_AUDIT = "VIEW_AUDIT"

ROLE_PERMISSIONS = {
    "VIEWER": {VIEW_DASHBOARD, VIEW_EVENTS, VIEW_INCIDENTS},
    "ANALYST": {VIEW_DASHBOARD, VIEW_EVENTS, VIEW_INCIDENTS, RUN_SIMULATION,
                INVESTIGATE_INCIDENT, BLOCK_IP},
    "ADMIN": {VIEW_DASHBOARD, VIEW_EVENTS, VIEW_INCIDENTS, RUN_SIMULATION,
              INVESTIGATE_INCIDENT, BLOCK_IP, MANAGE_RULES, MANAGE_WHITELIST,
              MANAGE_USERS, VIEW_AUDIT},
}


def require_permission(permission):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user_id = session.get("user_id")
            user = db.session.get(User, user_id) if user_id else None
            if not user:
                return jsonify(error="Authentication required"), 401
            if user.status != "ACTIVE":
                session.clear()
                return jsonify(error="Account is disabled"), 403
            if permission not in ROLE_PERMISSIONS.get(user.role, set()):
                return jsonify(error="Insufficient permission"), 403
            return fn(*args, **kwargs)
        return wrapped
    return decorator
