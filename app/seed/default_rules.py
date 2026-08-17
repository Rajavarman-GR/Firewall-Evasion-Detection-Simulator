from werkzeug.security import generate_password_hash
from app.extensions import db
from app.models import User, FirewallRule, SystemSetting


def seed():
    if not User.query.filter_by(username="admin").first():
        db.session.add(User(username="admin", password_hash=generate_password_hash("admin123"), role="ADMIN"))
        db.session.add(User(username="analyst", password_hash=generate_password_hash("analyst123"), role="ANALYST"))
        db.session.add(User(username="viewer", password_hash=generate_password_hash("viewer123"), role="VIEWER"))
    default = FirewallRule.query.filter_by(name="Default allow simulated traffic").first()
    legacy = FirewallRule.query.filter_by(name="Log all simulated traffic").first()
    if legacy and not default:
        legacy.name, legacy.description, legacy.action = "Default allow simulated traffic", "Educational default policy: allow traffic when no restrictive rule matches.", "ALLOW"
    elif not default:
        db.session.add(FirewallRule(name="Default allow simulated traffic", description="Educational default policy: allow traffic when no restrictive rule matches.", action="ALLOW", priority=1000))
    defaults = {
        "BRUTE_FORCE_THRESHOLD": ("5", "Failed-login events within 60 seconds before detection."),
        "PORT_SCAN_THRESHOLD": ("10", "Distinct destination ports within 30 seconds before detection."),
        "TEMP_BLOCK_DURATION": ("5", "Temporary simulated block duration in minutes."),
        "PERMANENT_BLOCK_THRESHOLD": ("10", "Violations before a permanent simulated block."),
        "CORRELATION_WINDOW": ("300", "Correlation window in seconds."),
        "SIMULATION_RATE": ("10", "Maximum normal events per automated request."),
    }
    for key, (value, description) in defaults.items():
        if not SystemSetting.query.filter_by(key=key).first():
            db.session.add(SystemSetting(key=key, value=value, description=description))
    db.session.commit()
