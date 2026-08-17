"""Simulation-only SOC services. No network or host firewall interaction occurs."""
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import random
from flask import current_app
from app.extensions import db
from app.models import Event, Incident, BlockedIP, FirewallRule, AuditLog, SystemSetting

MITRE = {"Brute Force": "T1110", "Port Scan": "T1046", "Web Attack": "T1190", "DDoS": "T1498", "Multi-Stage Attack": "T1046, T1110, T1190"}
BASE_RISK = {"NORMAL": 5, "LOW": 25, "MEDIUM": 45, "HIGH": 70, "CRITICAL": 90}

def utc_now(): return datetime.now(timezone.utc).replace(tzinfo=None)


def setting_int(key, fallback):
    item = SystemSetting.query.filter_by(key=key).first()
    return int(item.value) if item else fallback


def audit(action, target_type, target_id, details="", user="system"):
    db.session.add(AuditLog(user=user, action=action, target_type=target_type, target_id=str(target_id), details=details))


def severity_for(score):
    return "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"


def is_active_block(ip):
    block = BlockedIP.query.filter_by(ip=ip, status="ACTIVE", whitelisted=False).first()
    if block and block.expires_at and block.expires_at <= utc_now():
        block.status = "EXPIRED"
        db.session.commit()
        return False
    return bool(block)


def block_ip(ip, reason, severity="HIGH", duration_minutes=5, permanent=False, incident_id=None):
    existing = BlockedIP.query.filter_by(ip=ip).first()
    if existing and existing.whitelisted:
        return None, "IP is whitelisted"
    expires = None if permanent else utc_now() + timedelta(minutes=duration_minutes)
    block = existing or BlockedIP(ip=ip, reason=reason, severity=severity)
    block.reason, block.severity, block.expires_at, block.status, block.incident_id = reason, severity, expires, "ACTIVE", incident_id
    db.session.add(block)
    audit("BLOCK_IP", "blocked_ip", ip, reason)
    return block, None


def set_whitelist(ip, enabled=True, reason="Administrator whitelist"):
    """Persist a simulation whitelist entry; it always overrides block attempts."""
    item = BlockedIP.query.filter_by(ip=ip).first() or BlockedIP(
        ip=ip, reason=reason, severity="LOW"
    )
    item.whitelisted, item.status, item.reason = enabled, "WHITELISTED" if enabled else "INACTIVE", reason
    db.session.add(item)
    audit("WHITELIST_IP" if enabled else "REMOVE_WHITELIST", "blocked_ip", ip, reason)
    return item


def rule_conflicts(rule):
    """Return educational warnings for overlapping rules with different actions."""
    warnings = []
    for other in FirewallRule.query.filter(FirewallRule.id != rule.id).all():
        source_overlap = _patterns_overlap(rule.source_ip, other.source_ip)
        destination_overlap = _patterns_overlap(rule.destination_ip, other.destination_ip)
        protocol_overlap = "*" in (rule.protocol, other.protocol) or rule.protocol == other.protocol
        if source_overlap and destination_overlap and protocol_overlap and rule.action != other.action:
            warnings.append(f"'{other.name}' (priority {other.priority}) overlaps this rule with action {other.action}.")
    return warnings


def _patterns_overlap(left, right):
    if left in (None, "", "*") or right in (None, "", "*"):
        return True
    try:
        a, b = ipaddress.ip_network(left, strict=False), ipaddress.ip_network(right, strict=False)
        return a.overlaps(b)
    except ValueError:
        return left == right


def firewall_decision(event):
    if is_active_block(event.source_ip):
        return "DROP", "Active simulated block"
    for rule in FirewallRule.query.filter_by(enabled=True).order_by(FirewallRule.priority.asc(), FirewallRule.id.asc()):
        if _rule_matches(rule, event):
            if rule.action in {"BLOCK_TEMPORARY", "BLOCK_PERMANENT"}:
                block_ip(event.source_ip, "Rule: " + rule.name, event.severity, permanent=rule.action == "BLOCK_PERMANENT")
            return rule.action, "Rule: " + rule.name
    return "ALLOW", "Default allow policy: no enabled rule matched"


def _ip_matches(pattern, address):
    if pattern in (None, "", "*"): return True
    try: return ipaddress.ip_address(address) in ipaddress.ip_network(pattern, strict=False)
    except ValueError: return pattern == address


def _rule_matches(rule, event):
    return (_ip_matches(rule.source_ip, event.source_ip) and _ip_matches(rule.destination_ip, event.destination_ip)
            and rule.protocol in ("*", event.protocol) and rule.destination_port in ("*", str(event.destination_port)))


def risk_for(event):
    if event.status == "NORMAL":
        return 5, {"base": 5, "recent_events": 0, "unique_ports": 0, "baseline": True}
    recent = Event.query.filter(Event.source_ip == event.source_ip, Event.timestamp >= utc_now()-timedelta(seconds=60)).count()
    ports = {x.destination_port for x in Event.query.filter(Event.source_ip == event.source_ip, Event.timestamp >= utc_now()-timedelta(seconds=30)).all()}
    score = BASE_RISK.get(event.severity, 20) + min(recent * 3, 15) + (10 if len(ports) > 5 else 0)
    if is_active_block(event.source_ip): score += 5
    return min(score, 100), {"base": BASE_RISK.get(event.severity, 20), "recent_events": recent, "unique_ports": len(ports)}


def detect(event):
    now = utc_now()
    failed = Event.query.filter_by(source_ip=event.source_ip, attack_type="Brute Force").filter(Event.timestamp >= now-timedelta(seconds=60)).count()
    ports = {e.destination_port for e in Event.query.filter_by(source_ip=event.source_ip, attack_type="Port Scan").filter(Event.timestamp >= now-timedelta(seconds=30)).all()}
    web = Event.query.filter_by(source_ip=event.source_ip, attack_type="Web Attack").filter(Event.timestamp >= now-timedelta(seconds=90)).count()
    if failed > setting_int("BRUTE_FORCE_THRESHOLD", 5): return ("BRUTE_FORCE_001", "HIGH", "Temporary Block", f"{failed} failed login events from {event.source_ip} within 60 seconds.")
    if len(ports) > setting_int("PORT_SCAN_THRESHOLD", 10): return ("PORT_SCAN_001", "HIGH", "Temporary Block", f"{len(ports)} destination ports contacted by {event.source_ip} within 30 seconds.")
    if web >= 3: return ("WEB_ATTACK_001", "CRITICAL", "Create Incident", f"{web} suspicious web events from {event.source_ip} within 90 seconds.")
    return None


def correlate_and_incident(event, detection_result):
    since = utc_now() - timedelta(seconds=setting_int("CORRELATION_WINDOW", 300))
    related = Event.query.filter_by(source_ip=event.source_ip).filter(Event.timestamp >= since).all()
    types = {e.attack_type for e in related if e.status != "NORMAL"}
    should_create = detection_result or len(types) >= 3 or event.attack_type == "Multi-Stage Attack"
    if not should_create: return None
    existing = Incident.query.filter_by(source_ip=event.source_ip).filter(Incident.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"])).first()
    severity = "CRITICAL" if len(types) >= 3 or event.severity == "CRITICAL" else (detection_result[1] if detection_result else event.severity)
    if not existing:
        number = f"INC-{(Incident.query.count()+1):04d}"
        existing = Incident(incident_number=number, title="Possible Multi-Stage Attack" if len(types)>=3 else event.attack_type,
            description=(detection_result[3] if detection_result else "Related simulated events correlated by source and time."), severity=severity, risk_score=event.risk_score,
            status="OPEN", first_seen=event.timestamp, last_seen=event.timestamp, event_count=0, source_ip=event.source_ip,
            attack_category=event.attack_type, mitre_techniques=MITRE.get(event.attack_type, ""))
        db.session.add(existing); db.session.flush(); audit("CREATE_INCIDENT", "incident", existing.id, existing.title)
    existing.last_seen, existing.event_count = event.timestamp, len(related)
    for item in related:
        item.incident_id = existing.id
    return existing


def create_event(data):
    event = Event(timestamp=utc_now(), source_ip=data.get("source_ip", "192.168.1.100"), destination_ip=data.get("destination_ip", "10.0.0.10"),
        source_port=data.get("source_port", random.randint(1024, 65535)), destination_port=int(data.get("destination_port", 443)), protocol=data.get("protocol", "TCP"),
        country=data.get("country", "Simulation"), event_type=data.get("event_type", "TRAFFIC"), attack_type=data.get("attack_type", "Normal HTTP Request"),
        severity=data.get("severity", "LOW"), status=data.get("status", "NORMAL"), scenario_id=data.get("scenario_id"), description=data.get("description", "Synthetic educational event"), metadata_json=json.dumps({"simulated": True}))
    db.session.add(event); db.session.flush()
    event.risk_score, explanation = risk_for(event)
    detection = detect(event)
    if detection:
        event.severity, event.status = detection[1], "MALICIOUS"
        event.description += " Detection: " + detection[3]
        if detection[2] == "Temporary Block": block_ip(event.source_ip, detection[3], detection[1])
    elif event.status != "NORMAL":
        violations = Event.query.filter_by(source_ip=event.source_ip).filter(
            Event.status.in_(["SUSPICIOUS", "MALICIOUS"])
        ).count()
        thresholds = current_app.config["ATTEMPT_THRESHOLDS"]
        if violations >= thresholds["permanent"]:
            block_ip(event.source_ip, "Configured violation threshold reached", event.severity, permanent=True)
        elif violations >= thresholds["long"]:
            block_ip(event.source_ip, "Configured violation threshold reached", event.severity, setting_int("TEMP_BLOCK_DURATION", current_app.config["LONG_BLOCK_DURATION"]))
        elif violations >= thresholds["temporary"]:
            block_ip(event.source_ip, "Configured violation threshold reached", event.severity, setting_int("TEMP_BLOCK_DURATION", current_app.config["TEMP_BLOCK_DURATION"]))
    event.action, _ = firewall_decision(event)
    incident = correlate_and_incident(event, detection)
    if incident: event.incident_id = incident.id
    db.session.commit()
    return event, detection


def simulate(attack_type="random", scenario=None, count=1):
    normal = [("Normal HTTP Request", 80, "TCP"), ("DNS Query", 53, "UDP"), ("Successful Login", 443, "TCP"), ("SSH Connection", 22, "TCP"), ("File Download", 443, "TCP"), ("Database Request", 3306, "TCP")]
    created=[]; ip="192.168.1.100"
    if scenario == "brute_force": items=[("Brute Force", 443, "HIGH", "Failed simulated login")]*7
    elif scenario == "port_scan": items=[("Port Scan", p, "HIGH", "Synthetic scan connection") for p in [21,22,23,25,53,80,110,139,443,445,3306,3389]]
    elif scenario == "web_attack": items=[("Web Attack", 443, "CRITICAL", "Suspicious simulated web input")]*4
    elif scenario == "ddos": items=[("DDoS", 443, "HIGH", "Synthetic high-volume event")]*max(20, count)
    elif scenario == "multi_stage": items=[("Port Scan", p, "HIGH", "Reconnaissance simulation") for p in [21,22,80,443,445,3389]] + [("Brute Force",443,"HIGH","Failed simulated login")]*6 + [("Web Attack",443,"CRITICAL","Suspicious simulated input")]*3
    else:
        if attack_type == "normal":
            items=[]
            for _ in range(count):
                name, port, protocol=random.choice(normal)
                items.append((name,port,"LOW",f"Baseline {name.lower()} activity"))
        else: items=[(attack_type if attack_type != "random" else random.choice(["Brute Force","Port Scan","Web Attack","DDoS"]), 443, "HIGH", "Synthetic attack simulation") for _ in range(count)]
    for name, port, severity, description in items:
        created.append(create_event({"source_ip": ip if name not in [x[0] for x in normal] else "10.0.0.25", "destination_port":port, "protocol":"UDP" if port==53 else "TCP", "attack_type":name, "severity":severity, "status":"NORMAL" if severity=="LOW" else "SUSPICIOUS", "scenario_id":scenario, "description":description})[0])
    return created
