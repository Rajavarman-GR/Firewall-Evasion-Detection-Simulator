from datetime import datetime
from flask import Blueprint, jsonify, request, session, Response
from io import StringIO, BytesIO
import csv
from openpyxl import Workbook
from werkzeug.security import generate_password_hash
from app.extensions import db
from app.models import Event, Incident, BlockedIP, FirewallRule, AuditLog, User, InvestigationNote, SystemSetting
from app.services.core import simulate, block_ip, set_whitelist, rule_conflicts, audit
from app.permissions import (require_permission, VIEW_AUDIT, RUN_SIMULATION,
    INVESTIGATE_INCIDENT, BLOCK_IP, MANAGE_RULES, MANAGE_WHITELIST, MANAGE_USERS)
api = Blueprint("api", __name__)
def serialize(obj):
    data={c.name:getattr(obj,c.name) for c in obj.__table__.columns}
    for k,v in data.items():
        if isinstance(v,datetime): data[k]=v.isoformat()+"Z"
    return data
@api.get("/dashboard/stats")
def stats():
    items=Event.query.order_by(Event.timestamp.desc()).limit(100).all()
    return jsonify(total_events=Event.query.count(),active_incidents=Incident.query.filter(Incident.status.in_(["OPEN","INVESTIGATING","CONTAINED"])).count(),high_critical=Incident.query.filter(Incident.severity.in_(["HIGH","CRITICAL"]),Incident.status!="CLOSED").count(),blocked_ips=BlockedIP.query.filter_by(status="ACTIVE",whitelisted=False).count(),recent_events=[serialize(x) for x in items[:10]],incidents=[serialize(x) for x in Incident.query.order_by(Incident.last_seen.desc()).limit(8)],timeline=[serialize(x) for x in items])
@api.get("/events")
def events():
    q=Event.query
    for field in ["severity","attack_type","source_ip","protocol","action","status"]:
        if request.args.get(field):q=q.filter(getattr(Event,field)==request.args[field])
    if request.args.get("search"):q=q.filter(Event.description.ilike(f"%{request.args['search']}%"))
    if request.args.get("start"):q=q.filter(Event.timestamp >= datetime.fromisoformat(request.args["start"]))
    if request.args.get("end"):q=q.filter(Event.timestamp <= datetime.fromisoformat(request.args["end"]))
    sort=request.args.get("sort","timestamp");direction=request.args.get("direction","desc")
    if sort not in {"timestamp","severity","risk_score","source_ip","attack_type","action","status"}:return jsonify(error="Invalid sort field"),400
    column=getattr(Event,sort);q=q.order_by(column.asc() if direction=="asc" else column.desc())
    page=max(1,request.args.get("page",1,type=int));result=q.paginate(page=page,per_page=min(100,request.args.get("per_page",25,type=int)),error_out=False)
    return jsonify(items=[serialize(x) for x in result.items],total=result.total,page=page,pages=result.pages)
@api.get("/events/<int:event_id>")
def event_detail(event_id):return jsonify(serialize(Event.query.get_or_404(event_id)))
@api.get("/incidents")
def incidents():return jsonify([serialize(x) for x in Incident.query.order_by(Incident.last_seen.desc())])
@api.get("/incidents/<int:incident_id>")
def incident_detail(incident_id):
    incident=Incident.query.get_or_404(incident_id);data=serialize(incident);data["events"]=[serialize(x) for x in sorted(incident.events,key=lambda e:e.timestamp)];data["audit_history"]=[serialize(x) for x in AuditLog.query.filter_by(target_type="incident",target_id=str(incident_id)).order_by(AuditLog.timestamp.desc())];data["notes"]=[dict(serialize(x),username=x.user.username) for x in InvestigationNote.query.filter_by(incident_id=incident.id).order_by(InvestigationNote.timestamp.asc())];return jsonify(data)
@api.post("/incidents/<int:incident_id>/notes")
@require_permission(INVESTIGATE_INCIDENT)
def add_incident_note(incident_id):
    Incident.query.get_or_404(incident_id);data=request.get_json(silent=True) or {};content=str(data.get("content","")).strip()
    if not content or len(content)>2000:return jsonify(error="A note of 1-2000 characters is required"),400
    note=InvestigationNote(incident_id=incident_id,user_id=session["user_id"],content=content);db.session.add(note);db.session.flush();audit("ADD_INVESTIGATION_NOTE","incident",incident_id,content,session.get("username","unknown"));db.session.commit();return jsonify(dict(serialize(note),username=session.get("username"))),201
@api.patch("/incidents/<int:incident_id>")
@require_permission(INVESTIGATE_INCIDENT)
def update_incident(incident_id):
    incident=Incident.query.get_or_404(incident_id);data=request.get_json(silent=True) or {};valid={"OPEN","INVESTIGATING","CONTAINED","RESOLVED","CLOSED"}
    if "status" in data:
        if data["status"] not in valid:return jsonify(error="Invalid incident status"),400
        incident.status=data["status"];audit("CHANGE_INCIDENT_STATUS","incident",incident.id,data["status"],session.get("username","unknown"))
    if "assigned_to" in data:incident.assigned_to=data["assigned_to"]
    db.session.commit();return jsonify(serialize(incident))
@api.get("/firewall/rules")
def rules():return jsonify([serialize(x) for x in FirewallRule.query.order_by(FirewallRule.priority).all()])
@api.post("/firewall/rules")
@require_permission(MANAGE_RULES)
def create_rule():
    data=request.get_json(silent=True) or {}
    if not data.get("name") or data.get("action") not in {"ALLOW","DENY","DROP","LOG","ALERT","BLOCK_TEMPORARY","BLOCK_PERMANENT"}:return jsonify(error="name and valid action are required"),400
    rule=FirewallRule(**{k:v for k,v in data.items() if k in {"name","description","source_ip","destination_ip","protocol","source_port","destination_port","action","priority","enabled"}});db.session.add(rule);db.session.flush();warnings=rule_conflicts(rule);audit("CREATE_RULE","firewall_rule",rule.id,rule.name,session.get("username","unknown"));db.session.commit();return jsonify(rule=serialize(rule),conflict_warnings=warnings),201
@api.put("/firewall/rules/<int:rule_id>")
@require_permission(MANAGE_RULES)
def update_rule(rule_id):
    rule=FirewallRule.query.get_or_404(rule_id);data=request.get_json(silent=True) or {}
    for k in {"name","description","source_ip","destination_ip","protocol","source_port","destination_port","action","priority","enabled"}:
        if k in data:setattr(rule,k,data[k])
    audit("UPDATE_RULE","firewall_rule",rule.id,rule.name,session.get("username","unknown"));db.session.commit();return jsonify(serialize(rule))
@api.delete("/firewall/rules/<int:rule_id>")
@require_permission(MANAGE_RULES)
def delete_rule(rule_id):
    rule=FirewallRule.query.get_or_404(rule_id);audit("DELETE_RULE","firewall_rule",rule.id,rule.name,session.get("username","unknown"));db.session.delete(rule);db.session.commit();return "",204
@api.get("/firewall/blocked")
def blocked():return jsonify([serialize(x) for x in BlockedIP.query.order_by(BlockedIP.created_at.desc())])
@api.get("/firewall/whitelist")
def whitelist():return jsonify([serialize(x) for x in BlockedIP.query.filter_by(whitelisted=True).order_by(BlockedIP.created_at.desc())])
@api.post("/firewall/whitelist")
@require_permission(MANAGE_WHITELIST)
def add_whitelist():
    data=request.get_json(silent=True) or {}
    if not data.get("ip"):return jsonify(error="ip is required"),400
    item=set_whitelist(data["ip"],True,data.get("reason","Administrator whitelist"));db.session.commit();return jsonify(serialize(item)),201
@api.delete("/firewall/whitelist/<path:ip>")
@require_permission(MANAGE_WHITELIST)
def remove_whitelist(ip):
    item=BlockedIP.query.filter_by(ip=ip,whitelisted=True).first()
    if not item:return jsonify(error="Whitelist entry not found"),404
    set_whitelist(ip,False,"Whitelist removed");db.session.commit();return "",204
@api.post("/firewall/block")
@require_permission(BLOCK_IP)
def block():
    data=request.get_json(silent=True) or {}
    if not data.get("ip"):return jsonify(error="ip is required"),400
    item,error=block_ip(data["ip"],data.get("reason","Manual simulated block"),data.get("severity","HIGH"),int(data.get("duration_minutes",5)),bool(data.get("permanent",False)))
    if error:return jsonify(error=error),409
    db.session.commit();return jsonify(serialize(item)),201
@api.post("/firewall/unblock")
@require_permission(BLOCK_IP)
def unblock():
    item=BlockedIP.query.filter_by(ip=(request.get_json(silent=True) or {}).get("ip")).first()
    if not item:return jsonify(error="Block not found"),404
    item.status="INACTIVE";audit("UNBLOCK_IP","blocked_ip",item.ip,"Manual unblock",session.get("username","unknown"));db.session.commit();return jsonify(serialize(item))
@api.post("/simulation/attack")
@require_permission(RUN_SIMULATION)
def attack():
    data=request.get_json(silent=True) or {};made=simulate(data.get("attack_type","random"),count=max(1,min(50,int(data.get("count",1)))));return jsonify(created=len(made),events=[serialize(x) for x in made])
@api.post("/simulation/scenario")
@require_permission(RUN_SIMULATION)
def scenario():
    name=(request.get_json(silent=True) or {}).get("scenario")
    if name not in {"brute_force","port_scan","web_attack","ddos","multi_stage"}:return jsonify(error="Unknown scenario"),400
    made=simulate(scenario=name);return jsonify(created=len(made),scenario=name)
@api.post("/simulation/start")
@require_permission(RUN_SIMULATION)
def start():
    count=max(1,min(50,int((request.get_json(silent=True) or {}).get("count",10))));made=simulate("normal",count=count);return jsonify(created=len(made),mode="automated")
@api.get("/audit")
@require_permission(VIEW_AUDIT)
def audit_logs():return jsonify([serialize(x) for x in AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200)])
@api.get("/users")
@require_permission(MANAGE_USERS)
def users():return jsonify([serialize(x) for x in User.query.order_by(User.username)])
@api.post("/users")
@require_permission(MANAGE_USERS)
def create_user():
    data=request.get_json(silent=True) or {};username=str(data.get("username","")).strip();password=str(data.get("password", ""));role=data.get("role","VIEWER")
    if not username or len(username)>80 or not username.replace("_","").isalnum():return jsonify(error="Invalid username"),400
    if role not in {"VIEWER","ANALYST","ADMIN"}:return jsonify(error="Invalid role"),400
    if len(password)<10 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):return jsonify(error="Password must be 10+ characters with letters and numbers"),400
    if User.query.filter_by(username=username).first():return jsonify(error="Username already exists"),409
    user=User(username=username,password_hash=generate_password_hash(password),role=role);db.session.add(user);db.session.flush();audit("CREATE_USER","user",user.id,username,session["username"]);db.session.commit();return jsonify(serialize(user)),201
@api.patch("/users/<int:user_id>")
@require_permission(MANAGE_USERS)
def update_user(user_id):
    user=User.query.get_or_404(user_id);data=request.get_json(silent=True) or {}
    if "role" in data:
        if data["role"] not in {"VIEWER","ANALYST","ADMIN"}:return jsonify(error="Invalid role"),400
        if user.role=="ADMIN" and data["role"]!="ADMIN" and User.query.filter_by(role="ADMIN",status="ACTIVE").count()<=1:return jsonify(error="Cannot remove the last active administrator"),409
        user.role=data["role"]
    if "status" in data:
        if data["status"] not in {"ACTIVE","DISABLED"}:return jsonify(error="Invalid status"),400
        if user.role=="ADMIN" and data["status"]=="DISABLED" and User.query.filter_by(role="ADMIN",status="ACTIVE").count()<=1:return jsonify(error="Cannot disable the last active administrator"),409
        user.status=data["status"]
    if "password" in data:
        password=str(data["password"])
        if len(password)<10 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):return jsonify(error="Password must be 10+ characters with letters and numbers"),400
        user.password_hash=generate_password_hash(password)
    audit("UPDATE_USER","user",user.id,"role/status/password change",session["username"]);db.session.commit();return jsonify(serialize(user))
@api.delete("/users/<int:user_id>")
@require_permission(MANAGE_USERS)
def delete_user(user_id):
    user=User.query.get_or_404(user_id)
    if user.role=="ADMIN" and user.status=="ACTIVE" and User.query.filter_by(role="ADMIN",status="ACTIVE").count()<=1:return jsonify(error="Cannot delete the last active administrator"),409
    audit("DELETE_USER","user",user.id,user.username,session["username"]);db.session.delete(user);db.session.commit();return "",204
@api.get("/settings")
@require_permission(MANAGE_USERS)
def settings():return jsonify([serialize(x) for x in SystemSetting.query.order_by(SystemSetting.key)])
@api.patch("/settings/<string:key>")
@require_permission(MANAGE_USERS)
def update_setting(key):
    setting=SystemSetting.query.filter_by(key=key).first_or_404();value=str((request.get_json(silent=True) or {}).get("value","")).strip()
    try:
        if int(value)<1:return jsonify(error="Value must be positive"),400
    except ValueError:return jsonify(error="Value must be a positive integer"),400
    setting.value=value;audit("UPDATE_SETTING","setting",setting.id,f"{key}={value}",session["username"]);db.session.commit();return jsonify(serialize(setting))

def csv_export(rows, filename, action):
    out=StringIO(); data=[serialize(x) for x in rows]
    writer=csv.DictWriter(out,fieldnames=list(data[0]) if data else ["id"]);writer.writeheader();writer.writerows(data)
    audit(action,"export",filename,"CSV export",session.get("username","anonymous"));db.session.commit()
    return Response(out.getvalue(),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename={filename}"})
@api.get("/exports/events.csv")
def export_events_csv():return csv_export(Event.query.order_by(Event.timestamp.desc()).all(),"events.csv","EXPORT_LOGS")
@api.get("/exports/incidents.csv")
def export_incidents_csv():return csv_export(Incident.query.order_by(Incident.last_seen.desc()).all(),"incidents.csv","EXPORT_LOGS")
@api.get("/exports/audit.csv")
@require_permission(VIEW_AUDIT)
def export_audit_csv():return csv_export(AuditLog.query.order_by(AuditLog.timestamp.desc()).all(),"audit_logs.csv","EXPORT_LOGS")
@api.get("/exports/events.xlsx")
def export_events_excel():
    data=[serialize(x) for x in Event.query.order_by(Event.timestamp.desc()).all()];book=Workbook(write_only=True);sheet=book.create_sheet("Events")
    keys=list(data[0]) if data else ["id"];sheet.append(keys)
    for row in data:sheet.append([row.get(k) for k in keys])
    out=BytesIO();book.save(out);audit("EXPORT_LOGS","export","events.xlsx","Excel export",session.get("username","anonymous"));db.session.commit()
    return Response(out.getvalue(),mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",headers={"Content-Disposition":"attachment; filename=events.xlsx"})
