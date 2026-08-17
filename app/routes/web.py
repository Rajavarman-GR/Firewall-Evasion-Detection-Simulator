from flask import Blueprint,render_template,request,redirect,url_for,session,flash,abort
from werkzeug.security import check_password_hash
from app.extensions import db
from app.models import User
from app.services.core import audit
web=Blueprint("web",__name__)
@web.get("/")
def dashboard():return render_template("index.html")
@web.get("/events")
def event_page():return render_template("events.html")
@web.get("/incidents")
def incident_page():return render_template("incidents.html")
@web.get("/firewall")
def firewall_page():return render_template("firewall.html")
@web.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        user=User.query.filter_by(username=request.form.get("username","")).first()
        if user and user.status == "ACTIVE" and check_password_hash(user.password_hash,request.form.get("password","")):
            from datetime import datetime, timezone
            user.last_login=datetime.now(timezone.utc).replace(tzinfo=None)
            session.update(user_id=user.id,username=user.username,role=user.role);audit("LOGIN","user",user.id,"",user.username);db.session.commit();return redirect(url_for("web.dashboard"))
        flash("Invalid credentials")
    return render_template("login.html")
@web.get("/logout")
def logout():
    if session.get("user_id"):audit("LOGOUT","user",session["user_id"],"",session.get("username","unknown"));db.session.commit()
    session.clear();return redirect(url_for("web.login"))
@web.get("/admin/users")
def users_page():
    if session.get("role")!="ADMIN":abort(403)
    return render_template("users.html")
@web.get("/admin/settings")
def settings_page():
    if session.get("role")!="ADMIN":abort(403)
    return render_template("settings.html")
