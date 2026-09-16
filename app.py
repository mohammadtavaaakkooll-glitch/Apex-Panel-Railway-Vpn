"""
APEX PANEL - Flask Application
"""
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response
from functools import wraps
import os
import hashlib
import json
import platform
import socket
import time
from datetime import datetime
import psutil

from server import user_manager, xray_core, start_monitor

app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "apex-panel-change-me-in-production")

START_TIME = time.time()
REQUEST_COUNT = {"total": 0, "today": 0, "last_reset": datetime.now().date().isoformat()}


# ==================== HELPERS ====================
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()


def login_required(f):
    @wraps(f)
    def deco(*a, **kw):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return deco


def human_bytes(b):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"


def human_time(seconds):
    seconds = int(seconds)
    d, seconds = divmod(seconds, 86400)
    h, seconds = divmod(seconds, 3600)
    m, seconds = divmod(seconds, 60)
    parts = []
    if d: parts.append(f"{d}روز")
    if h: parts.append(f"{h}ساعت")
    if m: parts.append(f"{m}دقیقه")
    parts.append(f"{seconds}ثانیه")
    return " ".join(parts)


# ==================== REQUEST COUNTER ====================
@app.before_request
def count():
    REQUEST_COUNT["total"] += 1
    today = datetime.now().date().isoformat()
    if REQUEST_COUNT["last_reset"] != today:
        REQUEST_COUNT["today"] = 0
        REQUEST_COUNT["last_reset"] = today
    REQUEST_COUNT["today"] += 1


# ==================== ROUTES ====================
@app.route("/")
def index():
    if not user_manager.get_admin():
        return redirect(url_for("setup"))
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if user_manager.get_admin():
        return redirect(url_for("login"))
    if request.method == "POST":
        d = request.get_json()
        u = d.get("username", "").strip()
        p = d.get("password", "")
        if not u or not p:
            return jsonify({"ok": False, "error": "همه فیلدها الزامی"}), 400
        if len(p) < 4:
            return jsonify({"ok": False, "error": "رمز حداقل ۴ کاراکتر"}), 400
        user_manager.set_admin(u, hash_password(p))
        return jsonify({"ok": True})
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if not user_manager.get_admin():
        return redirect(url_for("setup"))
    if request.method == "POST":
        d = request.get_json()
        u = d.get("username", "").strip()
        p = d.get("password", "")
        admin = user_manager.get_admin()
        if admin and admin["username"] == u and admin["password"] == hash_password(p):
            session["logged_in"] = True
            session["username"] = u
            return jsonify({"ok": True})
        return jsonify({"ok": False, "error": "نام کاربری یا رمز اشتباه"}), 401
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/status")
def public_status():
    users = user_manager.list_users()
    s = user_manager.db["settings"]
    sys_stats = get_system_stats()
    return render_template("status.html",
        panel_name=s.get("panel_name", "Apex Panel"),
        total_users=len(users),
        active_users=len([u for u in users if u["status"] == "active"]),
        cpu=sys_stats.get("cpu", {}).get("percent", 0),
        ram=sys_stats.get("ram", {}).get("percent", 0),
        uptime=sys_stats.get("panel", {}).get("uptime", "—"),
        status_domain=s.get("status_domain", "status.apex.ir")
    )


# ==================== SYSTEM STATS ====================
def get_system_stats():
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()
        return {
            "cpu": {"percent": cpu, "count": psutil.cpu_count()},
            "ram": {
                "total": round(mem.total / (1024**3), 2),
                "used": round(mem.used / (1024**3), 2),
                "percent": mem.percent
            },
            "disk": {
                "total": round(disk.total / (1024**3), 2),
                "used": round(disk.used / (1024**3), 2),
                "percent": disk.percent
            },
            "network": {
                "sent_human": human_bytes(net.bytes_sent),
                "recv_human": human_bytes(net.bytes_recv)
            },
            "system": {
                "os": f"{platform.system()} {platform.release()}",
                "hostname": socket.gethostname(),
                "python": platform.python_version()
            },
            "panel": {
                "uptime": human_time(time.time() - START_TIME),
                "requests_today": REQUEST_COUNT["today"],
                "requests_total": REQUEST_COUNT["total"]
            },
            "xray": {
                "running": xray_core.is_running(),
                "started_at": xray_core.started_at.isoformat() if xray_core.started_at else None
            }
        }
    except Exception as e:
        return {"error": str(e)}


@app.route("/api/system")
@login_required
def api_system():
    return jsonify(get_system_stats())


@app.route("/api/system/processes")
@login_required
def api_processes():
    try:
        procs = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
            try:
                procs.append({
                    "pid": p.info["pid"],
                    "name": p.info["name"],
                    "cpu": round(p.info["cpu_percent"] or 0, 2),
                    "mem": round(p.info["memory_percent"] or 0, 2)
                })
            except: pass
        procs.sort(key=lambda x: x["cpu"], reverse=True)
        return jsonify(procs[:20])
    except Exception as e:
        return jsonify({"error": str(e)})


# ==================== USERS API ====================
@app.route("/api/users")
@login_required
def api_list_users():
    return jsonify(user_manager.list_users())


@app.route("/api/users", methods=["POST"])
@login_required
def api_create_user():
    d = request.get_json()
    name = d.get("name", "").strip()
    size = d.get("size")
    exp = d.get("expire_days", 0)
    proto = d.get("protocol", "vless")
    if not name or not size or int(size) <= 0:
        return jsonify({"error": "نام و حجم الزامی"}), 400
    user = user_manager.create_user(name, int(size), int(exp), proto)
    return jsonify(user)


@app.route("/api/users/<uid>", methods=["DELETE"])
@login_required
def api_delete_user(uid):
    user_manager.delete_user(uid)
    return jsonify({"ok": True})


@app.route("/api/users/<uid>", methods=["PATCH"])
@login_required
def api_update_user(uid):
    u = user_manager.update_user(uid, request.get_json())
    if u: return jsonify(u)
    return jsonify({"error": "not found"}), 404


@app.route("/api/users/<uid>/reset", methods=["POST"])
@login_required
def api_reset_user(uid):
    u = user_manager.reset_user(uid)
    if u: return jsonify(u)
    return jsonify({"error": "not found"}), 404


@app.route("/api/users/bulk", methods=["POST"])
@login_required
def api_bulk():
    d = request.get_json()
    created = user_manager.bulk_create(
        d.get("prefix", "user"),
        int(d.get("count", 1)),
        int(d.get("size", 10)),
        int(d.get("expire_days", 0))
    )
    return jsonify(created)


# ==================== STATS API ====================
@app.route("/api/stats")
@login_required
def api_stats():
    users = user_manager.list_users()
    total = sum(u["size"] for u in users)
    used = sum(u.get("used", 0) for u in users)
    now = datetime.now()
    return jsonify({
        "total_users": len(users),
        "active_users": len([u for u in users if u["status"] == "active"]),
        "disabled_users": len([u for u in users if u["status"] == "disabled"]),
        "expired_users": len([u for u in users if u.get("expire_at") and datetime.fromisoformat(u["expire_at"]) < now]),
        "total_traffic": round(total, 2),
        "used_traffic": round(used, 2),
        "remaining_traffic": round(total - used, 2),
        "total_connections": sum(u.get("connections", 0) for u in users),
        "xray_running": xray_core.is_running()
    })


# ==================== SETTINGS API ====================
@app.route("/api/settings")
@login_required
def api_get_settings():
    return jsonify(user_manager.db["settings"])


@app.route("/api/settings", methods=["POST"])
@login_required
def api_update_settings():
    d = request.get_json()
    s = user_manager.db["settings"]
    for k, v in d.items():
        s[k] = v
    user_manager.save()
    user_manager.apply_to_xray()
    return jsonify(s)


# ==================== XRAY CONTROL ====================
@app.route("/api/xray/start", methods=["POST"])
@login_required
def api_xray_start():
    ok, msg = xray_core.start()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/xray/stop", methods=["POST"])
@login_required
def api_xray_stop():
    ok, msg = xray_core.stop()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/xray/restart", methods=["POST"])
@login_required
def api_xray_restart():
    ok, msg = xray_core.restart()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/xray/stats")
@login_required
def api_xray_stats():
    return jsonify(xray_core.get_stats())


# ==================== LOGS ====================
@app.route("/api/logs")
@login_required
def api_logs():
    from server import load_json, LOG_FILE
    return jsonify(load_json(LOG_FILE, [])[:100])


# ==================== SECURITY ====================
@app.route("/api/change-password", methods=["POST"])
@login_required
def api_change_password():
    d = request.get_json()
    old = d.get("old_password", "")
    new = d.get("new_password", "")
    if len(new) < 4:
        return jsonify({"error": "رمز جدید حداقل ۴ کاراکتر"}), 400
    admin = user_manager.get_admin()
    if admin["password"] != hash_password(old):
        return jsonify({"error": "رمز قدیمی اشتباه"}), 401
    admin["password"] = hash_password(new)
    user_manager.save()
    return jsonify({"ok": True})


# ==================== BACKUP ====================
@app.route("/api/backup")
@login_required
def api_backup():
    return jsonify({
        "db": user_manager.db,
        "xray_config": json.load(open("data/xray_config.json", encoding="utf-8")) if os.path.exists("data/xray_config.json") else {},
        "exported_at": datetime.now().isoformat()
    })


# ==================== SUBSCRIPTION ====================
@app.route("/sub/<user_uuid>")
def subscription(user_uuid):
    user = user_manager.get_user_by_uuid(user_uuid)
    if not user:
        return Response("User not found", status=404)
    if user["status"] != "active":
        return Response("User disabled", status=403)

    # آپدیت last_seen
    user["last_seen"] = datetime.now().isoformat()
    user["connections"] = user.get("connections", 0) + 1
    user_manager.save()

    # خروجی base64 از لینک‌ها
    import base64
    links = "\n".join(user.get("links", {}).values())
    return Response(base64.b64encode(links.encode()).decode(), mimetype="text/plain")


# ==================== START ====================
if __name__ == "__main__":
    start_monitor()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
