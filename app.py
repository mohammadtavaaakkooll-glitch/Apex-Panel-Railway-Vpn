from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import os, hashlib, platform, socket, time
from datetime import datetime
import psutil
from server import mtproto, load_json, LOG_FILE

app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "apex-mtproto-secret")

START_TIME = time.time()


def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()


def login_required(f):
    @wraps(f)
    def deco(*a, **kw):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return deco


def human_time(s):
    s = int(s)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts = []
    if d: parts.append(f"{d}روز")
    if h: parts.append(f"{h}ساعت")
    if m: parts.append(f"{m}دقیقه")
    parts.append(f"{s}ثانیه")
    return " ".join(parts)


@app.route("/")
def index():
    if not mtproto.get_admin(): return redirect(url_for("setup"))
    if not session.get("logged_in"): return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if mtproto.get_admin(): return redirect(url_for("login"))
    if request.method == "POST":
        d = request.get_json()
        u, p = d.get("username", "").strip(), d.get("password", "")
        if not u or not p: return jsonify({"ok": False, "error": "همه فیلدها الزامی"}), 400
        if len(p) < 4: return jsonify({"ok": False, "error": "رمز حداقل ۴ کاراکتر"}), 400
        mtproto.set_admin(u, hash_password(p))
        return jsonify({"ok": True})
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if not mtproto.get_admin(): return redirect(url_for("setup"))
    if request.method == "POST":
        d = request.get_json()
        u, p = d.get("username", "").strip(), d.get("password", "")
        admin = mtproto.get_admin()
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


# ==================== API ====================
@app.route("/api/stats")
@login_required
def api_stats():
    s = mtproto.get_stats()
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        s["cpu"] = cpu
        s["ram"] = mem.percent
        s["uptime"] = human_time(time.time() - START_TIME)
    except:
        pass
    return jsonify(s)


@app.route("/api/users")
@login_required
def api_users():
    return jsonify(mtproto.list_users())


@app.route("/api/users", methods=["POST"])
@login_required
def api_create_user():
    d = request.get_json()
    name = d.get("name", "").strip()
    exp = d.get("expire_days", 0)
    if not name: return jsonify({"error": "نام الزامی"}), 400
    return jsonify(mtproto.create_user(name, int(exp)))


@app.route("/api/users/<uid>", methods=["DELETE"])
@login_required
def api_delete_user(uid):
    mtproto.delete_user(uid)
    return jsonify({"ok": True})


@app.route("/api/users/<uid>", methods=["PATCH"])
@login_required
def api_update_user(uid):
    u = mtproto.update_user(uid, request.get_json())
    return jsonify(u) if u else (jsonify({"error": "not found"}), 404)


@app.route("/api/users/bulk", methods=["POST"])
@login_required
def api_bulk():
    d = request.get_json()
    return jsonify(mtproto.bulk_create(
        d.get("prefix", "user"),
        int(d.get("count", 1)),
        int(d.get("expire_days", 0))
    ))


@app.route("/api/proxy/start", methods=["POST"])
@login_required
def api_proxy_start():
    ok, msg = mtproto.start_proxy()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/proxy/stop", methods=["POST"])
@login_required
def api_proxy_stop():
    ok, msg = mtproto.stop_proxy()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/proxy/restart", methods=["POST"])
@login_required
def api_proxy_restart():
    ok, msg = mtproto.restart_proxy()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/proxy/link")
@login_required
def api_proxy_link():
    return jsonify({
        "link": mtproto.build_link(),
        "https_link": mtproto.build_https_link(),
        "secret": mtproto.db["settings"]["secret"],
        "server": mtproto.db["settings"]["server_ip"],
        "port": mtproto.db["settings"]["port"]
    })


@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    if request.method == "POST":
        d = request.get_json()
        for k, v in d.items():
            mtproto.db["settings"][k] = v
        mtproto.save()
        return jsonify(mtproto.db["settings"])
    return jsonify(mtproto.db["settings"])


@app.route("/api/logs")
@login_required
def api_logs():
    return jsonify(load_json(LOG_FILE, [])[:100])


@app.route("/api/change-password", methods=["POST"])
@login_required
def api_change_password():
    d = request.get_json()
    old, new = d.get("old_password", ""), d.get("new_password", "")
    if len(new) < 4: return jsonify({"error": "رمز جدید حداقل ۴ کاراکتر"}), 400
    admin = mtproto.get_admin()
    if admin["password"] != hash_password(old):
        return jsonify({"error": "رمز قدیمی اشتباه"}), 401
    admin["password"] = hash_password(new)
    mtproto.save()
    return jsonify({"ok": True})


if __name__ == "__main__":
    mtproto.start_proxy()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
