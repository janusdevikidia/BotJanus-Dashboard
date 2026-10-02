"""Scripts "en continu" hébergés sur un serveur distant (via BotJanus Agent).

Le dashboard ne lance rien lui-même : il parle à l'agent (bot_agent.py) en HTTPS avec
un jeton secret. Le jeton reste côté serveur Flask, jamais envoyé au navigateur.

Routes :
  GET  /api/services/status               public : état résumé (carte du dashboard)
  GET  /admin/services                    admin  : page de contrôle
  GET  /admin/services/<id>/logs          admin  : dernières lignes de journal (JSON)
  POST /admin/services/<id>/<action>      admin  : start | stop | restart (CSRF)
"""
import threading
import time

import requests
from flask import Blueprint, jsonify, render_template_string, request, session

from flask_app import (ROLE_ADMIN, AGENT_URL, AGENT_TOKEN, check_role, get_db, log_to_db)
from templates import GLASS_CSS, ADMIN_SERVICES_HTML

services_bp = Blueprint("services", __name__)

AGENT_TIMEOUT = 6          # secondes : un agent lent ne doit pas bloquer le dashboard
CACHE_TTL = 5              # secondes : évite de marteler l'agent (plusieurs visiteurs)

_cache = {"t": 0.0, "data": None}
_cache_lock = threading.Lock()


def _agent(method, path, acting_user=None, **kw):
    headers = {"Authorization": f"Bearer {AGENT_TOKEN}"}
    if acting_user:
        headers["X-Acting-User"] = acting_user
    return requests.request(method, f"{AGENT_URL.rstrip('/')}{path}", headers=headers,
                            timeout=AGENT_TIMEOUT, **kw)


def fetch_services(force=False):
    """Renvoie {"reachable": bool, "services": [...], "error": str|None}."""
    if not AGENT_URL or not AGENT_TOKEN:
        return {"reachable": False, "services": [], "error": "Agent non configuré (AGENT_URL / AGENT_TOKEN)."}
    with _cache_lock:
        if not force and _cache["data"] and time.time() - _cache["t"] < CACHE_TTL:
            return _cache["data"]
    try:
        r = _agent("GET", "/services")
        r.raise_for_status()
        data = {"reachable": True, "services": r.json()["services"], "error": None}
    except Exception as e:
        data = {"reachable": False, "services": [], "error": f"Serveur distant injoignable ({type(e).__name__})."}
    with _cache_lock:
        _cache.update(t=time.time(), data=data)
    return data


def _is_admin():
    if 'user_id' not in session:
        return False
    u = get_db().execute("SELECT role, is_banned FROM users WHERE wiki_id=?", (session['user_id'],)).fetchone()
    return bool(u and u['role'] == ROLE_ADMIN and not u['is_banned'])


PUBLIC_FIELDS = ("id", "label", "description", "running", "health", "health_reason",
                 "uptime_s", "heartbeat_age_s")
ADMIN_FIELDS = PUBLIC_FIELDS + ("desired", "pid", "started_at", "restarts", "crash_count",
                                "last_exit", "last_action", "last_action_by", "autorestart",
                                "cpu_percent", "memory_mb", "errors_last_hour", "last_error")


@services_bp.route("/api/services/status")
def services_status():
    data = fetch_services()
    fields = ADMIN_FIELDS if _is_admin() else PUBLIC_FIELDS
    return jsonify(reachable=data["reachable"], error=data["error"] if _is_admin() else
                   (None if data["reachable"] else "Serveur distant injoignable."),
                   is_admin=_is_admin(),
                   services=[{k: s.get(k) for k in fields} for s in data["services"]])


@services_bp.route("/admin/services")
@check_role([ROLE_ADMIN])
def admin_services():
    return render_template_string(ADMIN_SERVICES_HTML, glass_css=GLASS_CSS, active='services')


@services_bp.route("/admin/services/<sid>/logs")
@check_role([ROLE_ADMIN])
def service_logs(sid):
    try:
        r = _agent("GET", f"/services/{sid}/logs", params={"lines": request.args.get("lines", 150)})
        r.raise_for_status()
        return jsonify(r.json())
    except Exception as e:
        return jsonify(error=f"Impossible de lire le journal ({type(e).__name__})."), 502


@services_bp.route("/admin/services/<sid>/<action>", methods=["POST"])
@check_role([ROLE_ADMIN])
def service_action(sid, action):
    if action not in ("start", "stop", "restart"):
        return jsonify(ok=False, message="Action inconnue."), 400
    who = session.get('username') or 'admin'
    try:
        r = _agent("POST", f"/services/{sid}/{action}", acting_user=who)
        payload = r.json()
    except Exception as e:
        return jsonify(ok=False, message=f"Serveur distant injoignable ({type(e).__name__})."), 502
    if r.status_code == 404:
        return jsonify(ok=False, message="Service inconnu."), 404
    log_to_db("SYSTEM", f"Service continu '{sid}' : {action} par {who} -> {payload.get('message')}")
    fetch_services(force=True)
    return jsonify(ok=bool(payload.get("ok")), message=payload.get("message"),
                   service=payload.get("service")), (200 if payload.get("ok") else 409)
