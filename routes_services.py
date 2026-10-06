"""Scripts "en continu" hébergés sur un serveur distant (via BotJanus Agent).

  Agent  --POST /api/agent/sync (jeton)-->  Dashboard
         { état de santé des scripts, derniers logs, résultats des ordres exécutés }
         <-- { ordres en attente (start/stop/restart), délai avant le prochain appel } --

Le dashboard stocke le dernier état reçu (SQLite) et les ordres demandés par les admins ;
l'agent vient les chercher au prochain appel. Pour économiser le quota CPU de l'hébergeur,
l'agent n'appelle que toutes les ~30 s au repos, et toutes les ~4 s quand un admin regarde la
page de contrôle ou qu'un ordre est en attente.

Routes :
  POST /api/agent/sync                    agent  : jeton Bearer (AGENT_TOKEN)
  GET  /api/services/logs?after=<id>      bot Discord : clé API (X-API-Key) ; nouvelles lignes de logs
  GET  /api/services/events?after=<id>    bot Discord : clé API ; ordres start/stop/restart terminés
  GET  /api/services/status               public : état résumé (carte) ; ?watch=1 = page admin ouverte
  GET  /admin/services                    admin  : page de contrôle
  GET  /admin/services/<id>/logs          admin  : dernières lignes de journal (JSON)
  POST /admin/services/<id>/<action>      admin  : start | stop | restart (CSRF) -> ordre en file
"""
import hmac
import json
import os
import time

from flask import Blueprint, jsonify, render_template_string, request, session

from flask_app import ROLE_ADMIN, AGENT_TOKEN, check_role, csrf, get_db, log_to_db, require_api_key
from templates import GLASS_CSS, ADMIN_SERVICES_HTML

services_bp = Blueprint("services", __name__)

IDLE_INTERVAL = int(os.environ.get("AGENT_IDLE_INTERVAL", 30))     # s entre 2 appels au repos
ACTIVE_INTERVAL = int(os.environ.get("AGENT_ACTIVE_INTERVAL", 4))  # s si admin présent / ordre en attente
WATCH_WINDOW = 90                    # s pendant lesquelles "un admin regarde" après son dernier ping
OFFLINE_AFTER = max(IDLE_INTERVAL * 3, 90)   # s sans appel de l'agent => considéré hors ligne
PENDING_TTL = 180                    # s : un ordre non récupéré par l'agent expire
SENT_TTL = 300                       # s : un ordre récupéré sans résultat expire
MAX_BODY = 512 * 1024
ACTIONS = ("start", "stop", "restart")
LOG_HISTORY_MAX = 5000               # lignes conservées au total dans service_log_lines
LOG_API_MAX = 500                    # lignes max renvoyées par appel à /api/services/logs


def _token_ok():
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    return bool(AGENT_TOKEN) and hmac.compare_digest(token.encode(), AGENT_TOKEN.encode())


def _snapshot(db):
    row = db.execute("SELECT data, logs, updated_at, watch_until FROM agent_snapshot WHERE id=1").fetchone()
    try:
        return json.loads(row["data"]), json.loads(row["logs"]), row["updated_at"] or 0, row["watch_until"] or 0
    except Exception:
        return [], {}, 0, 0


def _new_lines(previous, current):
    """Lignes de `current` qui ne figuraient pas déjà dans `previous`. L'agent renvoie à chaque
    appel la fin du journal (fenêtre glissante) : on cherche le plus long suffixe de `previous`
    qui est aussi le début de `current`, tout ce qui suit est nouveau."""
    for k in range(min(len(previous), len(current)), 0, -1):
        if previous[-k:] == current[:k]:
            return current[k:]
    return current


def _expire_stale(db, now):
    """Marque comme expirés les ordres jamais récupérés / sans résultat (appelé à chaque sync
    de l'agent et à chaque lecture du flux d'événements, pour qu'un agent hors ligne ne
    bloque pas les notifications)."""
    db.execute("UPDATE agent_commands SET status='expired', result='non récupéré par l''agent', done_at=? "
               "WHERE status='pending' AND requested_at < ?", (now, now - PENDING_TTL))
    db.execute("UPDATE agent_commands SET status='expired', result='pas de résultat reçu', done_at=? "
               "WHERE status='sent' AND requested_at < ?", (now, now - SENT_TTL))


def _is_admin(db):
    if 'user_id' not in session:
        return False
    u = db.execute("SELECT role, is_banned FROM users WHERE wiki_id=?", (session['user_id'],)).fetchone()
    return bool(u and u['role'] == ROLE_ADMIN and not u['is_banned'])


# ------------------------------------------------------------------
# Côté agent
# ------------------------------------------------------------------

@services_bp.route("/api/agent/sync", methods=["POST"])
@csrf.exempt
def agent_sync():
    if not _token_ok():
        return jsonify(error="unauthorized"), 401
    if request.content_length and request.content_length > MAX_BODY:
        return jsonify(error="trop volumineux"), 413
    body = request.get_json(silent=True) or {}
    services = body.get("services")
    if not isinstance(services, list) or len(services) > 50 or not all(isinstance(s, dict) for s in services):
        return jsonify(error="format invalide"), 400
    logs = body.get("logs") if isinstance(body.get("logs"), dict) else {}
    clean_logs = {str(k)[:40]: [str(l)[:400] for l in v[-150:]] for k, v in logs.items() if isinstance(v, list)}
    results = body.get("results") if isinstance(body.get("results"), list) else []

    db = get_db()
    now = time.time()
    _s, old_logs, _u, _w = _snapshot(db)
    labels = {str(s.get("id")): s.get("label") or str(s.get("id")) for s in services}
    for sid, lines in clean_logs.items():
        fresh = _new_lines(old_logs.get(sid, []), lines)
        if fresh:
            db.executemany("INSERT INTO service_log_lines (service_id, label, ts, line) VALUES (?,?,?,?)",
                           [(sid, labels.get(sid, sid), now, l) for l in fresh])
    db.execute("DELETE FROM service_log_lines WHERE id <= (SELECT MAX(id) FROM service_log_lines) - ?",
               (LOG_HISTORY_MAX,))
    db.execute("UPDATE agent_snapshot SET data=?, logs=?, updated_at=? WHERE id=1",
               (json.dumps(services), json.dumps(clean_logs), now))
    for r in results[:50]:
        if isinstance(r, dict) and isinstance(r.get("id"), int):
            db.execute("UPDATE agent_commands SET status=?, result=?, done_at=? WHERE id=? AND status='sent'",
                       ("done" if r.get("ok") else "failed", str(r.get("message", ""))[:300], now, r["id"]))
    _expire_stale(db, now)

    commands = []
    for row in db.execute("SELECT id, service_id, action, requested_by FROM agent_commands "
                          "WHERE status='pending' ORDER BY id").fetchall():
        # UPDATE conditionnel : deux appels simultanés ne reçoivent jamais le même ordre
        cur = db.execute("UPDATE agent_commands SET status='sent' WHERE id=? AND status='pending'", (row["id"],))
        if cur.rowcount == 1:
            commands.append({"id": row["id"], "service": row["service_id"],
                             "action": row["action"], "by": row["requested_by"]})
    watch_until = db.execute("SELECT watch_until FROM agent_snapshot WHERE id=1").fetchone()[0] or 0
    db.commit()
    active = bool(commands) or watch_until > now or \
        db.execute("SELECT 1 FROM agent_commands WHERE status='sent' LIMIT 1").fetchone() is not None
    return jsonify(commands=commands, interval=ACTIVE_INTERVAL if active else IDLE_INTERVAL)


# ------------------------------------------------------------------
# Côté navigateur
# ------------------------------------------------------------------

PUBLIC_FIELDS = ("id", "label", "description", "running", "health", "health_reason",
                 "uptime_s", "heartbeat_age_s")
ADMIN_FIELDS = PUBLIC_FIELDS + ("desired", "pid", "started_at", "restarts", "crash_count",
                                "last_exit", "last_action", "last_action_by", "autorestart",
                                "cpu_percent", "memory_mb", "errors_last_hour", "last_error")


@services_bp.route("/api/services/status")
def services_status():
    db = get_db()
    admin = _is_admin(db)
    now = time.time()
    if admin and request.args.get("watch") == "1":
        db.execute("UPDATE agent_snapshot SET watch_until=? WHERE id=1", (now + WATCH_WINDOW,))
        db.commit()
    services, _logs, updated_at, _w = _snapshot(db)
    age = now - updated_at if updated_at else None

    if not AGENT_TOKEN:
        reachable, error = False, "Fonction non configurée (AGENT_TOKEN absent du .env)."
    elif age is None:
        reachable, error = False, "L'agent n'a encore jamais contacté le dashboard."
    elif age > OFFLINE_AFTER:
        reachable = False
        error = f"Agent hors ligne (dernier contact il y a {int(age // 60)} min)."
    else:
        reachable, error = True, None
    if not admin and not reachable:
        error = "Serveur distant hors ligne."

    out = []
    if reachable:
        fields = ADMIN_FIELDS if admin else PUBLIC_FIELDS
        # l'âge du heartbeat et l'uptime étaient mesurés à l'envoi : on ajoute le temps écoulé
        out = []
        for s in services:
            item = {k: s.get(k) for k in fields}
            if s.get("running") and item.get("uptime_s") is not None:
                item["uptime_s"] += int(age)
            if item.get("heartbeat_age_s") is not None:
                item["heartbeat_age_s"] += int(age)
            out.append(item)
        if admin:
            cmds = db.execute("SELECT id, service_id, action, status, result FROM agent_commands "
                              "WHERE requested_at > ? ORDER BY id", (now - 600,)).fetchall()
            last, pending = {}, {}
            for c in cmds:
                last[c["service_id"]] = {"id": c["id"], "action": c["action"],
                                         "status": c["status"], "result": c["result"]}
                if c["status"] in ("pending", "sent"):
                    pending[c["service_id"]] = c["action"]
            for item in out:
                item["pending_action"] = pending.get(item["id"])
                item["last_command"] = last.get(item["id"])
    return jsonify(reachable=reachable, error=error, is_admin=admin,
                   last_contact_age_s=int(age) if age is not None else None, services=out)


@services_bp.route("/api/services/logs")
@csrf.exempt
@require_api_key
def api_service_logs():
    """Passerelle vers le bot Discord : lignes de logs des scripts continus arrivées après le
    curseur `after` (id de la dernière ligne déjà vue). `after=latest` ne renvoie aucune ligne,
    seulement le curseur courant (le bot l'utilise au premier démarrage pour ne pas rejouer
    tout l'historique). Réponse : {lines: [{id, service, label, ts, line}], last_id}."""
    db = get_db()
    raw = request.args.get("after", "latest")
    top = db.execute("SELECT COALESCE(MAX(id), 0) FROM service_log_lines").fetchone()[0]
    if raw == "latest":
        return jsonify(lines=[], last_id=top)
    try:
        after = int(raw)
    except ValueError:
        return jsonify(error="paramètre 'after' invalide"), 400
    if after > top:     # curseur d'avant une réinitialisation de la base : on repart du courant
        return jsonify(lines=[], last_id=top, reset=True)
    limit = max(1, min(request.args.get("limit", LOG_API_MAX, type=int), LOG_API_MAX))
    rows = db.execute("SELECT id, service_id, label, ts, line FROM service_log_lines "
                      "WHERE id > ? ORDER BY id LIMIT ?", (after, limit)).fetchall()
    lines = [{"id": r["id"], "service": r["service_id"], "label": r["label"],
              "ts": r["ts"], "line": r["line"]} for r in rows]
    return jsonify(lines=lines, last_id=lines[-1]["id"] if lines else after)


@services_bp.route("/api/services/events")
@csrf.exempt
@require_api_key
def api_service_events():
    """Passerelle vers le bot Discord : ordres start/stop/restart terminés (réussis, échoués ou
    expirés) dont l'id est > `after`. `after=latest` ne renvoie que le curseur courant.
    Les ordres se terminent dans le désordre (deux scripts en parallèle) : on ne renvoie que
    les ids situés avant le plus ancien ordre encore ouvert, pour que le curseur ne saute
    jamais un événement. Réponse : {events: [{id, service, label, action, status, result,
    requested_by, requested_at, done_at}], last_id}."""
    db = get_db()
    _expire_stale(db, time.time())
    db.commit()
    open_id = db.execute("SELECT MIN(id) FROM agent_commands WHERE status IN ('pending','sent')").fetchone()[0]
    top = db.execute("SELECT COALESCE(MAX(id), 0) FROM agent_commands").fetchone()[0]
    upper = (open_id - 1) if open_id else top
    raw = request.args.get("after", "latest")
    if raw == "latest":
        return jsonify(events=[], last_id=upper)
    try:
        after = int(raw)
    except ValueError:
        return jsonify(error="paramètre 'after' invalide"), 400
    if after > top:     # curseur d'avant une réinitialisation de la base
        return jsonify(events=[], last_id=upper, reset=True)
    limit = max(1, min(request.args.get("limit", 50, type=int), 100))
    rows = db.execute("SELECT id, service_id, action, status, result, requested_by, requested_at, done_at "
                      "FROM agent_commands WHERE id > ? AND id <= ? AND status IN ('done','failed','expired') "
                      "ORDER BY id LIMIT ?", (after, upper, limit)).fetchall()
    services, _logs, _u, _w = _snapshot(db)
    labels = {str(s.get("id")): s.get("label") or str(s.get("id")) for s in services}
    events = [{"id": r["id"], "service": r["service_id"], "label": labels.get(r["service_id"], r["service_id"]),
               "action": r["action"], "status": r["status"], "result": r["result"],
               "requested_by": r["requested_by"], "requested_at": r["requested_at"],
               "done_at": r["done_at"] or r["requested_at"]} for r in rows]
    return jsonify(events=events, last_id=events[-1]["id"] if events else after)


@services_bp.route("/admin/services")
@check_role([ROLE_ADMIN])
def admin_services():
    return render_template_string(ADMIN_SERVICES_HTML, glass_css=GLASS_CSS, active='services')


@services_bp.route("/admin/services/<sid>/logs")
@check_role([ROLE_ADMIN])
def service_logs(sid):
    _s, logs, _u, _w = _snapshot(get_db())
    if sid not in logs:
        return jsonify(lines=[], error="Aucun journal reçu pour ce script."), 404
    n = max(1, min(request.args.get("lines", 150, type=int), 150))
    return jsonify(id=sid, lines=logs[sid][-n:])


@services_bp.route("/admin/services/<sid>/<action>", methods=["POST"])
@check_role([ROLE_ADMIN])
def service_action(sid, action):
    if action not in ACTIONS:
        return jsonify(ok=False, message="Action inconnue."), 400
    db = get_db()
    services, _logs, updated_at, _w = _snapshot(db)
    now = time.time()
    if not updated_at or now - updated_at > OFFLINE_AFTER:
        return jsonify(ok=False, message="Agent hors ligne : ordre impossible pour l'instant."), 503
    if sid not in {s.get("id") for s in services}:
        return jsonify(ok=False, message="Service inconnu."), 404
    busy = db.execute("SELECT 1 FROM agent_commands WHERE service_id=? AND status IN ('pending','sent')", (sid,)).fetchone()
    if busy:
        return jsonify(ok=False, message="Un ordre est déjà en cours pour ce script."), 409
    who = session.get('username') or 'admin'
    cur = db.execute("INSERT INTO agent_commands (service_id, action, requested_by, requested_at) VALUES (?,?,?,?)",
                     (sid, action, who, now))
    db.execute("UPDATE agent_snapshot SET watch_until=? WHERE id=1", (now + WATCH_WINDOW,))
    db.commit()
    log_to_db("SYSTEM", f"Service continu '{sid}' : ordre {action} demandé par {who}")
    return jsonify(ok=True, command_id=cur.lastrowid,
                   message="Ordre envoyé, l'agent le prend en compte dans quelques secondes.")
