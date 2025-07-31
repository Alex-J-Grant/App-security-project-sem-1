from flask import Blueprint, request, jsonify, render_template
from sqlalchemy import text
from extensions import db
import html

search_bp = Blueprint('search', __name__)

def sanitize_query(q: str) -> str:
    return html.escape(q.strip())[:100]  # limit length

@search_bp.route("/search_suggestions")
def search_suggestions():
    q = request.args.get("q", "")
    if not q:
        return jsonify({"users": [], "communities": []})

    q_clean = sanitize_query(q)

    # Use fulltext if available, else fallback to LIKE
    user_stmt = text("""
        SELECT USER_ID, USERNAME, USERPFP,
        MATCH(USERNAME) AGAINST (:q IN NATURAL LANGUAGE MODE) AS score
        FROM USERS
        WHERE MATCH(USERNAME) AGAINST (:q IN NATURAL LANGUAGE MODE)
        ORDER BY score DESC
        LIMIT 3
    """)
    community_stmt = text("""
        SELECT ID, NAME, COMM_PFP,
        MATCH(NAME) AGAINST (:q IN NATURAL LANGUAGE MODE) AS score
        FROM SUBCOMMUNITY
        WHERE MATCH(NAME) AGAINST (:q IN NATURAL LANGUAGE MODE)
        ORDER BY score DESC
        LIMIT 3
    """)
    # Fallback if fulltext not present: use LIKE
    try:
        with db.engine.connect() as conn:
            users = conn.execute(user_stmt, {"q": q_clean}).mappings().all()
            communities = conn.execute(community_stmt, {"q": q_clean}).mappings().all()
    except Exception:
        # Fallback
        like_q = f"%{q_clean}%"
        with db.engine.connect() as conn:
            users = conn.execute(text("""
                SELECT USER_ID, USERNAME, USERPFP
                FROM USERS
                WHERE USERNAME LIKE :like_q
                ORDER BY USERNAME = :exact DESC, USERNAME LIKE :prefix DESC
                LIMIT 3
            """), {"like_q": like_q, "exact": q_clean, "prefix": f"{q_clean}%"}).mappings().all()

            communities = conn.execute(text("""
                SELECT ID, NAME, COMM_PFP
                FROM SUBCOMMUNITY
                WHERE NAME LIKE :like_q
                ORDER BY NAME = :exact DESC, NAME LIKE :prefix DESC
                LIMIT 3
            """), {"like_q": like_q, "exact": q_clean, "prefix": f"{q_clean}%"}).mappings().all()

    # Build response (ensure no raw HTML injection)
    users_out = [{
        "id": u["USER_ID"],
        "username": u["USERNAME"],
        "pfp": "/static/images/profile_pictures/" + u["USERPFP"] if u["USERPFP"] else "/static/images/SC_logo.png"
    } for u in users]

    communities_out = [{
        "id": c["ID"],
        "name": c["NAME"],
        "pfp": "/static/images/profile_pictures/" + c["COMM_PFP"] if c["COMM_PFP"] else "/static/images/default_pfp.jpg"
    } for c in communities]

    return jsonify({"users": users_out, "communities": communities_out})


@search_bp.route("/search")
def search_page():
    q = request.args.get("q", "")
    q_clean = sanitize_query(q)
    users = []
    communities = []
    if q_clean:
        like_q = f"%{q_clean}%"
        with db.engine.connect() as conn:
            users = conn.execute(text("""
                SELECT USER_ID, USERNAME, USERPFP
                FROM USERS
                WHERE USERNAME LIKE :like_q
                ORDER BY USERNAME = :exact DESC, USERNAME LIKE :prefix DESC
                LIMIT 10
            """), {"like_q": like_q, "exact": q_clean, "prefix": f"{q_clean}%"}).mappings().all()

            communities = conn.execute(text("""
                SELECT ID, NAME, COMM_PFP
                FROM SUBCOMMUNITY
                WHERE NAME LIKE :like_q
                ORDER BY NAME = :exact DESC, NAME LIKE :prefix DESC
                LIMIT 10
            """), {"like_q": like_q, "exact": q_clean, "prefix": f"{q_clean}%"}).mappings().all()

    return render_template("search_results.html",
                           query=q_clean,
                           users=users,
                           communities=communities)