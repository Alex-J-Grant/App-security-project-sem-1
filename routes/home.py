# auth.py

from flask import Blueprint, render_template, url_for
from extensions import db
from sqlalchemy import text
import os
from helperfuncs.post_likes import has_liked_post
from helperfuncs.email_sender import send_email
from flask_login import current_user
UPLOAD_FOLDER_POST = 'static/images/post_images'

# Define the blueprint
homebp = Blueprint('home', __name__, url_prefix='')


# Routes
@homebp.route('/')
def home():
    query = text("""
           SELECT 
            p.POST_ID AS id,
            p.TITLE AS title,
            p.IMAGE AS image_url,
            p.DESCRIPT,
            u.USERNAME AS username,
            s.NAME AS subcommunity_name,
            s.COMM_PFP AS subcommunity_pfp,
            p.CREATED_AT AS created_at,
            p.LIKE_COUNT AS likes,
            p.COMMENT_COUNT AS comments
            FROM POST p
            JOIN USERS u ON p.USER_ID = u.USER_ID
            JOIN SUBCOMMUNITY s ON p.COMM_ID = s.ID
            ORDER BY p.CREATED_AT DESC;
       """)
    # Execute the query using SQLAlchemy Core
    result = db.session.execute(query)

    # Convert to list of dictionaries
    posts = []
    for row in result:
        posts.append({
            'id': row.id,
            'title': row.title,
            'description': row.DESCRIPT,
            'image_url':  url_for('static', filename=f'images/post_images/{row.image_url}') if row.image_url else None,
            'username': row.username,
            'subcommunity_pfp': url_for('static', filename=f'images/profile_pictures/{row.subcommunity_pfp}') if row.subcommunity_pfp else '/static/images/SC_logo.png',
            'subcommunity_name':row.subcommunity_name,
            'created_at': row.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'likes': row.likes,
            'comments': row.comments,
            'user_liked':has_liked_post(current_user.id,row.id)
        })

    return render_template('home.html', posts=posts)
