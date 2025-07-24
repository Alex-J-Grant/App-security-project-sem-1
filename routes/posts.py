from flask import *
import os
import uuid
from flask import Blueprint, render_template, request, redirect, flash, url_for, session
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length
from extensions import db
from wtforms import ValidationError
from forms.postforms import PostForm
from sqlalchemy import text

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER_POST = 'static/images/post_images'

view_post = Blueprint('view_post', __name__, url_prefix='/view_post')
community = Blueprint('community',__name__,url_prefix='/communities')
create_post = Blueprint('create_post',__name__)

@view_post.route('/<post_id>')
def view_post_route(post_id):
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
        WHERE p.POST_ID = :post_id
        ORDER BY p.CREATED_AT DESC
    """)

    result = db.session.execute(query, {'post_id': post_id}).fetchone()

    if not result:
        return render_template("404.html"), 404

    post = {
        'id': result.id,
        'title': result.title,
        'description': result.DESCRIPT,
        'image_url':  url_for('static', filename=f'images/post_images/{result.image_url}') if result.image_url else None,
        'username': result.username,
        'subcommunity_pfp': url_for('static', filename=f'images/post_images/{result.subcommunity_pfp}') if result.subcommunity_pfp else '/static/images/SC_logo.png',
        'created_at': result.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'likes': result.likes,
        'comments': result.comments
    }
    return render_template('inside_post.html', post=post, back_url = request.referrer)


@community.route("/<string:subreddit_name>")
def community_route(subreddit_name):
    # db = get_db_connection()
    # cursor = db.cursor(dictionary=True)
    #
    # # Get subreddit info
    # cursor.execute("SELECT * FROM subreddits WHERE name = %s", (subreddit_name,))
    # subreddit = cursor.fetchone()
    # if not subreddit:
    #     abort(404, "Subreddit not found.")
    #
    # # Get posts from that subreddit
    # cursor.execute("""
    #     SELECT posts.*, users.username, users.avatar_url
    #     FROM posts
    #     JOIN users ON posts.user_id = users.id
    #     WHERE posts.subreddit_id = %s
    #     ORDER BY posts.created_at DESC
    # """, (subreddit["id"],))
    # posts = cursor.fetchall()
    #
    # db.close()
    community = {
        "name": "cybersec",
        "title": "Cybersecurity",
        "description": "Discuss threats, exploits, malware, and red/blue team ops.",
        "banner_image": "images/John_Placeholder.png",
        "icon_image": "images/John_Placeholder.png"
    }

    posts = [
            {
                'id': 1,
                "username": "infosec_nerd",
                "avatar_url": "images/avatars/user1.png",
                "title": "Found a new XSS payload",
                "description": "Check this out: `<img src=x onerror=alert(1)>`",
                "image_url": None,
                "created_at": "2025-07-21 10:20:00",
                "likes": 23,
                "comments": 5,
            },
            {
                'id': 7,
                "username": "packet_sniffer",
                "avatar_url": "images/avatars/user2.png",
                "title": "PCAP analysis of the latest attack",
                "description": "I uploaded some screenshots of malicious DNS tunneling.",
                "image_url": "images/posts/pcap.png",
                "created_at": "2025-07-21 08:12:00",
                "likes": 45,
                "comments": 12,
            }
        ]
    return render_template("community.html", community=community, posts=posts)



@create_post.route('/upload_post', methods=['GET', 'POST'])
def upload_post():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data.strip()
        description = form.description.data.strip()
        image_file = form.image.data

        filename = None

        filename = uuid.uuid4().hex
        filepath = os.path.join(UPLOAD_FOLDER_POST, filename)
        image_file.save(filepath)


        # Insert into DB using parameterized query
        stmt = text("""
            INSERT INTO POST (POST_ID, USER_ID, COMM_ID, TITLE, IMAGE,DESCRIPT)
            VALUES (:post_id, :user_id, :comm_id, :title, :image, :description)
        """)
        with db.engine.connect() as conn:
            conn.execute(stmt, {
                "post_id": str(uuid.uuid4()),
                "user_id": 'user-1',
                "comm_id": "comm-1",  # Replace with actual logic
                "title": title,
                "image": filename,
                "description":description
            })
            conn.commit()

        flash("Post uploaded successfully", "success")
        return redirect(url_for('home.home'))  # or wherever you want
    return render_template('upload_post.html', form=form)