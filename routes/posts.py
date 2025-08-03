
import os
import uuid
from flask import Blueprint, render_template, request, redirect, flash, url_for, session,jsonify
from flask_login import login_required,current_user
from extensions import db
from wtforms import ValidationError
from forms.postforms import PostForm
from sqlalchemy import text
from PIL import Image
from helperfuncs.post_likes import like_post,unlike_post
import bleach
from flask_login import login_required,current_user
from rate_limiter_config import limiter
UPLOAD_FOLDER_POST = 'static/images/post_images'

view_post = Blueprint('view_post', __name__, url_prefix='/view_post')
create_post = Blueprint('create_post',__name__)
like_bp = Blueprint("like", __name__)  # register this in create_app
@view_post.route('/<post_id>')
def view_post_route(post_id):
    query = text("""
        SELECT 
            p.POST_ID AS id,
            p.TITLE AS title,
            p.IMAGE AS image_url,
            p.DESCRIPT,
            u.USERPFP as userpfp,
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
        'userpfp': result.userpfp if result.userpfp else '/static/images/default_pfp.jpg',
        'subcommunity_pfp': url_for('static', filename=f'images/profile_pictures/{result.subcommunity_pfp}') if result.subcommunity_pfp else '/static/images/SC_logo.png',
        'subcommunity_name': result.subcommunity_name,
        'created_at': result.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'likes': result.likes,
        'comments': result.comments
    }
    return render_template('inside_post.html', post=post, back_url = request.referrer)


@create_post.route('/upload_post', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@login_required
def upload_post():
    form = PostForm()
    with db.engine.connect() as conn:
        result = conn.execute(text("SELECT ID, NAME FROM SUBCOMMUNITY")).fetchall()
        form.community.choices = [(row[0], row[1]) for row in result]

    if form.validate_on_submit():
        userid = current_user.id
        title = bleach.clean(form.title.data.strip(), tags=[], strip=True)
        description = bleach.clean(form.description.data.strip(), tags=[], strip=True)
        comm_id = bleach.clean(form.community.data.strip(), tags=[], strip=True)
        image_file = form.image.data



        try:
            #get the file extension
            orig_filename = image_file.filename
            ext = os.path.splitext(orig_filename)[1].lower()  # e.g., '.png'

            #if somehow got past everything else
            if ext not in ['.png', '.jpg', '.jpeg', '.gif']:
                flash('Please upload image files only', 'danger')
                return render_template('upload_post.html', form=form)

            # Strip metadata in-memory
            with Image.open(image_file.stream) as img:
                data = img.getdata()
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(data)

                # Ensure correct format when saving
                format_map = {
                    '.jpg': 'JPEG',
                    '.jpeg': 'JPEG',
                    '.png': 'PNG',
                    '.gif': 'GIF'
                }

                filename = uuid.uuid4().hex + ext
                filepath = os.path.join(UPLOAD_FOLDER_POST, filename)
                clean_img.save(filepath, format=format_map[ext])

            # Insert into DB using parameterized query
            stmt = text("""
                INSERT INTO POST (POST_ID, USER_ID, COMM_ID, TITLE, IMAGE, DESCRIPT)
                VALUES (:post_id, :user_id, :comm_id, :title, :image, :description)
            """)
            with db.engine.connect() as conn:
                conn.execute(stmt, {
                    "post_id": str(uuid.uuid4()),
                    "user_id": userid,
                    "comm_id": comm_id ,
                    "title": title,
                    "image": filename,
                    "description": description
                })
                conn.commit()

            flash("Post uploaded successfully", "success")
            return redirect(url_for('home.home'))
        except Exception as e:
            #log later
            print(e)
            # Delete saved files
            if os.path.exists(filepath):
                os.remove(filepath)
            flash("Sorry something went wrong please try again later.", "danger")

    return render_template('upload_post.html', form=form)




@like_bp.route("/post/<post_id>/like", methods=["POST"])
@login_required
def toggle_like(post_id):
    action = request.form.get("action")  # "like" or "unlike"
    if action not in ("like", "unlike"):
        return jsonify({"error": "invalid action"}), 400

    user_id = current_user.id
    if action == "like":
        new_count = like_post(user_id, post_id)
        if new_count is None:
            # already liked
            return jsonify({"liked": True, "like_count": get_like_count(post_id)})
        return jsonify({"liked": True, "like_count": new_count})
    else:  # unlike
        new_count = unlike_post(user_id, post_id)
        if new_count is None:
            # wasn't liked
            return jsonify({"liked": False, "like_count": get_like_count(post_id)})
        return jsonify({"liked": False, "like_count": new_count})

def get_like_count(post_id):
    stmt = text("SELECT LIKE_COUNT FROM POST WHERE POST_ID = :pid")
    with db.engine.connect() as conn:
        row = conn.execute(stmt, {"pid": post_id}).first()
    return row["LIKE_COUNT"] if row else 0
