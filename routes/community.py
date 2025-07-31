
from flask import Blueprint, render_template, request, redirect, flash, url_for,abort
from werkzeug.utils import secure_filename
from PIL import Image
import os, uuid, bleach
from forms.communityforms import CreateCommunityForm
from extensions import db
from sqlalchemy import text
from flask_login import login_required

from helperfuncs.validation import allowed_mime_type, virus_check
community = Blueprint('community',__name__,url_prefix='/communities')
create_community = Blueprint('create_community',__name__)

#first is for community banners then community profile pictures
UPLOAD_FOLDERS = ["static/images/community_banners","static/images/profile_pictures"]


ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif'}

# Ensure correct format when saving
format_map = {
                    '.jpg': 'JPEG',
                    '.jpeg': 'JPEG',
                    '.png': 'PNG',
                    '.gif': 'GIF'
                }

@community.route("/<string:subreddit_name>")
def community_route(subreddit_name):
    stmt = text("SELECT * FROM SUBCOMMUNITY WHERE NAME = :name")
    with db.engine.connect() as conn:
        result = conn.execute(stmt, {"name": subreddit_name}).mappings().fetchone()

    if not result:
        abort(404)

    # Prepare community object for template
    community = {
        "name": result["NAME"],
        "description": result["DESCRIPTION"],
        "banner_image": url_for('static', filename=f'images/community_banners/{result["BANNER_IMAGE"]}') if result["BANNER_IMAGE"] else None,
        "icon_image": url_for('static', filename=f'images/profile_pictures/{result["COMM_PFP"]}') if result["BANNER_IMAGE"] else None,
        "tag": result["TAG"],
        "mem_count": result["MEMBER_COUNT"]
    }


    posts = []  # Fetch posts where SUBCOMMUNITY.ID matches
    query = text("""
               SELECT 
                p.POST_ID AS id,
                p.TITLE AS title,
                p.IMAGE AS image_url,
                p.DESCRIPT,
                u.USERNAME AS username,
                u.USERPFP as user_pfp,
                s.NAME AS subcommunity_name,
                s.COMM_PFP AS subcommunity_pfp,
                p.CREATED_AT AS created_at,
                p.LIKE_COUNT AS likes,
                p.COMMENT_COUNT AS comments
                FROM POST p
                JOIN USERS u ON p.USER_ID = u.USER_ID
                JOIN SUBCOMMUNITY s ON p.COMM_ID = s.ID
                WHERE s.NAME = :subreddit_name
                ORDER BY p.CREATED_AT DESC;
           """)
    result = db.session.execute(query,{'subreddit_name':subreddit_name})

    for row in result:
        posts.append({
            'id': row.id,
            'title': row.title,
            'description': row.DESCRIPT,
            'image_url':  url_for('static', filename=f'images/post_images/{row.image_url}') if row.image_url else None,
            'username': row.username,
            'user_pfp': row.user_pfp if row.user_pfp else "/static/images/2903-default-blue.jpg",
            'subcommunity_pfp': url_for('static', filename=f'images/profile_pictures/{row.subcommunity_pfp}') if row.subcommunity_pfp else '/static/images/SC_logo.png',
            'created_at': row.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'likes': row.likes,
            'comments': row.comments
        })
    # Execute the query using SQLAlchemy Core



    return render_template("community.html", community=community, posts=posts)



@create_community.route("/create_community", methods=["GET", "POST"])
@login_required
def create_community_route():
    form = CreateCommunityForm()
    if form.validate_on_submit():
        # Sanitize inputs
        name = bleach.clean(form.name.data.strip(), tags=[], strip=True)
        description = bleach.clean(form.description.data.strip(), tags=[], strip=True)
        tag = bleach.clean(form.tag.data.strip(), tags=[], strip=True)
        banner_file = form.banner_image.data
        icon_file = form.icon_image.data



        #put them into loop so i can repeat meta data removal
        file_list = [banner_file,icon_file]
        #Store file names for uploading to sql
        file_names = []
        #for storing file paths incase of sql error so i can delete the files
        saved_file_paths = []

        #ensure that if there is an error then no files are still inside the server
        try:
            for index,image_file in enumerate(file_list):
                orig_filename = image_file.filename
                ext = os.path.splitext(orig_filename)[1].lower()  # e.g., '.png'

                if ext not in ['.png', '.jpg', '.jpeg', '.gif']:
                    flash('Please upload image files only2', 'danger')
                    return render_template('create_community.html', form=form)

                # Strip metadata in-memory
                with Image.open(image_file.stream) as img:
                    data = img.getdata()
                    clean_img = Image.new(img.mode, img.size)
                    clean_img.putdata(data)



                    filename = uuid.uuid4().hex + ext
                    file_names.append(filename)
                    filepath = os.path.join(UPLOAD_FOLDERS[index], filename)
                    clean_img.save(filepath, format=format_map[ext])
                    saved_file_paths.append(filepath)


            # Insert into DB
            stmt = text("""
                INSERT INTO SUBCOMMUNITY (ID, NAME,DESCRIPTION,COMM_PFP,BANNER_IMAGE,TAG)
                VALUES (:id, :name, :desc, :icon, :banner, :tag)
            """)
            with db.engine.connect() as conn:
                conn.execute(stmt, {
                    "id": str(uuid.uuid4()),
                    "name": name,
                    "desc": description,
                    "banner": file_names[0],
                    "icon": file_names[1],
                    "tag": tag
                })
                conn.commit()

            flash("Community created successfully", "success")
            return redirect(url_for("home.home"))
        except Exception as e:
            #log it later
            print(e)
            # Delete saved files
            for path in saved_file_paths:
                if os.path.exists(path):
                    os.remove(path)
            flash("Sorry something went wrong please try again later.", "danger")


    return render_template("create_community.html", form=form)