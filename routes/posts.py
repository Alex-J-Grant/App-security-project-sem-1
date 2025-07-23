from flask import *


view_post = Blueprint('view_post', __name__, url_prefix='')
community = Blueprint('community',__name__,url_prefix='')

@view_post.route('/view_post/<int:post_id>')
def view_post_route(post_id):

    #once got db then get post based on id

    post = {
            'id': post_id,
            'title': 'Exploring AI',
            'description': '<h1>Hello</h1>',
            'image_url': 'images/John_Placeholder.png',
            'username': 'alexj',
            'avatar_url': 'images/John_Placeholder.png',
            'created_at': '2025-07-20 14:32:00',
            'likes': 34,
            'comments': 12
        }


    return render_template('inside_post.html', post=post, back_url = request.referrer)


@community.route("/communities/<string:subreddit_name>")
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