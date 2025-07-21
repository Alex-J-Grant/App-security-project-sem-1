from flask import *


view_post = Blueprint('view_post', __name__, url_prefix='')


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


    return render_template('inside_post.html', post=post)
