# auth.py

from flask import Blueprint, render_template

# Define the blueprint
homebp = Blueprint('home', __name__, url_prefix='')

# Routes
@homebp.route('/')
def home():
    # Connect to SQLite or your SQL backend
    # conn = sqlite3.connect('database/posts.db')
    # conn.row_factory = sqlite3.Row  # Enables dict-style access
    #
    # cursor = conn.cursor()
    # cursor.execute("SELECT * FROM posts ORDER BY created_at DESC")
    # posts = cursor.fetchall()
    # conn.close()

    posts = [
        {
            'id': 1,
            'title': 'Exploring AI',
            'description': '<h1>Hello</h1>',
            'image_url': 'images/John_Placeholder.png',
            'username': 'alexj',
            'avatar_url': 'images/John_Placeholder.png',
            'created_at': '2025-07-20 14:32:00',
            'likes': 34,
            'comments': 12
        },
        {
            'id': 7,
            'title': 'test',
            'description': 'test content here...',
            'image_url': '',
            'username': 'alexj',
            'avatar_url': 'images/John_Placeholder.png',
            'created_at': '2025-07-20 14:32:00',
            'likes': 400,
            'comments': 123
        }

    ]

    return render_template('home.html', posts=posts)


