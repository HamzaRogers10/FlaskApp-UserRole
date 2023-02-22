import re
from flask_wtf.csrf import generate_csrf
from flask_login import login_user, current_user, logout_user
from app import app, db
from app.models import User, Role, Post
from . import paginate_results
from .forms import LoginForm, RegistrationForm, PostForm
from flask import jsonify, request


@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return {"message": "Login successful"}, 200
        else:
            return {"message": "Invalid username or password"}, 401
    else:
        errors = form.errors
        return {"errors": errors}, 422


@app.route('/register', methods=['POST'])
def create_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    role_id = data.get('role_id')

    if not email or not password or not role_id:
        return jsonify({'error': 'Missing required parameter.'}), 400

    # Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'error': 'Invalid email format.'}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'A user with that email already exists.'}), 409

    user = User(email=email, role_id=role_id)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'success': 'User created successfully.'}), 201


@app.route('/csrf_token')
def get_csrf_token():
    token = generate_csrf()
    return {"csrf_token": token}, 200


@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        return {"message": "Logged out successfully"}, 200
    else:
        return {"message": "Not logged in"}, 401


@app.route('/roles', methods=['POST'])
def create_role():
    name = request.json.get('name')
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    role = Role(name=name)
    db.session.add(role)
    db.session.commit()
    return jsonify({'message': 'Role created successfully'}), 201


# Post creation route
@app.route('/posts', methods=['POST'])
def create_post():
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    author_id = data.get('author_id')

    if not title or not description or not author_id:
        return jsonify({'error': 'Missing required parameter.'}), 400

    post = Post(title=title, description=description, author_id=author_id)
    db.session.add(post)
    db.session.commit()

    return jsonify({'success': 'Post created successfully.'}), 201


@app.route('/posts/author/<int:author_id>', methods=['GET'])
def get_posts_by_author(author_id):
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)
    posts = Post.query.filter_by(author_id=author_id).paginate(page=page, per_page=per_page, error_out=False)
    post_list = []
    for post in posts.items:
        post_list.append({
            'id': post.id,
            'title': post.title,
            'description': post.description,
            'author_id': post.author_id,
            'created_at': post.created_at,
            'updated_at': post.updated_at
        })
    return jsonify(paginate_results(posts, post_list)), 200
