import re
import jsonschema
from flask import jsonify, request
from flask_wtf.csrf import generate_csrf
from flask_login import login_user, current_user, logout_user
from app import app, db
from app.models import User, Role, Post
from . import paginate_results
from .forms import LoginForm, RegistrationForm, PostForm

# Define request schemas
LOGIN_SCHEMA = {
    "type": "object",
    "properties": {
        "email": {"type": "string", "format": "email"},
        "password": {"type": "string"},
        "remember_me": {"type": "boolean"}
    },
    "required": ["email", "password"]
}

REGISTRATION_SCHEMA = {
    "type": "object",
    "properties": {
        "email": {"type": "string", "format": "email"},
        "password": {"type": "string", "minLength": 8},
        "role_id": {"type": "integer"}
    },
    "required": ["email", "password", "role_id"]
}

USER_SCHEMA = {
    "type": "object",
    "properties": {
        "email": {"type": "string", "format": "email"},
        "role_id": {"type": "integer"}
    },
    "required": ["email", "role_id"]
}


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


@app.route('/register/<int:role_id>', methods=['POST'])
def create_user(role_id):
    # Get the request data in JSON format
    data = request.get_json()

    # Validate the request data against the JSON schema
    try:
        jsonschema.validate(data, REGISTRATION_SCHEMA)
    except jsonschema.exceptions.ValidationError as e:
        return jsonify({'error': str(e)}), 400

    # Check if a user with the same email already exists in the database
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'error': 'A user with that email already exists.'}), 409

    # Create a new User object with the email and role_id parameters
    user = User(email=data['email'], role_id=role_id)

    # Set the user's password and hash it before storing it in the database
    user.set_password(data['password'])

    # Add the user object to the database session and commit it to the database
    db.session.add(user)
    db.session.commit()

    # Return the new user's data, including their ID
    return jsonify({'id': user.id, 'email': user.email, 'role_id': user.role_id}), 201


@app.route('/users', methods=['GET'])
def get_all_users():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)
    users = User.query.paginate(page=page, per_page=per_page, error_out=False)
    user_list = []
    for user in users.items:
        user_list.append({
            'id': user.id,
            'email': user.email,
            'role_id': user.role_id
        })
    return jsonify(user_list)


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
    return jsonify({'id': role.id, 'name': role.name}), 201



@app.route('/posts/<int:author_id>', methods=['POST'])
def create_post(author_id):
    # Get the request data in JSON format
    data = request.get_json()

    # Extract the required parameters from the request data
    title = data.get('title')
    description = data.get('description')

    # Check if any of the required parameters are missing
    if not title or not description:
        return jsonify({'error': 'Missing required parameter.'}), 400

    # Create a new Post object with the title, description, and author_id parameters
    post = Post(author_id=author_id, title=title, description=description)

    # Add the post object to the database session and commit it to the database
    db.session.add(post)
    db.session.commit()

    # Return a success message and the new post's data, including its ID
    return jsonify({'author_id': post.author_id, 'title': post.title, 'description': post.description}), 201


@app.route('/posts/author/<int:author_id>', methods=['GET'])
def get_posts_by_author(author_id):
    user = User.query.get(author_id)
    if not user:
        return jsonify({'error': 'User is not registered with this id'}), 404

    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)
    posts = Post.query.filter_by(author_id=author_id).paginate(page=page, per_page=per_page, error_out=False)

    if not posts.total:
        return jsonify({'error': 'No posts found for this author'}), 404

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


# All posts route
@app.route('/posts', methods=['GET'])
def get_all_posts():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)
    posts = Post.query.paginate(page=page, per_page=per_page, error_out=False)
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
