from functools import wraps
from flask import make_response
import jsonschema
from email_validator import validate_email, EmailNotValidError
from flask import jsonify, request
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.exceptions import BadRequest, Unauthorized

from . import app, db, login_manager
from .models import User, Role, Post, PostSharedUsers


@app.route('/protected')
@jwt_required
def protected():
    current_user_id = get_jwt_identity()
    return jsonify(logged_in_as=current_user_id), 200


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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


def validate_request(schema):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            data = request.get_json()
            try:
                jsonschema.validate(data, schema)
            except jsonschema.exceptions.ValidationError as e:
                raise BadRequest(description=str(e))

            try:
                # Validate email format using email-validator library
                valid = validate_email(data['email'])
                data['email'] = valid.email
            except EmailNotValidError as e:
                raise BadRequest(description=str(e))

            return func(*args, **kwargs)

        return wrapper

    return decorator


@app.route('/register/<int:role_id>', methods=['POST'])
@validate_request(REGISTRATION_SCHEMA)
def create_user(role_id):
    data = request.get_json()

    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        raise BadRequest(description='A user with that email already exists.')

    user = User(email=data['email'], role_id=role_id)
    user.set_password(data['password'])

    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=user.id)

    # Include user data in response
    response = {
        'access_token': access_token,
        'user': {
            'id': user.id,
            'email': user.email,
            'role_id': user.role_id
        }
    }

    return jsonify(response), 201


@app.route('/login', methods=['POST'])
@validate_request(LOGIN_SCHEMA)
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        raise Unauthorized(description='Invalid email or password.')
    login_user(user)
    access_token = create_access_token(identity=user.id)
    response = make_response(jsonify({'message': 'Login successful.'}))
    response.headers['Authorization'] = f'Bearer {access_token}'
    return response, 200


# All users route
@app.route('/users', methods=['GET'])
def get_all_users():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=30, type=int)
    users = User.query.paginate(page=page, per_page=per_page, error_out=False)
    user_list = []
    for user in users.items:
        user_list.append({
            'id': user.id,
            'email': user.email,
            'role_id': user.role_id
        })
    return jsonify(user_list)


# Logout route
@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        return {"message": "Logged out successfully"}, 200
    else:
        return {"message": "Not logged in"}, 401


# Create role route
@app.route('/roles', methods=['POST'])
def create_role():
    name = request.json.get('name')
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    role = Role(name=name)
    db.session.add(role)
    db.session.commit()
    return jsonify({'id': role.id, 'name': role.name}), 201


# Create post route
@app.route('/posts/<int:author_id>', methods=['POST'])
def create_post(author_id):
    data = request.get_json()

    title = data.get('title')
    description = data.get('description')

    if not title or not description:
        return jsonify({'error': 'Missing required parameter.'}), 400

    post = Post(author_id=author_id, title=title, description=description)

    db.session.add(post)
    db.session.commit()

    # Return a success message and the new post's data, including its ID

    return jsonify(
        {'id': post.id, 'author_id': post.author_id, 'title': post.title, 'description': post.description}), 201


def paginate_results(posts, post_list):
    return {
        'page': posts.page,
        'per_page': posts.per_page,
        'total': posts.total,
        'pages': posts.pages,
        'items': post_list
    }


@app.route('/posts/author/<int:author_id>', methods=['GET'])
def get_posts_by_author(author_id):
    user = User.query.get(author_id)
    if not user:
        return jsonify({'error': 'User is not registered with this id'}), 404

    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=30, type=int)
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
    per_page = request.args.get('per_page', default=20, type=int)
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


@app.route('/share_post/<int:post_id>/<int:user_id>', methods=['POST'])
@login_required
def share_post(post_id, user_id):
    if request.method != 'POST':
        return jsonify({'error': 'Method not allowed'}), 405

    post = Post.query.filter_by(id=post_id, author_id=user_id).first()

    if not post:
        return jsonify({'error': 'Invalid post ID or user ID'}), 400

    if current_user.id == user_id:
        return jsonify({'error': 'You cannot share your own post'}), 403

    # Create a new PostSharedUsers object and set its attributes
    shared_post = PostSharedUsers(
        post_id=post.id,
        user_id=current_user.id,
        title=post.title,
        description=post.description,
        updated_at=post.updated_at,
        created_at=post.created_at
    )

    # Add the new PostSharedUsers object to the database session and commit the changes
    db.session.add(shared_post)
    db.session.commit()

    return jsonify({'message': f'Post shared with user ID {user_id}.'})


@app.route('/shared_posts/<int:user_id>', methods=['GET'])
@login_required
def shared_posts(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Invalid user ID'}), 400

    shared_posts = user.shared_posts.all()
    if not shared_posts:
        return jsonify({'message': 'This user has not shared any posts.'}), 404

    return jsonify({'posts': [post.to_dict() for post in shared_posts]}), 200
