from flask import Flask
from config import Config
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from app .pagination import paginate_results

app = Flask(__name__)

app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db, compare_type=True)
login_manager = LoginManager(app)

jwt = JWTManager(app)
from app import routes, models