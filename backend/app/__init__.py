import os
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
from .db import db
from .routes import bp as api_bp

# load .env (if exists)
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
env_path = os.path.join(basedir, ".env")
load_dotenv(env_path)

def build_db_uri():
    # if DB_USER is present we assume MySQL connection desired
    db_user = os.getenv("DB_USER")
    if db_user:
        db_pass = os.getenv("DB_PASS", "")
        db_host = os.getenv("DB_HOST", "127.0.0.1")
        db_port = os.getenv("DB_PORT", "3306")
        db_name = os.getenv("DB_NAME", "fintech_sim")
        # prefer explicit engine if provided, otherwise use mysql+pymysql
        engine = os.getenv("DB_ENGINE", "mysql+pymysql")
        return f"{engine}://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}?charset=utf8mb4"
    # fallback to sqlite for convenience
    return "sqlite:///fintech_sim.db"

def create_app():
    app = Flask(__name__, static_folder=None)
    app.config.from_mapping({
        "SQLALCHEMY_DATABASE_URI": build_db_uri(),
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SECRET_KEY": os.getenv("SECRET_KEY", "dev-secret"),
    })

    # init extensions
    db.init_app(app)
    CORS(app, resources={r"/*": {"origins": "*"}})

    # register routes
    app.register_blueprint(api_bp, url_prefix="")

    # create tables
    with app.app_context():
        db.create_all()

    return app
