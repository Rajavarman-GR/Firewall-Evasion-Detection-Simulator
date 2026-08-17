from flask import Flask
from app.config import Config
from app.extensions import db


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(config_class)
    db.init_app(app)
    from app.routes.web import web
    from app.routes.api import api
    app.register_blueprint(web)
    app.register_blueprint(api, url_prefix="/api")
    with app.app_context():
        db.create_all()
        # SQLite does not alter existing tables during create_all; retain existing data.
        from sqlalchemy import inspect, text
        columns = {column["name"] for column in inspect(db.engine).get_columns("user")}
        if "status" not in columns:
            db.session.execute(text("ALTER TABLE user ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'"))
        if "last_login" not in columns:
            db.session.execute(text("ALTER TABLE user ADD COLUMN last_login DATETIME"))
        db.session.commit()
        from app.seed.default_rules import seed
        seed()
    return app
