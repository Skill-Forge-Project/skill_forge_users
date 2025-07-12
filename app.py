import datetime, traceback
from flask import Flask, request, jsonify, g, current_app, make_response
from flask_cors import CORS
from config import Config
from extensions import db, jwt, migrate
from jwt import ExpiredSignatureError, InvalidTokenError
from flask_jwt_extended.exceptions import NoAuthorizationError
from flask_jwt_extended import (
    verify_jwt_in_request,
    get_jwt,
    set_access_cookies,
    get_jwt_identity,
    decode_token,
    create_access_token
)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, supports_credentials=True, origins=["http://localhost:5173"])
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)

    from routes import users_bp
    from user_progress_routes import users_progress
    app.register_blueprint(users_bp)
    app.register_blueprint(users_progress)

    with app.app_context():
        db.create_all()
    
    @app.before_request
    def check_access_token():
        """Check if the access token is valid and not expired.

        """
        print("🔍 Checking access token validity...")
        try:
            verify_jwt_in_request()
            jwt_data = get_jwt()
            exp_timestamp = jwt_data["exp"]
            now = datetime.datetime.now(datetime.timezone.utc)
            target_timestamp = datetime.datetime.timestamp(now + datetime.timedelta(minutes=29))
            print(f"🔗 Current time: {now}, Expiration time: {datetime.datetime.fromtimestamp(exp_timestamp, datetime.timezone.utc)}")
            print(f"⏳ Target timestamp for refresh: {datetime.datetime.fromtimestamp(target_timestamp, datetime.timezone.utc)}")
            if exp_timestamp < target_timestamp:
                print("🔄 Access token is about to expire, setting needs_refresh flag.")
                g.needs_refresh = True
                g.identity = get_jwt_identity()
        except ExpiredSignatureError:
            print("⏰ Access token has expired, attempting refresh...")

            try:
                verify_jwt_in_request(refresh=True)
                identity = get_jwt_identity()
                new_access_token = create_access_token(identity=identity)

                # Create a dummy response just to set the cookie
                response = make_response()
                set_access_cookies(response, new_access_token)

                print(f"🔁 Refreshed access token for user: {identity}")
                return response  # This will short-circuit the request and return early

            except Exception as e:
                print("❌ Failed to refresh access token:", e)
                return jsonify({"msg": "Session expired"}), 401
        except Exception:
            g.needs_refresh = False
    
    @app.after_request
    def maybe_refresh_token(response):
        print("🔁 Checking if token refresh is needed after request...")
        if getattr(g, "needs_refresh", False):
            try:
                # Use refresh token to get new access token
                # verify_jwt_in_request(refresh=True)
                # identity = get_jwt_identity()
                # new_access_token = create_access_token(identity=identity)
                # set_access_cookies(response, new_access_token)
                print(f"🔁 Refreshed access token for user:")
            except Exception as e:
                current_app.logger.warning(f"Failed to refresh token: {e}")
                # Optionally clear cookies or return 401
        return response

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5001, debug=True)
