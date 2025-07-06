import datetime, traceback
from flask import Flask, request, jsonify, g, current_app
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
    def refresh_expired_access_token():
        """ Refresh the access token via cookie if it's about to expire.

        Returns:
            _type_: _description_
        """
        print("Checking if access token needs to be refreshed...")
        try:
            if "access_token_cookie" not in request.cookies:
                print("No access token cookie found, skipping refresh.")
                return # Skip refresh if no access token cookie is present(unauthenticated requests)
            
            verify_jwt_in_request()
            jwt_data = get_jwt()
            exp_timestamp = jwt_data["exp"]
            now = datetime.datetime.now(datetime.timezone.utc)
            # If this token is going to expire within the next 60 seconds, refresh it now.
            target_timestamp = datetime.datetime.timestamp(now + datetime.timedelta(minutes=59))
            print(f"Current time: {now}, Expiry time: {datetime.datetime.fromtimestamp(exp_timestamp, datetime.timezone.utc)}")
            if exp_timestamp < target_timestamp:
                identity = get_jwt_identity()
                new_access_token = create_access_token(identity=identity)
                g.new_access_token = new_access_token
                print(f"Access token refreshed for user: {identity}")

            
        except NoAuthorizationError:
            # No access_token_cookie = not logged in = skip refresh silently
            current_app.logger.debug(
                f"No access token cookie found for {request.path}, skipping refresh."
            )
            pass
        except (ExpiredSignatureError, InvalidTokenError) as token_error:
            current_app.logger.warning(
                f"JWT refresh failed at {request.path}: {token_error}"
            )
            return jsonify({"msg": "Token invalid or expired"}), 401

        except RuntimeError as jwt_err:
            # This happens if no valid JWT is found—ignore and move on
            current_app.logger.debug(f"No valid token found for {request.path}: {jwt_err}")
            pass

        except Exception as e:
            current_app.logger.error(
                f"Unexpected error during token refresh: {e}\n{traceback.format_exc()}"
            )
            return jsonify({"msg": "Internal server error"}), 500
    
    @app.after_request
    def after_request(response):
        """ After request function to set the new access token cookie if it was refreshed. """
        if hasattr(g, 'new_access_token'):
            print("Setting new access token cookie...")
            set_access_cookies(response, g.new_access_token)
        return response

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5001, debug=True)
