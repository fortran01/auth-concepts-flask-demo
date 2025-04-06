import json
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for

# Load environment variables from .env file
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY", "your-secret-key")

# Auth0 configuration
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=(
        f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
    ),
)

# Routes
@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user", {}), indent=4),
    )

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    # Get the access token
    token = oauth.auth0.authorize_access_token()
    
    # Use the token to get user information from Auth0's userinfo endpoint
    userinfo = token.get('userinfo')
    if not userinfo:
        # If userinfo is not in the token response, fetch it separately
        resp = oauth.auth0.get('userinfo')
        userinfo = resp.json()
        token['userinfo'] = userinfo
    
    # Store the user information in the session
    session["user"] = token
    
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@app.route("/profile")
def profile():
    if session.get("user"):
        return render_template(
            "profile.html",
            session=session.get("user"),
            pretty=json.dumps(session.get("user", {}), indent=4),
        )
    return redirect("/login")

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(env.get("PORT", 3000)),
        debug=True
    ) 