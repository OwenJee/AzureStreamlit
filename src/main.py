import streamlit as st
from msal import ConfidentialClientApplication, SerializableTokenCache
import os
from dotenv import load_dotenv
import time
import requests
import sqlite3
from datetime import datetime, timedelta
import uuid
from cryptography.fernet import Fernet
import yaml

# Load environment variables from .env file
load_dotenv()
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY").encode()

with open("/workspaces/AzureStreamlit/config.yaml", "r") as config_file:
    config = yaml.safe_load(config_file)

CLIENT_ID = config["CLIENT_ID"]
TENANT_ID = config["TENANT_ID"]
REDIRECT_URI = config["REDIRECT_URI"]

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"


# Setting cache manually since Streamlit refreshes and resets cache in msal_app
cache = SerializableTokenCache()
msal_app = ConfidentialClientApplication(
    CLIENT_ID,
    CLIENT_SECRET,
    authority=AUTHORITY,
    token_cache=cache
)

cipher_suite = Fernet(ENCRYPTION_KEY)


def authenticate():
    """Authenticate user via Microsoft SSO."""
    auth_url = msal_app.get_authorization_request_url(
        ["User.Read"], redirect_uri=REDIRECT_URI)
    st.link_button("Login with Microsoft", auth_url)


def logout():
    """Clear session and logout user."""
    st.session_state.pop("user", None)
    st.session_state.pop("session_id", None)
    st.session_state.pop("msal_cache", None)
    st.session_state.pop("token_expiration", None)
    st.success("Logged out successfully!")
    time.sleep(2)
    st.rerun()


def save_session(session_id, email):
    """Save user session in database."""
    conn = sqlite3.connect("user_sessions.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sessions (session_id, email, login_time) VALUES (?, ?, ?)",
        (session_id, email, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def log_usage(email, action, session_id):
    """Log user actions in the database."""
    conn = sqlite3.connect("user_sessions.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO usage (timestamp, email, action, session_id) VALUES (?, ?, ?, ?)",
        (datetime.now().isoformat(), email, action, session_id),
    )
    conn.commit()
    conn.close()


def check_session_timeout():
    """Auto-logout user if inactive for too long."""
    if "last_activity" in st.session_state:
        now = datetime.now()
        last_active = st.session_state["last_activity"]
        if (now - last_active).seconds > 900:  # 15 minutes
            st.warning("Session timed out.")
            logout()
    st.session_state["last_activity"] = datetime.now()


def save_refresh_token(email, refresh_token):
    """Save refresh token in the database."""
    encrypted_refresh_token = cipher_suite.encrypt(refresh_token.encode())
    conn = sqlite3.connect("user_sessions.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO tokens (email, refresh_token) VALUES (?, ?)",
        (email, encrypted_refresh_token),
    )
    conn.commit()
    conn.close()


def get_refresh_token(email):
    """Retrieve refresh token from the database."""
    conn = sqlite3.connect("user_sessions.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT refresh_token FROM tokens WHERE email = ?",
        (email,)
    )
    token_data = cursor.fetchone()
    conn.close()

    if token_data:
        return cipher_suite.decrypt(token_data[0]).decode()
    return None


def refresh_access_token():
    """Refresh the access token using the refresh token."""
    email = st.session_state["user"]["email"]

    # First, try acquiring a token silently
    msal_app.token_cache.deserialize(st.session_state["msal_cache"])
    accounts = msal_app.get_accounts()
    account = accounts[0] if accounts else None
    result = msal_app.acquire_token_silent(
        ["User.Read"], account)

    if not result:
        # If no valid token exists, use the refresh token
        refresh_token = get_refresh_token(email)
        if refresh_token:
            result = msal_app.acquire_token_by_refresh_token(
                refresh_token, scopes=["User.Read"]
            )

    if result and "access_token" in result:
        st.session_state["user"]["token"] = result["access_token"]
        st.session_state["token_expiration"] = datetime.now(
        ) + timedelta(seconds=result["expires_in"])
    else:
        st.error("Failed to refresh token. Please log in again.")
        logout()


def get_user_info(token):
    """Fetch user details from Microsoft Graph API."""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(
        "https://graph.microsoft.com/v1.0/me", headers=headers)
    return response.json() if response.status_code == 200 else None


def create_tables():
    """Create necessary tables in the database."""
    conn = sqlite3.connect("user_sessions.db")
    cursor = conn.cursor()
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS usage
        (timestamp TEXT, email TEXT, action TEXT, session_id TEXT)"""
    )
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS sessions
        (session_id TEXT PRIMARY KEY, email TEXT, login_time TEXT)"""
    )
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS tokens
        (email TEXT PRIMARY KEY, refresh_token BLOB)"""
    )
    conn.close()


def handle_auth_code(auth_code):
    """Handle the authentication code."""
    result = msal_app.acquire_token_by_authorization_code(
        auth_code,
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI
    )

    if result:
        check_session_timeout()

        user_info = get_user_info(result["access_token"])
        if user_info:
            st.session_state["session_id"] = str(uuid.uuid4())
            st.session_state["msal_cache"] = msal_app.token_cache.serialize()
            st.session_state["access_token"] = result["access_token"]
            st.session_state["token_expiration"] = datetime.now(
            ) + timedelta(seconds=result["expires_in"])

            st.session_state["user"] = {
                "name": user_info["displayName"],
                "email": user_info["mail"] or user_info["userPrincipalName"],
                "token": result["access_token"],
            }

            save_session(st.session_state["session_id"],
                         st.session_state["user"]["email"])

            save_refresh_token(
                st.session_state["user"]["email"], result["refresh_token"])
        else:
            st.warning("User could not be found.")
            time.sleep(2)

        st.query_params.clear()
        st.rerun()
    else:
        st.error("Authentication failed. Please try again.")
        st.query_params.clear()


def main():
    """Main function to run the Streamlit app."""
    create_tables()

    if "user" not in st.session_state:
        auth_code = st.query_params.get("code", None)
        if auth_code:
            handle_auth_code(auth_code)
        else:
            authenticate()
    else:
        if "token_expiration" in st.session_state and datetime.now() >= st.session_state["token_expiration"]:
            refresh_access_token()

        st.sidebar.write(f"Welcome, {st.session_state['user']['name']}")
        if st.sidebar.button("Logout"):
            logout()
        for i in range(5):
            if st.button(f"Action {i}", key=f"action{i}"):
                check_session_timeout()
                log_usage(st.session_state["user"]["email"],
                          f"action{i}", st.session_state["session_id"])


if __name__ == "__main__":
    main()
