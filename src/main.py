import streamlit as st
from msal import ConfidentialClientApplication
import os
from dotenv import load_dotenv
import time
import requests
import sqlite3
from datetime import datetime, timedelta
import uuid
from cryptography.fernet import Fernet

# Load environment variables from .env file
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TENANT_ID = os.getenv("TENANT_ID")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY").encode()

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
REDIRECT_URI = "http://localhost:8501"

msal_app = ConfidentialClientApplication(
    CLIENT_ID, CLIENT_SECRET, authority=AUTHORITY
)

cipher_suite = Fernet(ENCRYPTION_KEY)


def authenticate():
    """Authenticate user via Microsoft SSO."""
    auth_url = msal_app.get_authorization_request_url(
        ["User.Read"], redirect_uri=REDIRECT_URI)
    st.link_button("Login with Microsoft", auth_url)


def logout(session_id):
    """Clear session and logout user."""
    st.session_state.pop("user", None)
    end_session(session_id)
    st.success("Logged out successfully!")
    time.sleep(2)
    st.rerun()


def save_session(session_id, email):
    """Save user session in database."""
    conn = sqlite3.connect("user_sessions.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sessions (session_id, email, login_time, is_active) VALUES (?, ?, ?, ?)",
        (session_id, email, datetime.now().isoformat(), 1),
    )
    conn.commit()
    conn.close()


def end_session(session_id):
    """Mark session as inactive."""
    conn = sqlite3.connect("user_sessions.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE sessions SET is_active = 0 WHERE session_id = ?", (session_id,))
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
            logout(st.session_state["session_id"])
    st.session_state["last_activity"] = datetime.now()


def get_token_from_code(auth_code):
    """Exchanges authorization code for an access token."""
    result = msal_app.acquire_token_by_authorization_code(
        auth_code,
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI,
    )
    return result


def save_refresh_token_to_db(email, refresh_token, expires_at):
    """Save refresh token in the database."""
    encrypted_refresh_token = cipher_suite.encrypt(refresh_token.encode())
    conn = sqlite3.connect("user_sessions.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO tokens (email, refresh_token, expires_at) VALUES (?, ?, ?)",
        (email, encrypted_refresh_token, expires_at),
    )
    conn.commit()
    conn.close()


def get_refresh_token_from_db(email):
    """Retrieve refresh token from the database."""
    conn = sqlite3.connect("user_sessions.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT refresh_token, expires_at FROM tokens WHERE email = ?",
        (email,)
    )
    token_data = cursor.fetchone()
    conn.close()

    if token_data:
        refresh_token = cipher_suite.decrypt(token_data[0]).decode()
        expires_at = token_data[1]
        return refresh_token, expires_at

    return None, None


def refresh_token():
    """Refresh the access token using the refresh token."""
    email = st.session_state["user"]["email"]

    # First, try acquiring a token silently
    accounts = msal_app.get_accounts()
    account = accounts[0] if accounts else None
    result = msal_app.acquire_token_silent(["User.Read"], account)

    if not result:
        # If no valid token exists, use the refresh token
        refresh_token, expires_at = get_refresh_token_from_db(email)

        if refresh_token and datetime.now() < datetime.fromisoformat(expires_at):
            result = msal_app.acquire_token_by_refresh_token(
                refresh_token, scopes=["User.Read"]
            )

    if result and "access_token" in result:
        st.session_state["user"]["token"] = result["access_token"]
        new_expires_at = (
            datetime.now() + timedelta(seconds=result["expires_in"])).isoformat()
        save_refresh_token_to_db(
            email, result.get("refresh_token", refresh_token), new_expires_at)
    else:
        st.error("Failed to refresh token. Please log in again.")
        logout(st.session_state["session_id"])


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
        (session_id TEXT PRIMARY KEY, email TEXT, login_time TEXT, is_active INTEGER)"""
    )
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS tokens
        (email TEXT PRIMARY KEY, refresh_token BLOB, expires_at TEXT)"""
    )
    conn.close()


def handle_auth_code(auth_code):
    """Handle the authentication code."""
    token_response = get_token_from_code(auth_code)
    if "access_token" in token_response:
        user_info = get_user_info(token_response["access_token"])
        if user_info:
            check_session_timeout()
            st.session_state["session_id"] = str(uuid.uuid4())
            st.session_state["user"] = {
                "name": user_info["displayName"],
                "email": user_info["mail"] or user_info["userPrincipalName"],
                "token": token_response["access_token"],
            }

            save_session(st.session_state["session_id"],
                         st.session_state["user"]["email"])

            expires_at = (
                datetime.now() + timedelta(seconds=token_response["expires_in"])).isoformat()
            save_refresh_token_to_db(
                st.session_state["user"]["email"], token_response["refresh_token"], expires_at)

            st.query_params.clear()
            st.rerun()
    else:
        st.error("Authentication failed. Please try again.")
        st.query_params.clear()


def main():
    create_tables()

    if "user" not in st.session_state:
        auth_code = st.query_params.get("code", None)
        if auth_code:
            handle_auth_code(auth_code)
        else:
            authenticate()
    else:
        refresh_token()
        st.sidebar.write(f"Welcome, {st.session_state['user']['name']}")
        if st.sidebar.button("Logout"):
            logout(st.session_state["session_id"])
        for i in range(5):
            if st.button(f"Action {i}", key=f"action{i}"):
                check_session_timeout()
                log_usage(st.session_state["user"]["email"],
                          f"action{i}", st.session_state["session_id"])


if __name__ == "__main__":
    main()
