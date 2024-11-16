import streamlit as st
import firebase_admin
from firebase_admin import credentials, auth
import pyrebase
import time
from streamlit_cookies_manager import EncryptedCookieManager
import pandas as pd

# Firebase Admin SDK setup, loading private key from a file
cred = credentials.Certificate('/workspaces/st-test-admin-users-restrict/serviceAccountKey.json')
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

# Pyrebase setup for client-side operations
firebase_config = {
    "apiKey": "AIzaSyB0gbs0qPbl4fZkIVBZ6_UQwZxKV0uPwAk",
    "authDomain": "t7-securities-database.firebaseapp.com",
    "databaseURL": "https://t7-securities-database.firebaseio.com",
    "projectId": "t7-securities-database",
    "storageBucket": "t7-securities-database.appspot.com",
    "messagingSenderId": "278676976057",
    "appId": "1:278676976057:web:182f8c1110d96f9d7f4668",
    "measurementId": "G-DNJN5ZKZEP"
}

firebase = pyrebase.initialize_app(firebase_config)
auth_client = firebase.auth()

def login_user(email, password):
    try:
        # Attempt to sign in the user
        user = auth_client.sign_in_with_email_and_password(email, password)
        
        # Check if the user has the "disabled" custom claim
        user_info = auth.get_user_by_email(email)
        
        if user_info.custom_claims and user_info.custom_claims.get("disabled"):
            st.error("This account has been disabled. Please contact the admin.")
            return None
        
        return user['email']
    except Exception as e:
        st.error(f"Error logging in: {e}")
        return None

def register_user(email, password):
    try:
        auth_client.create_user_with_email_and_password(email, password)
        return True
    except Exception as e:
        st.error(f"Error registering user: {e}")
        return False

def reset_password(email):
    try:
        auth_client.send_password_reset_email(email)
        return True
    except Exception as e:
        st.error(f"Error resetting password: {e}")
        return False

# Set up encrypted cookies for storing login state
cookies = EncryptedCookieManager(
    prefix="myapp_",  
    password="A very secret password",
)

# Check if cookies are ready to use
if not cookies.ready():
    st.stop()

# Timeout duration set to 15 minutes (900 seconds)
TIMEOUT_DURATION = 900

# Function to check if session is timed out
def check_session_timeout():
    current_time = time.time()
    if "last_activity" in cookies:
        last_activity = float(cookies["last_activity"])
        time_diff = current_time - last_activity
        if time_diff > TIMEOUT_DURATION:
            st.warning("Session timed out due to inactivity. Please log in again.")
            st.session_state["logged_in"] = False
            st.session_state["user_email"] = None
            cookies["logged_in"] = "False"
            cookies.save()
            st.experimental_rerun()
    cookies["last_activity"] = str(current_time)
    cookies.save()

# Define admin emails
ADMIN_EMAILS = ["nasimk7045@gmail.com","syam.mohan@t7wealth.com", "another_admin@example.com"]

def disable_user_login(user_email):
    try:
        # Prevent disabling admin accounts
        if user_email in ADMIN_EMAILS:
            st.warning(f"Cannot disable login for admin email: {user_email}")
            return

        # Disable user login by setting a custom claim
        user = auth.get_user_by_email(user_email)
        auth.set_custom_user_claims(user.uid, {"disabled": True})
        st.success(f"User {user_email} login has been disabled.")
    except Exception as e:
        st.error(f"Failed to disable user login: {str(e)}")

def enable_user_login(user_email):
    try:
        # Prevent enabling admin accounts if already set
        if user_email in ADMIN_EMAILS:
            st.warning(f"Admin email {user_email} cannot be modified.")
            return

        # Re-enable user login by removing the custom claim
        user = auth.get_user_by_email(user_email)
        auth.set_custom_user_claims(user.uid, {"disabled": False})
        st.success(f"User {user_email} login has been re-enabled.")
    except Exception as e:
        st.error(f"Failed to enable user login: {str(e)}")
def main():
    st.title('Firebase Authentication with Streamlit')

    # Initialize session states
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = cookies.get("logged_in", "False") == "True"

    if "user_email" not in st.session_state:
        st.session_state["user_email"] = cookies.get("user_email", None)

    if "register" not in st.session_state:
        st.session_state["register"] = False

    if "forgot_password" not in st.session_state:
        st.session_state["forgot_password"] = False

    if st.session_state["logged_in"]:
        # Display logged-in user information
        st.write(f"You are logged in as: {st.session_state['user_email']}")

        menu_options = ["Main Menu", "Settings", "About", "Admin Mode"]
        choice = st.sidebar.selectbox("Choose an option", menu_options)

        if choice == "Main Menu":
            st.subheader("Welcome to the Main Menu")
            st.write("This is the main menu. Choose other options from the sidebar.")
        elif choice == "Settings":
            st.subheader("Settings")
            st.write("Settings page (to be implemented).")
        elif choice == "About":
            st.subheader("About")
            st.write("About page (to be implemented).")
        elif choice == "Admin Mode":
            # Check if the logged-in user is an admin
            if st.session_state['user_email'] in ADMIN_EMAILS:
                st.subheader("Admin Mode")
                st.write("Manage registered users below. Use the checkboxes to enable or disable user logins.")

                try:
                    users = auth.list_users().users
                    if users:
                        st.write("### Registered Users")

                        # Table headers
                        cols = st.columns([0.1, 0.2, 0.4, 0.2, 0.2])  # Adjust column widths
                        with cols[0]:
                            st.markdown("**Sr. No.**")
                        with cols[1]:
                            st.markdown("**Disable Users**")
                        with cols[2]:
                            st.markdown("**Emails**")
                        with cols[3]:
                            st.markdown("**Last Login**")
                        with cols[4]:
                            st.markdown("**User ID**")

                        # Display user data
                        for idx, user in enumerate(users):
                            last_login = "Never"
                            if user.user_metadata.last_sign_in_timestamp:
                                last_login = time.strftime(
                                    '%Y-%m-%d %H:%M:%S',
                                    time.localtime(user.user_metadata.last_sign_in_timestamp / 1000)
                                )
                            is_disabled = user.custom_claims.get("disabled", False) if user.custom_claims else False

                            row_cols = st.columns([0.1, 0.2, 0.4, 0.2, 0.2])
                            with row_cols[0]:
                                st.write(idx + 1)  # Sr. No.
                            with row_cols[1]:
                                disable_checkbox = st.checkbox(
                                    "",
                                    value=is_disabled,
                                    key=f"disable_{user.email}"
                                )
                                if disable_checkbox and not is_disabled:
                                    disable_user_login(user.email)
                                elif not disable_checkbox and is_disabled:
                                    enable_user_login(user.email)
                            with row_cols[2]:
                                st.write(user.email)
                            with row_cols[3]:
                                st.write(last_login)
                            with row_cols[4]:
                                st.write(user.uid)
                    else:
                        st.write("No users found.")
                except Exception as e:
                    st.error(f"Error retrieving users: {str(e)}")
            else:
                st.error("Access Denied: You do not have admin privileges.")
        if st.button("Logout"):
            st.session_state["logged_in"] = False
            st.session_state["user_email"] = None
            cookies["logged_in"] = "False"
            cookies["user_email"] = ""
            cookies.save()
            st.rerun()
    else:
        # Registration, Login, and Forgot Password workflows
        if st.session_state["register"]:
            st.subheader("Register a New Account")
            email = st.text_input("Enter your email")
            password = st.text_input("Enter your password", type="password")
            confirm_password = st.text_input("Confirm your password", type="password")

            if st.button("Register"):
                if password == confirm_password:
                    if register_user(email, password):
                        st.success("Registration successful! You can now log in.")
                        st.session_state["register"] = False
                        st.rerun()
                    else:
                        st.error("Registration failed. Try again.")
                else:
                    st.error("Passwords do not match. Please try again.")

            if st.button("Back to Login"):
                st.session_state["register"] = False
                st.rerun()

        elif st.session_state["forgot_password"]:
            st.subheader("Forgot Password")
            reset_email = st.text_input("Enter your email for password reset")
            if st.button("Send Password Reset Email"):
                if reset_email:
                    if reset_password(reset_email):
                        st.success("Password reset email sent! Check your inbox.")
                    else:
                        st.error("Failed to send password reset email. Please try again.")
                else:
                    st.error("Please enter a valid email address.")

            if st.button("Back to Login"):
                st.session_state["forgot_password"] = False
                st.rerun()

        else:
            st.subheader("Login")
            email = st.text_input("Enter your email")
            password = st.text_input("Enter your password", type="password")

            if st.button("Login"):
                user_email = login_user(email, password)
                if user_email:
                    st.session_state["logged_in"] = True
                    st.session_state["user_email"] = user_email
                    cookies["logged_in"] = "True"
                    cookies["user_email"] = user_email
                    cookies["last_activity"] = str(time.time())
                    cookies.save()
                    st.rerun()
                else:
                    st.error("Invalid email or password")

            if st.button("Sign Up"):
                st.session_state["register"] = True
                st.rerun()

            if st.button("Forgot Password"):
                st.session_state["forgot_password"] = True
                st.rerun()


if __name__ == '__main__':
    main()