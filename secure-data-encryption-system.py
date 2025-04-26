import streamlit as st
import hashlib
import time
import json
import os
from cryptography.fernet import Fernet

import streamlit as st

# Set page configuration first
st.set_page_config(page_title="Secure Data Storage", page_icon="🛡️")

# Add background color using CSS
st.markdown(
    """
    <style>
    .stApp {
        background-color: #B2DFDB;  # Light Teal background
        color: #87CEEB;  # Sky Blue text color
    }
    .stButton>button {
        background-color: #87CEEB;  # Sky Blue buttons
        color: white;
    }
    .stTextInput>div>div>input {
        background-color: #E0FFFF;  # Light Sky Blue background for inputs
        color: #87CEEB;  # Sky Blue text in inputs
        border: 1px solid #87CEEB;  # Sky Blue border
    }
    .stTextArea>div>div>textarea {
        background-color: #E0FFFF;  # Light Sky Blue background for text areas
        color: #87CEEB;  # Sky Blue text
        border: 1px solid #87CEEB;  # Sky Blue border for text areas
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Your Streamlit content
st.title("🔒 Secure Data Encryption System")

DATA_FILE = "data.json"

# Initializing the Fernet key
if "cipher" not in st.session_state:
    KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(KEY)

# Initializing states
if "stored_data" not in st.session_state:
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            st.session_state.stored_data = json.load(f)
    else:
        st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authenticated" not in st.session_state:
    st.session_state.authenticated = True
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None

cipher = st.session_state.cipher

# Functions
def save_data_to_file():
    with open(DATA_FILE, "w") as f:
        json.dump(st.session_state.stored_data, f)

def hash_passkey_pbkdf2(passkey):
    salt = b'streamlit_salt'  # For demo. In production, we have to use random salt per user.
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000).hex()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, input_passkey):
    hashed_passkey = hash_passkey_pbkdf2(input_passkey)

    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

def is_lockout_active():
    if st.session_state.lockout_time:
        elapsed = time.time() - st.session_state.lockout_time
        if elapsed < 30:
            return 30 - int(elapsed)
        else:
            st.session_state.lockout_time = None
            st.session_state.failed_attempts = 0
            return 0
    return 0

# Pages
def home_page():
    st.subheader("🏠 Welcome to Secure Data System")
    st.write("**Store** and **Retrieve** your sensitive data safely, using a unique passkey.")
    st.success("Navigate using the sidebar to **Store** or **Retrieve** your data.")

def store_data_page():
    st.subheader("📂 Store Data Securely")

    user_data = st.text_area("Enter data to encrypt and store:")
    passkey = st.text_input("Enter a unique passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            hashed_passkey = hash_passkey_pbkdf2(passkey)
            encrypted_text = encrypt_data(user_data)

            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }

            save_data_to_file()

            st.success("✅ Data encrypted and stored securely!")
            st.text_area("Here is your Encrypted Data:", value=encrypted_text, height=100)
            st.info("💡 Save the encrypted data safely! You'll need it to retrieve your information.")
        else:
            st.error("⚠️ Please fill out both fields.")

def retrieve_data_page():
    if not st.session_state.authenticated:
        st.warning("🔒 Access restricted! Please login first.")
        st.switch_page("Login")

    st.subheader("🔍 Retrieve Your Data")

    encrypted_text = st.text_area("Paste your Encrypted Data here:")
    passkey = st.text_input("Enter your Passkey:", type="password")

    if st.button("Decrypt & Retrieve"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success("✅ Data successfully decrypted!")
                st.text_area("Your Decrypted Data:", value=decrypted_text, height=100)
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey or data. Attempts left: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🚫 Too many failed attempts! Redirecting to Login...")
                    st.session_state.authenticated = False
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

def login_page():
    st.subheader("🔑 Reauthentication Required")

    lockout_remaining = is_lockout_active()
    if lockout_remaining > 0:
        st.error(f"🚫 Locked out due to too many failed attempts! Try again in {lockout_remaining} seconds.")
        return

    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Simple master password for demo
            st.session_state.failed_attempts = 0
            st.session_state.authenticated = True
            st.session_state.lockout_time = None
            st.success("✅ Reauthenticated successfully!")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password!")
            st.session_state.failed_attempts += 1

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time()
                st.warning("🚫 Too many failed attempts. Locking out for 30 seconds.")
                st.experimental_rerun()

# Sidebar Navigation
st.sidebar.title("🧭 Navigation")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Go to:", menu)

if choice == "Home":
    home_page()
elif choice == "Store Data":
    store_data_page()
elif choice == "Retrieve Data":
    if st.session_state.authenticated:
        retrieve_data_page()
    else:
        login_page()
elif choice == "Login":
    login_page()