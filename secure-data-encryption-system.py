import streamlit as st
import hashlib
import time
import json
import os
from cryptography.fernet import Fernet

# Set page configuration first
st.set_page_config(page_title="Secure Data Storage", page_icon="🛡️")

# Add background color using CSS
st.markdown(
    """
    <style>
    /* Apply background gradient and frosted effect */
    .stApp {
        background: linear-gradient(to bottom right, #e0f7fa, #ffffff);
        background-attachment: fixed;
        min-height: 100vh;
        backdrop-filter: blur(6px);
        -webkit-backdrop-filter: blur(6px);
    }

    /* Text color */
    html, body, [class*="css"] {
        color: #333333;
        font-family: 'Poppins', sans-serif;
    }

    /* Button styles */
    .stButton>button {
        background-color: #4FC3F7;
        color: white;
        border-radius: 10px;
        padding: 0.5rem 1rem;
        font-weight: bold;
        transition: 0.3s;
    }
    .stButton>button:hover {
        background-color: #29B6F6;
        transform: scale(1.05);
    }

    /* Input and Text Area styling */
    .stTextInput>div>div>input,
    .stTextArea>div>div>textarea {
        background: rgba(255, 255, 255, 0.6);
        border-radius: 10px;
        padding: 0.5rem;
        color: #333333;
        font-weight: 500;
        border: 1px solid #B2EBF2;
    }

    /* Sidebar styling */
    .css-1d391kg {
        background: rgba(255, 255, 255, 0.4) !important;
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border-radius: 10px;
        margin: 1rem;
        padding: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Streamlit Title
st.title("🔒 Secure Data Encryption System")

DATA_FILE = "data.json"

# Initialize Fernet cipher key
if "cipher" not in st.session_state:
    KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(KEY)

# Initialize session state
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
    salt = b'streamlit_salt'
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
        login_page()
        return

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
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

def login_page():
    st.subheader("🔑 Reauthentication Required")

    lockout_remaining = is_lockout_active()
    if lockout_remaining > 0:
        st.error(f"🚫 Locked out due to too many failed attempts! Try again in {lockout_remaining} seconds.")
        return  # <- immediately exit if locked

    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authenticated = True
            st.session_state.lockout_time = None  # Clear lockout after successful login
            st.success("✅ Reauthenticated successfully!")
            st.rerun()
        else:
            st.session_state.failed_attempts += 1
            st.error(f"❌ Incorrect master password! Attempts left: {3 - st.session_state.failed_attempts}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time()
                st.warning("🚫 Too many failed attempts. Locking out for 30 seconds.")
                st.rerun()

# Sidebar Navigation
st.sidebar.title("🧭 Navigation")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Go to:", menu)

if choice == "Home":
    home_page()
elif choice == "Store Data":
    store_data_page()
elif choice == "Retrieve Data":
    retrieve_data_page()
elif choice == "Login":
    login_page()
