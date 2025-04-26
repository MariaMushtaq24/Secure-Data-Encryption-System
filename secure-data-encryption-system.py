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
@media screen and (max-width: 768px) {
    html, body, [class*="css"] {
        color: #111111 !important; /* Much darker text */
        font-weight: 600 !important; /* Bolder for visibility */
    }

    .stApp::before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.05); /* subtle dark overlay */
        z-index: 0;
    }

    .stApp > * {
        position: relative;
        z-index: 1;
    }

    .stTextInput>div>div>input,
    .stTextArea>div>div>textarea {
        background: rgba(255, 255, 255, 0.9) !important; /* even stronger opacity */
        color: #111111 !important;
    }

    .stButton>button {
        padding: 0.8rem 1.4rem !important; 
        font-size: 1.1rem !important;
    }
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
        st.stop()  # 👉 forcefully stop everything if locked out (important)
    
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authenticated = True
            st.session_state.lockout_time = None  # Clear lockout after successful login
            st.success("✅ Reauthenticated successfully!")
            time.sleep(5)  # 👉 optional short pause to show success message
            st.rerun()  # 👉 important: rerun to refresh session properly
        else:
            st.session_state.failed_attempts += 1
            st.error(f"❌ Incorrect master password! Attempts left: {3 - st.session_state.failed_attempts}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time()
                st.warning("🚫 Too many failed attempts. Locking out for 30 seconds.")
                time.sleep(1)  # 👉 small pause before rerun
                st.rerun()  # 👉 important: rerun immediately after locking out

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
