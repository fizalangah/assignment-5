

import streamlit as st
from pymongo import MongoClient
#  from bson.objectid import ObjectId # type: ignore

import base64

def set_background(image_path: str):
    with open(image_path, "rb") as image_file:
        encoded = base64.b64encode(image_file.read()).decode()
    st.markdown(
        f"""
        <style>
        .stApp {{
            background-image: url("data:image/png;base64,{encoded}");
            background-size: cover;
            background-repeat: no-repeat;
            background-position: center;
            color: #FAFAFA;
        }}

        .stSidebar {{
    background-color: rgba(0, 0, 0, 0.7);
}}

.stSidebar > div {{
    color: white !important;
}}

.stSidebar label, .stSidebar span, .stSidebar div {{
    color: white !important;
}}
        .stTextInput input, .stTextArea textarea {{
            background-color: #1a1a1a !important;
            color: white !important;
            border: 1px solid #339CFF !important;
        }}

        .stButton button {{
            background-color: #339CFF;
            color: white;
            border-radius: 6px;
            padding: 8px 16px;
        }}

        .stAlert, .stSuccess, .stError, .stInfo, .stWarning {{
            background-color: rgba(0, 0, 0, 0.6) !important;
            background-color: #FAFAFA !important;
            border-left: 5px solid #00bcd4;
            border-radius: 10px;
        }}

        h1, h2, h3, h4 {{
            color: #00bcd4 !important;
        }}

        label {{
            color: white !important;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

# MongoDB connection
client = MongoClient("mongodb+srv://fiza86363:XiDt8eQrUgBwQf7p@cluster0.d2xmx8k.mongodb.net/")
db = client["data-secure"]
users = db["users"]

# Session state initialization
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""

def home():
    set_background("home.png")
    st.title("🏠 Home Page")
    st.success(f"Welcome to the home page, {st.session_state.username}!")



def data():
    set_background("home.png")
    st.title("🔐 Secure Data Storage (Base64 Safe)")
    st.write("Store and encrypt both your data and passkey.")

    input_data = st.text_input("Enter your data")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("🔒 Store & Encrypt"):
        if input_data and passkey:
            # XOR encryption
            encrypted_bytes = bytes([ord(c) ^ ord(passkey[i % len(passkey)]) for i, c in enumerate(input_data)])
            # Base64 encode for safe storage
            encrypted_data = base64.b64encode(encrypted_bytes).decode()

            # Same for passkey (using a static salt)
            salt = "my_static_salt"
            encrypted_passkey_bytes = bytes([ord(c) ^ ord(salt[i % len(salt)]) for i, c in enumerate(passkey)])
            encrypted_passkey = base64.b64encode(encrypted_passkey_bytes).decode()

            # Store
            users.update_one(
                {"username": st.session_state.username},
                {"$set": {"data": encrypted_data, "encrypted_passkey": encrypted_passkey}}
            )

            st.success("✅ Data and passkey encrypted and stored!")
            st.code(f"Encrypted Data: {encrypted_data}")
            st.code(f"Encrypted Passkey: {encrypted_passkey}")
        else:
            st.error("⚠️ Please enter both fields.")


def decrypt_data():
    set_background("home.png")
    st.title("🔓 Decrypt Stored Data")

    encrypted_data = st.text_input("Enter Encrypted Data")
    encrypted_passkey = st.text_input("Enter Encrypted Passkey")
    salt = "my_static_salt"

    if st.button("🔍 Decrypt"):
        if encrypted_data and encrypted_passkey:
            try:
                # Decrypt passkey
                encrypted_passkey_bytes = base64.b64decode(encrypted_passkey.encode())
                decrypted_passkey = "".join(
                    chr(b ^ ord(salt[i % len(salt)]))
                    for i, b in enumerate(encrypted_passkey_bytes)
                )

                # Decrypt data
                encrypted_data_bytes = base64.b64decode(encrypted_data.encode())
                decrypted_data = "".join(
                    chr(b ^ ord(decrypted_passkey[i % len(decrypted_passkey)]))
                    for i, b in enumerate(encrypted_data_bytes)
                )

                st.success("✅ Decryption successful!")
                st.code(f"Original Passkey: {decrypted_passkey}")
                st.code(f"Original Data: {decrypted_data}")

            except Exception as e:
                st.error(f"❌ Decryption failed: {e}")
        else:
            st.error("⚠️ Please fill in both fields.")


# Register Page
def register():
    set_background("login.png")
    st.title("Register")
    username = st.text_input("Enter Username")
    password = st.text_input("Enter Password", type="password")
    if st.button("Register"):
        if users.find_one({"username": username}):
            st.error("Username already exists.")
        else:
            users.insert_one({"username": username, "password": password})
            st.success("Registered successfully! Please login.")
# login

def login():
    set_background("login.png")
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = users.find_one({"username": username, "password": password})
        if user:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success(f"Welcome, {username}!")
            st.rerun()
        else:
            st.error("Invalid username or password.")


# Logout Page
def logout():
    set_background("home.png")
    st.title("Logout")
    if st.session_state.logged_in:
        st.write(f"Logged in as: {st.session_state.username}")
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.success("Logged out successfully.")
            st.rerun()
    else:
        st.info("You are not logged in.")

# Sidebar Navigation
st.sidebar.title("🔐 Navigation")

if st.session_state.logged_in:
    page = st.sidebar.radio("Go to", ["Home", "Store Date", "Decrypt Data", "Logout"])
    
else:
    page = st.sidebar.radio("Go to", ["Login", "Register"])

# Page Routing
if st.session_state.logged_in:
    if page == "Home":
        home()
    elif page == "Store Date":
        data()  
    elif page == "Decrypt Data":
        decrypt_data()       
    elif page == "Logout":
        logout()
else:
    if page == "Login":
        login()
    elif page == "Register":
        register()

# Encrypted Data: T^_
# Encrypted Passkey: Hm@