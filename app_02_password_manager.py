import os
import bcrypt
import logging
from cryptography.fernet import Fernet
import streamlit as st
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, ForeignKey, LargeBinary
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlalchemy.exc import IntegrityError

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
DATABASE_URL = "postgresql://sharath:K1gd00m@localhost/home_base"
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(LargeBinary, nullable=False)
    passwords = relationship('Password', backref='user')

class Password(Base):
    __tablename__ = 'passwords'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    website = Column(String, nullable=False)
    username = Column(String, nullable=False)
    password = Column(LargeBinary, nullable=False)

Base.metadata.create_all(engine)

# Encryption functions
def generate_key():
    return Fernet.generate_key()

def encrypt_password(key, password):
    fernet = Fernet(key)
    return fernet.encrypt(password.encode())

def decrypt_password(key, encrypted_password):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_password).decode()

def hash_master_password(master_password):
    return bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())

def verify_master_password(master_password, hashed):
    return bcrypt.checkpw(master_password.encode(), hashed)

# Streamlit app functions
def main():
    st.title("Secure Password Manager")

    menu = ["Login", "Register", "Manage Passwords"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Register":
        st.subheader("Register")
        username = st.text_input("Username")
        master_password = st.text_input("Master Password", type="password")
        if st.button("Register"):
            hashed_master = hash_master_password(master_password)
            new_user = User(username=username, password_hash=hashed_master)
            try:
                session.add(new_user)
                session.commit()
                st.success("Registration successful. Please log in.")
                logger.info(f"User {username} registered successfully.")
            except IntegrityError:
                session.rollback()
                st.error("Username already exists.")
                logger.warning(f"Registration failed: Username {username} already exists.")

    elif choice == "Login":
        st.subheader("Login")
        username = st.text_input("Username")
        master_password = st.text_input("Master Password", type="password")
        if st.button("Login"):
            user = session.query(User).filter_by(username=username).first()
            if user and verify_master_password(master_password, user.password_hash):
                st.session_state['logged_in'] = True
                st.session_state['user_id'] = user.id
                st.session_state['key'] = generate_key()  # New session, generate a new key
                st.success("Logged in successfully")
                logger.info(f"User {username} logged in successfully.")
            else:
                st.error("Invalid username or password")
                logger.warning(f"Login attempt failed for user {username}.")

    elif choice == "Manage Passwords":
        if 'logged_in' in st.session_state and st.session_state['logged_in']:
            st.subheader("Manage Passwords")

            # Add a new password
            with st.form("add_password_form"):
                website = st.text_input("Website")
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Add Password")
                if submitted:
                    encrypted_password = encrypt_password(st.session_state['key'], password)
                    new_password = Password(
                        user_id=st.session_state['user_id'],
                        website=website,
                        username=username,
                        password=encrypted_password
                    )
                    session.add(new_password)
                    session.commit()
                    st.success("Password added successfully")
                    logger.info(f"Password for {website} added successfully.")

            # Display stored passwords
            passwords = session.query(Password).filter_by(user_id=st.session_state['user_id']).all()
            if passwords:
                st.write("Stored Passwords")
                for pwd in passwords:
                    st.write(f"Website: {pwd.website}")
                    st.write(f"Username: {pwd.username}")
                    decrypted_password = decrypt_password(st.session_state['key'], pwd.password)
                    st.write(f"Password: {decrypted_password}")
                    st.write("---")
        else:
            st.error("Please log in to manage passwords")

if __name__ == "__main__":
    main()
