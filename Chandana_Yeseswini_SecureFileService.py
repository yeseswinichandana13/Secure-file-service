import sqlite3
from datetime import datetime

import streamlit as st
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes


DB_STORAGE_PATH = "vault.db"
PBKDF2_ITERATOR = 200_000


# Database connections

def init_db():
    dbconn = sqlite3.connect(DB_STORAGE_PATH)
    cur = dbconn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            nonce BLOB NOT NULL,
            tag BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            file_hash TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
        """
    )

    dbconn.commit()
    dbconn.close()


def get_db_connection():
    return sqlite3.connect(DB_STORAGE_PATH)


#Encryptions are below
def derive_keys(password: str, salt: bytes):
    """
    Making two 32-byte keys from a password:
      - first 32 bytes: from stored password hash
      - last 32 bytes:  encryption key for files
    """
    full_key = PBKDF2(
        password,
        salt,
        dkLen=64,
        count=PBKDF2_ITERATOR,
        hmac_hash_module=SHA256,
    )
    return full_key[:32], full_key[32:]


def encrypt_file(plaintext: bytes, enc_key: bytes):
    nonce = get_random_bytes(12) 
    cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    file_hash = SHA256.new(plaintext).hexdigest()
    return nonce, tag, ciphertext, file_hash


def decrypt_file(nonce: bytes, tag: bytes, ciphertext: bytes, enc_key: bytes, stored_hash: str):
    cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    calc_hash = SHA256.new(plaintext).hexdigest()
    if calc_hash != stored_hash:
        raise ValueError("Integrity check failed")
    return plaintext



# User Registrations

def register_user(username: str, password: str):
    if not username or not password:
        return None, "Username and password are required"

    dbconn = get_db_connection()
    cur = dbconn.cursor()

    salt = get_random_bytes(16)
    pw_hash, enc_key = derive_keys(password, salt)

    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, pw_hash, salt),
        )
        dbconn.commit()
        user_id = cur.lastrowid
        dbconn.close()
        return (user_id, enc_key), None
    except sqlite3.IntegrityError:
        dbconn.close()
        return None, "Username already taken"


def authenticate_user(username: str, password: str):
    dbconn = get_db_connection()
    cur = dbconn.cursor()
    cur.execute(
        "SELECT id, password_hash, salt FROM users WHERE username = ?",
        (username,),
    )
    row = cur.fetchone()
    dbconn.close()

    if not row:
        return None, "User not found"

    user_id, stored_hash, salt = row
    pw_hash, enc_key = derive_keys(password, salt)

    if pw_hash != stored_hash:
        return None, "Incorrect password"

    return (user_id, enc_key), None


#FILES RECORDS
def save_encrypted_file(owner_id: int, filename: str, data: bytes, enc_key: bytes):
    nonce, tag, ciphertext, file_hash = encrypt_file(data, enc_key)

    dbconn = get_db_connection()
    cur = dbconn.cursor()
    cur.execute(
        """
        INSERT INTO files (owner_id, filename, nonce, tag, ciphertext, file_hash, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (owner_id, filename, nonce, tag, ciphertext, file_hash, datetime.utcnow().isoformat()),
    )
    dbconn.commit()
    dbconn.close()


def get_user_files(owner_id: int):
    dbconn = get_db_connection()
    cur = dbconn.cursor()
    cur.execute(
        "SELECT id, filename, uploaded_at FROM files WHERE owner_id = ? ORDER BY uploaded_at DESC",
        (owner_id,),
    )
    rows = cur.fetchall()
    dbconn.close()
    files = [
        {"id": r[0], "filename": r[1], "uploaded_at": r[2]}
        for r in rows
    ]
    return files


def load_file_record(file_id: int, owner_id: int):
    dbconn = get_db_connection()
    cur = dbconn.cursor()
    cur.execute(
        """
        SELECT nonce, tag, ciphertext, file_hash, filename
        FROM files
        WHERE id = ? AND owner_id = ?
        """,
        (file_id, owner_id),
    )
    row = cur.fetchone()
    dbconn.close()
    if not row:
        return None
    nonce, tag, ciphertext, file_hash, filename = row
    return {
        "nonce": nonce,
        "tag": tag,
        "ciphertext": ciphertext,
        "file_hash": file_hash,
        "filename": filename,
    }


#UserInterface
def reset_session():
    for key in ["user_id", "username", "enc_key", "logged_in"]:
        if key in st.session_state:
            del st.session_state[key]


def login_register_ui():
    st.subheader("Authentication")

    mode = st.radio("Choose action", ["Login", "Register"])

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if mode == "Register":
        if st.button("Create account"):
            result, error = register_user(username, password)
            if error:
                st.error(error)
            else:
                user_id, enc_key = result
                st.success("Account created. You are now logged in.")
                st.session_state["user_id"] = user_id
                st.session_state["username"] = username
                st.session_state["enc_key"] = enc_key
                st.session_state["logged_in"] = True
    else:  # Login
        if st.button("Login"):
            result, error = authenticate_user(username, password)
            if error:
                st.error(error)
            else:
                user_id, enc_key = result
                st.success("Logged in successfully.")
                st.session_state["user_id"] = user_id
                st.session_state["username"] = username
                st.session_state["enc_key"] = enc_key
                st.session_state["logged_in"] = True


def vault_ui():
    st.subheader(f"Welcome, {st.session_state['username']}")

    if st.button("Log out"):
        reset_session()
        st.experimental_rerun()

    st.markdown("### Upload a file (it will be encrypted before storage)")
    uploaded = st.file_uploader("Select a file")
    if uploaded is not None:
        if st.button("Upload securely"):
            data = uploaded.read()
            save_encrypted_file(
                st.session_state["user_id"],
                uploaded.name,
                data,
                st.session_state["enc_key"],
            )
            st.success("File encrypted and stored securely.")

    st.markdown("---")
    st.markdown("### Your encrypted files")

    files = get_user_files(st.session_state["user_id"])
    if not files:
        st.info("No files uploaded yet.")
        return

    for f in files:
        col1, col2, col3 = st.columns([4, 2, 3])
        with col1:
            st.write(f"**{f['filename']}**")
            st.caption(f"Uploaded at: {f['uploaded_at']}")
        with col2:
            file_id = f["id"]
            record = load_file_record(file_id, st.session_state["user_id"])
            if record is None:
                st.error("File record not found.")
                continue

            try:
                plaintext = decrypt_file(
                    record["nonce"],
                    record["tag"],
                    record["ciphertext"],
                    st.session_state["enc_key"],
                    record["file_hash"],
                )
                st.download_button(
                    label="Download",
                    data=plaintext,
                    file_name=record["filename"],
                    mime="application/octet-stream",
                    key=f"dl_{file_id}",
                )
            except ValueError:
                st.error("Integrity check failed! check your file")
        with col3:
            st.text("") 


# Main Function
def main():
    st.title("Yeseswini Secure File Service")

    st.markdown(
        """
        Files are encrypted before being stored in SQLite.
        Only your derived encryption key can decrypt your files.
        """
    )

    init_db()

    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False

    if not st.session_state["logged_in"]:
        login_register_ui()
    else:
        vault_ui()


if __name__ == "__main__":
    main()
