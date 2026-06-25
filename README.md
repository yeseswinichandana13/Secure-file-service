# Secure File Service — Cryptography

A secure file storage system built with Python, AES-GCM, PBKDF2, SHA-256, Streamlit and SQLite.

## What it does
- Encrypts every file before storing it in SQLite database
- Only the authenticated user can decrypt their files
- Dual-layer integrity verification using AES-GCM tags and SHA-256 hashing
- Defends against 4 threat types: database theft, brute-force, file tampering and replay attacks

## Technologies Used
- Python, Streamlit, SQLite, PyCryptodome
- AES-GCM, PBKDF2, SHA-256
