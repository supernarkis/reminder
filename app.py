import streamlit as st
import psycopg2
import pandas as pd
from passlib.hash import bcrypt
from datetime import datetime

# ------------------------------------------------------------------------------
# 1. Подключаемся к БД (PostgreSQL)
# ------------------------------------------------------------------------------
# Вместо @st.singleton / @st.experimental_singleton используем @st.cache_resource
@st.cache_resource
def get_connection():
    conn = psycopg2.connect(
        host=st.secrets["postgres"]["host"],
        port=st.secrets["postgres"]["port"],
        database=st.secrets["postgres"]["database"],
        user=st.secrets["postgres"]["user"],
        password=st.secrets["postgres"]["password"],
    )
    return conn

# ------------------------------------------------------------------------------
# 2. Инициализируем таблицы (users, notes) - вызываем один раз при старте
# ------------------------------------------------------------------------------
def init_db():
    conn = get_connection()
    with conn.cursor() as cur:
        # Таблица пользователей
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL
            );
        """)
        # Таблица заметок
        cur.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                text TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
        """)
        conn.commit()

# ------------------------------------------------------------------------------
# 3. Регистрация нового пользователя
# ------------------------------------------------------------------------------
def register_user(email: str, password: str) -> bool:
    """Возвращает True, если регистрация прошла успешно, иначе False (например, email уже существует)."""
    conn = get_connection()
    with conn.cursor() as cur:
        # Проверим, нет ли такого email
        cur.execute("SELECT id FROM users WHERE email=%s;", (email,))
        existing = cur.fetchone()
        if existing is not None:
            # Уже есть пользователь с таким email
            return False

        # Хэшируем пароль
        password_hash = bcrypt.hash(password)
        # Вставляем запись
        cur.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s)",
            (email, password_hash)
        )
        conn.commit()
        return True

# ------------------------------------------------------------------------------
# 4. Аутентификация (проверка логина/пароля)
# ------------------------------------------------------------------------------
def authenticate_user(email: str, password: str) -> bool:
    """Проверяем логин+пароль, при успехе сохраняем в session_state user_id."""
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT id, password_hash FROM users WHERE email=%s;", (email,))
        row = cur.fetchone()
        if row is None:
            return False
        user_id, password_hash = row
        # Сверяем хэш
        if bcrypt.verify(password, password_hash):
            # Сохраняем в сессии
            st.session_state["authenticated"] = True
            st.session_state["user_id"] = user_id
            st.session_state["email"] = email
            return True
        else:
            return False

# --------
