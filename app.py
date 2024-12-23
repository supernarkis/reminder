import streamlit as st
import psycopg2
import pandas as pd
from passlib.hash import bcrypt
from datetime import datetime

# ------------------------------------------------------------------------------
# 1. Подключаемся к БД (PostgreSQL)
# ------------------------------------------------------------------------------
# Параметры подключения берем из secrets.toml (или из "Secrets" на Streamlit Cloud).
# В публичном репо не храним пароли БД!

@st.experimental_singleton
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

# ------------------------------------------------------------------------------
# 5. Проверка, авторизован ли пользователь
# ------------------------------------------------------------------------------
def is_authenticated() -> bool:
    return st.session_state.get("authenticated", False)

# ------------------------------------------------------------------------------
# 6. Добавление новой заметки
# ------------------------------------------------------------------------------
def add_note(user_id: int, text: str):
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO notes (user_id, text, created_at) VALUES (%s, %s, %s)",
            (user_id, text, datetime.now())
        )
        conn.commit()

# ------------------------------------------------------------------------------
# 7. Загрузка заметок для текущего пользователя
# ------------------------------------------------------------------------------
def load_notes(user_id: int) -> pd.DataFrame:
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, text, created_at
            FROM notes
            WHERE user_id = %s
            ORDER BY created_at DESC;
        """, (user_id,))
        rows = cur.fetchall()
    df = pd.DataFrame(rows, columns=["id", "text", "created_at"])
    return df

# ------------------------------------------------------------------------------
# 8. Главная логика Streamlit
# ------------------------------------------------------------------------------
def main():
    # При первом запуске создаём таблицы (если не созданы)
    init_db()

    # Инициализируем переменные в сессии при необходимости
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
        st.session_state["user_id"] = None
        st.session_state["email"] = None

    # Шапка
    st.title("Пример приложения с аутентификацией")
    st.write("""
        Простое демо: регистрация, вход и личный кабинет с заметками.
    """)

    # Меню навигации (упрощённое)
    menu = ["Главная", "Регистрация", "Вход", "Мои заметки", "Выход"]
    choice = st.sidebar.selectbox("Навигация", menu)

    # --- (A) Общая зона: Главная страница ---
    if choice == "Главная":
        st.header("Главная страница (общедоступная)")
        st.write("Здесь может быть любая публичная информация.")

    # --- (B) Регистрация ---
    elif choice == "Регистрация":
        st.header("Регистрация нового пользователя")
        email = st.text_input("Email")
        password = st.text_input("Пароль", type="password")
        password2 = st.text_input("Повторите пароль", type="password")
        if st.button("Зарегистрироваться"):
            if password != password2:
                st.error("Пароли не совпадают!")
            elif len(email) < 5 or len(password) < 4:
                st.warning("Слишком короткий email или пароль.")
            else:
                success = register_user(email, password)
                if success:
                    st.success("Регистрация прошла успешно! Теперь можете войти.")
                else:
                    st.error("Пользователь с таким email уже существует.")

    # --- (C) Вход (Логин) ---
    elif choice == "Вход":
        st.header("Вход (логин)")
        email = st.text_input("Email")
        password = st.text_input("Пароль", type="password")
        if st.button("Войти"):
            if authenticate_user(email, password):
                st.success("Успешный вход!")
            else:
                st.error("Неправильный логин или пароль.")

    # --- (D) Личный кабинет: Мои заметки (приватная зона) ---
    elif choice == "Мои заметки":
        if not is_authenticated():
            st.warning("Пожалуйста, войдите, чтобы просмотреть заметки.")
        else:
            st.header("Мои заметки")
            st.write(f"Вы вошли как: **{st.session_state['email']}**")

            # Форма добавления новой заметки
            new_note = st.text_area("Новая заметка")
            if st.button("Добавить"):
                if new_note.strip():
                    add_note(st.session_state["user_id"], new_note.strip())
                    st.success("Заметка добавлена!")
                else:
                    st.warning("Пустая заметка!")

            # Отобразим все заметки пользователя
            df_notes = load_notes(st.session_state["user_id"])
            if df_notes.empty:
                st.info("Пока нет заметок.")
            else:
                for index, row in df_notes.iterrows():
                    st.write(f"- **{row['created_at']}**: {row['text']}")

    # --- (E) Выход (logout) ---
    elif choice == "Выход":
        if is_authenticated():
            st.session_state["authenticated"] = False
            st.session_state["user_id"] = None
            st.session_state["email"] = None
            st.success("Вы вышли из системы.")
        else:
            st.info("Вы не залогинены.")

if __name__ == "__main__":
    main()
