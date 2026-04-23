import re
import random
import string
import math
import hashlib
import sqlite3
from datetime import datetime

# -------------------------------
# 🗄️ DATABASE SETUP (SQLite)
# -------------------------------
DB_NAME = "passwords.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT UNIQUE,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def check_password_reuse(password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    hashed = hash_password(password)

    cursor.execute("SELECT * FROM passwords WHERE hash = ?", (hashed,))
    result = cursor.fetchone()

    conn.close()
    return result is not None


def save_password(password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    hashed = hash_password(password)

    try:
        cursor.execute(
            "INSERT INTO passwords (hash, created_at) VALUES (?, ?)",
            (hashed, datetime.now().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass

    conn.close()


# -------------------------------
# 📊 ENTROPY CALCULATION
# -------------------------------
def calculate_entropy(password):
    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        charset += 32

    if charset == 0:
        return 0

    return len(password) * math.log2(charset)


# -------------------------------
# 🔍 ANALYSIS
# -------------------------------
def analyze_password(password):
    score = 0
    issues = []

    if len(password) >= 12:
        score += 25
    else:
        issues.append("Password should be at least 12 characters")

    if re.search(r"[a-z]", password):
        score += 15
    else:
        issues.append("Add lowercase letters")

    if re.search(r"[A-Z]", password):
        score += 15
    else:
        issues.append("Add uppercase letters")

    if re.search(r"[0-9]", password):
        score += 15
    else:
        issues.append("Add numbers")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 20
    else:
        issues.append("Add special characters")

    entropy = calculate_entropy(password)
    if entropy > 60:
        score += 10
    else:
        issues.append("Low entropy (predictable password)")

    if score >= 80:
        strength = "Strong"
    elif score >= 50:
        strength = "Moderate"
    else:
        strength = "Weak"

    return score, strength, issues


# -------------------------------
# 💡 SMART PASSWORD SUGGESTIONS
# -------------------------------
def improve_password(password):
    suggestions = []

    # Replace common letters
    replacements = {
        "a": "@",
        "s": "$",
        "o": "0",
        "i": "1",
        "e": "3"
    }

    modified = password
    for char, rep in replacements.items():
        modified = modified.replace(char, rep)

    # Add missing complexity
    if not re.search(r"[A-Z]", modified):
        modified = modified.capitalize()

    if not re.search(r"[0-9]", modified):
        modified += str(random.randint(10, 99))

    if not re.search(r"[!@#$%^&*]", modified):
        modified += random.choice("!@#$%^&*")

    # Ensure length
    while len(modified) < 12:
        modified += random.choice(string.ascii_letters)

    suggestions.append(modified)

    # Another variation (random strong)
    strong_random = ''.join(random.choice(
        string.ascii_letters + string.digits + "!@#$%^&*()"
    ) for _ in range(14))

    suggestions.append(strong_random)

    return suggestions


# -------------------------------
# 🚀 MAIN
# -------------------------------
def main():
    init_db()

    print("\n🔐 PASSWORD STRENGTH ANALYZER 🔐\n")

    password = input("Enter your password: ")

    # Check reuse
    if check_password_reuse(password):
        print("\n⚠️ This password was already used before!")
        print("❌ Choose a new password.\n")
        return

    score, strength, issues = analyze_password(password)

    print("\n📊 RESULT")
    print("-" * 30)
    print(f"Strength : {strength}")
    print(f"Score    : {score}/100")

    print("\n🔍 Issues:")
    if issues:
        for issue in issues:
            print(f"- {issue}")
    else:
        print("No issues found ✅")

    # Improved suggestions
    if strength != "Strong":
        print("\n💡 Improved Password Suggestions:")
        suggestions = improve_password(password)
        for i, s in enumerate(suggestions, 1):
            print(f"{i}. {s}")

    save_password(password)
    print("\n✅ Password stored securely in SQLite DB.")


if __name__ == "__main__":
    main()