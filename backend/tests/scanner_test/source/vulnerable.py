"""
스캐너 테스트용 취약한 Python 코드
Bandit, Dlint가 탐지해야 할 보안 취약점 포함
"""
import sqlite3
import os
import pickle
import hashlib
import subprocess

# CWE-89: SQL Injection
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # 취약: 사용자 입력을 직접 쿼리에 포함
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

# CWE-798: Hard-coded Credentials
PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "password123"

# CWE-78: OS Command Injection
def run_command(user_input):
    # 취약: 사용자 입력을 직접 시스템 명령어에 포함
    os.system("ls " + user_input)

def execute_shell(command):
    # 취약: shell=True 사용
    subprocess.call(command, shell=True)

# CWE-502: Unsafe Deserialization
def load_data(data):
    # 취약: pickle.loads 사용
    return pickle.loads(data)

# CWE-327: Weak Cryptography
def hash_password(password):
    # 취약: MD5 사용
    return hashlib.md5(password.encode()).hexdigest()

def weak_hash(data):
    # 취약: SHA1 사용
    return hashlib.sha1(data.encode()).hexdigest()

# CWE-95: Code Injection
def evaluate_expression(expr):
    # 취약: eval 사용
    return eval(expr)

# CWE-22: Path Traversal
def read_file(filename):
    # 취약: 경로 검증 없음
    with open("/var/data/" + filename, 'r') as f:
        return f.read()

# CWE-377: Insecure Temporary File
import tempfile
def create_temp():
    # 취약: mktemp 사용
    return tempfile.mktemp()
