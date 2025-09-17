import os
import subprocess
import pickle
import sqlite3
import hashlib

# Hardcoded secret - Critical
API_KEY = "sk-1234567890abcdef1234567890abcdef"

def vulnerable_function(user_input):
    # SQL Injection - High
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query)
    
    # Command Injection - Critical
    subprocess.Popen("ls " + user_input, shell=True)
    
    # Insecure Deserialization - High
    data = pickle.loads(user_input)
    
    # Weak Crypto - Medium
    import md5
    hash_result = md5.md5(user_input.encode()).hexdigest()
    
    return data

# Dangerous eval usage - High
def process_data(data):
    result = eval(data)
    return result

# Debug mode enabled - Medium
if __name__ == '__main__':
    app.run(debug=True)