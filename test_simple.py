# Simple test file
API_KEY = "sk-1234567890abcdef1234567890abcdef"  # Hardcoded secret

def bad_function(user_input):
    return eval(user_input)  # Dangerous eval

result = bad_function("1+1")
