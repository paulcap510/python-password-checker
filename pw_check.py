import re
import math
import hashlib
import requests

def load_common_passwords(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        common_passwords = set(password.strip() for password in file)
    return common_passwords

COMMON_PASSWORDS = load_common_passwords('rockyou-75.txt')

def check_password_strength(password):
    strength = 0
    length = len(password)

    if length >= 8:
        strength += 1

    if re.search(r'[A-Z]', password):
        strength += 1

    if re.search(r'[a-z]', password):
        strength += 1

    if re.search(r'\d', password):
        strength += 1

    if re.search(r'[@$!%*?&]', password):
        strength += 1

    if password not in COMMON_PASSWORDS:
        strength += 1

    return strength

def rate_password(strength):
    if strength <= 2:
        return "Weak"
    elif strength <= 4:
        return "Moderate"
    else:
        return "Strong"

def calculate_entropy(password):
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'\d', password):
        pool += 10
    if re.search(r'[@$!%*?&]', password):
        pool += len("@$!%*?&")
    entropy = len(password) * math.log2(pool) if pool > 0 else 0
    return entropy

def explain_entropy(entropy):
    explanation = (
        f"Entropy: {entropy:.2f} bits\n"
        "Explanation: Entropy is a measure of the unpredictability of your password. "
        "Higher entropy means your password is more complex and harder to guess.\n"
        "Here is a general guideline for entropy scores:\n"
        "- Less than 28 bits: Very weak (easy to guess)\n"
        "- 28-35 bits: Weak (easily guessable)\n"
        "- 36-59 bits: Reasonable (could be guessed with some effort)\n"
        "- 60-127 bits: Strong (very hard to guess)\n"
        "- 128 bits or more: Very strong (virtually impossible to guess)"
    )
    return explanation

def check_pwned_password(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    hashes = (line.split(':') for line in response.text.splitlines())
    return any(suffix == h for h, _ in hashes)

def check_patterns(password):
    patterns = [
        r'(.)\1{2,}',   
        r'1234',        
        r'password',    
    ]
    for pattern in patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return True
    return False

def provide_feedback(password):
    feedback = []
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        feedback.append("Include at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        feedback.append("Include at least one lowercase letter.")
    if not re.search(r'\d', password):
        feedback.append("Include at least one digit.")
    if not re.search(r'[@$!%*?&]', password):
        feedback.append("Include at least one special character (@$!%*?&).")
    if check_patterns(password):
        feedback.append("Avoid common patterns or repeated characters.")
    if check_pwned_password(password):
        feedback.append("This password has been compromised in a data breach.")
    return feedback

if __name__ == "__main__":
    password = input("Enter a password to check its strength: ")
    strength = check_password_strength(password)
    rating = rate_password(strength)
    entropy = calculate_entropy(password)
    feedback = provide_feedback(password)
    
    print(f"Password strength: {rating}")
    print(explain_entropy(entropy))
    if feedback:
        print("Suggestions to improve your password:")
        for item in feedback:
            print(f"- {item}")
