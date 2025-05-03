import re
import math
import hashlib
import requests
import matplotlib.pyplot as plt
from collections import Counter
from password_strength import PasswordPolicy
from colorama import Fore, Style, init
import time

# Initialize colorama
init(autoreset=True)

# URL for common passwords list (you can replace it with any other list URL)
COMMON_PASSWORDS_URL = 'https://raw.githubusercontent.com/dwyl/english-words/master/words.txt'

# Password strength policy
policy = PasswordPolicy.from_names(
    length=12,  # Minimum length
    uppercase=1,  # At least 1 uppercase
    numbers=1,  # At least 1 number
    special=1,  # At least 1 special character
    nonletters=1  # At least 1 non-letter character
)

# Function to download the common passwords list
def download_common_passwords():
    try:
        response = requests.get(COMMON_PASSWORDS_URL, timeout=10)  # Timeout after 10 seconds
        response.raise_for_status()  # Raise an error for bad status codes
        # Parse the response into a list of common passwords
        passwords = set(response.text.splitlines())
        return passwords
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error contacting the passwords list: {e}")
        return set()  # Return an empty set if the download fails

# Load the common passwords list (this is done once at the start)
common_passwords = download_common_passwords()

# Function to calculate entropy
def calculate_entropy(password):
    char_set_size = len(set(password))  # Unique characters
    password_length = len(password)
    entropy = password_length * math.log2(char_set_size)
    return entropy

# Function to check if password has been exposed in known data breaches (using "Have I Been Pwned" API)
def check_pwned_password(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_chars = sha1_password[:5]
    rest_of_hash = sha1_password[5:]
    
    url = f'https://api.pwnedpasswords.com/range/{first5_chars}'
    
    try:
        response = requests.get(url, timeout=10)  # Timeout after 10 seconds
        response.raise_for_status()  # Raise an error for bad status codes
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error contacting API: {e}")
        return False, 0

    if response.status_code == 200:
        hashes = (line.split(":") for line in response.text.splitlines())
        for hash_suffix, count in hashes:
            if hash_suffix == rest_of_hash:
                return True, count
    return False, 0

# Function to check for dictionary words or common passwords
def contains_common_words(password):
    # Check against the common password list
    if password.lower() in common_passwords:
        return True
    return False

# Function to give feedback on password improvement
def give_feedback(password):
    feedback = []
    if len(password) < 12:
        feedback.append(f"{Fore.RED}Password too short! Consider making it longer.")
    if not re.search(r'[a-z]', password):
        feedback.append(f"{Fore.RED}Add at least one lowercase letter.")
    if not re.search(r'[A-Z]', password):
        feedback.append(f"{Fore.RED}Add at least one uppercase letter.")
    if not re.search(r'[0-9]', password):
        feedback.append(f"{Fore.RED}Add at least one number.")
    if not re.search(r'[@#$%^&+=!]', password):
        feedback.append(f"{Fore.RED}Add at least one special character.")
    
    if not feedback:
        feedback.append(f"{Fore.GREEN}{Style.BRIGHT}Password is strong!")
    
    return feedback

# Password Rating System
def password_rating(entropy, breach_score, length_score, repetition_score):
    total_score = entropy + breach_score + length_score + repetition_score
    
    if total_score >= 30:
        return "Good", total_score
    elif total_score >= 20:
        return "Fair", total_score
    else:
        return "Poor", total_score

# Advanced password strength checker
def check_advanced_password_strength(password):
    # Check if password is in common passwords list
    if contains_common_words(password):
        return f"{Fore.RED}{Style.BRIGHT}Password is too common, please choose another one."

    # Check password strength using the password-strength library
    strength = policy.test(password)
    if strength:
        return f"{Fore.RED}{Style.BRIGHT}Password is weak: {', '.join(str(x) for x in strength)}"

    # Check for repeated characters
    if any(v > 2 for v in Counter(password).values()):
        return f"{Fore.RED}{Style.BRIGHT}Password should not contain repeated characters like 'aaa' or '111'."

    # Check for dictionary words or personal information
    if contains_common_words(password):
        return f"{Fore.RED}{Style.BRIGHT}Password contains common words or easily guessable terms."

    # Check if password has been exposed in known data breaches
    pwned, breach_count = check_pwned_password(password)
    breach_score = 0
    if pwned:
        if breach_count <= 5:
            breach_score = 5
        elif breach_count <= 20:
            breach_score = 10
        else:
            breach_score = 15

    # Calculate entropy
    entropy = calculate_entropy(password)
    length_score = 5 if len(password) >= 12 else 0
    repetition_score = 0 if all(v <= 2 for v in Counter(password).values()) else 5

    # Password rating based on total score
    rating, total_score = password_rating(entropy, breach_score, length_score, repetition_score)
    
    # Generate visual report
    generate_report(entropy, breach_count, len(password), rating)

    return f"{Fore.CYAN}{Style.BRIGHT}Password Rating: {rating} (Total Score: {total_score})"

# Visualization of Password Performance
def generate_report(entropy, breach_count, password_length, rating):
    categories = ['Entropy', 'Breach Count', 'Password Length']
    values = [entropy, breach_count, password_length]

    # Plotting
    plt.figure(figsize=(8, 6))
    plt.bar(categories, values, color=['blue', 'orange', 'green'])
    plt.title(f"Password Strength Report ({rating})")
    plt.xlabel("Criteria")
    plt.ylabel("Score")
    plt.show()

# Real-time feedback while typing
def real_time_feedback():
    password = ""
    while True:
        password = input(f"{Fore.MAGENTA}{Style.BRIGHT}Enter password: ")
        feedback = give_feedback(password)
        print("\n".join(feedback))
        
        if len(password) >= 12 and "strong" in feedback[-1]:
            print(f"{Fore.CYAN}Password is good! You can submit it now.\n")
            break

# Main Function to Run the Checker
if __name__ == "__main__":
    real_time_feedback()
