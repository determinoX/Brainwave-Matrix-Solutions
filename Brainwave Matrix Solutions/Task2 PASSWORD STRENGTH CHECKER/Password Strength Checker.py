import re

def check_password_strength(password):
    # Initialize variables to track password properties
    length_error = len(password) < 8
    uppercase_error = not re.search(r"[A-Z]", password)
    lowercase_error = not re.search(r"[a-z]", password)
    digit_error = not re.search(r"\d", password)
    special_char_error = not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)

    # Count the number of failed checks
    errors = sum([length_error, uppercase_error, lowercase_error, digit_error, special_char_error])

    # Determine password strength based on errors
    if errors == 0:
        strength = "Strong"
    elif errors <= 2:
        strength = "Moderate"
    else:
        strength = "Weak"

    # Generate suggestions for improvement
    suggestions = []
    if length_error:
        suggestions.append("Increase the password length to at least 8 characters.")
    if uppercase_error:
        suggestions.append("Include at least one uppercase letter.")
    if lowercase_error:
        suggestions.append("Include at least one lowercase letter.")
    if digit_error:
        suggestions.append("Include at least one numeric digit.")
    if special_char_error:
        suggestions.append("Include at least one special character (e.g., !, @, #).")

    return strength, suggestions


def main():
    print("Welcome to the Password Strength Checker!")
    
    # Get user input for the password
    password = input("Enter a password to check its strength: ")

    # Check the strength of the entered password
    strength, suggestions = check_password_strength(password)

    # Display the results
    print(f"\nPassword Strength: {strength}")
    
    if suggestions:
        print("\nSuggestions to improve your password:")
        for suggestion in suggestions:
            print(f"- {suggestion}")
    
    print("\nThank you for using the Password Strength Checker!")

if __name__ == "__main__":
    main()
