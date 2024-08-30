import re
import urllib.parse
from termcolor import colored # type: ignore

# List of suspicious patterns to check against
patterns = [
    r';',  # Semicolon
    r'%00',  # Null byte encoding
    r'%2E',  # URL encoded dot
    r'%20',  # URL encoded space
    r'%252E',  # Double URL encoded dot
    r'\.\s',  # Trailing space after dot
    r'\.+$',  # Trailing dots
    r'%E2%80%AE',  # Right-to-left override character
    r'%E2%80%8C',  # Zero-width non-joiner
    r'%E2%80%8B',  # Zero-width space
    r'\.[pP][hH][pP]\d*',  # PHP-related extensions
    r'\.(asp|php|phtml)\.',  # Multiple dots in suspicious extensions
    r'\.(asp|php|phtml)%00',  # Null byte in extensions
    r'[^\x00-\x7F]',  # Non-ASCII characters, potentially dangerous
    r'\xC0\xAE',  # Unicode dot
    r'php[0-9a-zA-Z]*\.',  # Obfuscated PHP extensions
    r'[pP][hH][pP][0-9]*$',  # Mixed case PHP extensions
    r'\.(jpg|jpeg|png|gif)$',  # Files ending in common image extensions but with obfuscated content
]

# Function to detect obfuscation techniques in a filename
def detect_obfuscation(filename):
    decoded_filename = urllib.parse.unquote(filename)  # Decode URL encoding
    for pattern in patterns:
        if re.search(pattern, decoded_filename):
            return True, pattern  # Returns True and the matched pattern if any obfuscation technique is found
    return False, None

def main():
    # Prompt user for filenames
    user_input = input("Enter filenames to check (comma-separated), or press Enter to use defaults: ")
    
    if user_input:
        filenames_to_check = [filename.strip() for filename in user_input.split(',')]
    else:
        filenames_to_check = [
            "exploit.php.jpg",
            "exploit.pHp",
            "exploit.asp;.jpg",
            "exploit.php%00.jpg",
            "exploit.%E2%80%AEphp",
            "exploit.php%2E.jpg",
            "safe_image.jpg",
            "exploit.p.phphp"
        ]

    detected = []
    not_detected = []

    # Analyze each filename
    for filename in filenames_to_check:
        is_obfuscated, matched_pattern = detect_obfuscation(filename)
        if is_obfuscated:
            detected.append((filename, matched_pattern))
            print(colored(f"Suspicious file detected: {filename} (Pattern matched: {matched_pattern})", "green"))
        else:
            not_detected.append(filename)
            print(colored(f"File is likely safe: {filename}", "red"))

    # Print categorized results
    print("\nCategorized Results:")
    print(colored("Detected Obfuscated Filenames:", "green"))
    for filename, pattern in detected:
        print(f"  - {filename} (Pattern matched: {pattern})")
    
    print(colored("\UnDetected Filenames:", "red"))
    for filename in not_detected:
        print(f"  - {filename}")

    print(colored("\nObfuscation detection complete.", "blue"))

if __name__ == "__main__":
    main()
