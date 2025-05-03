
# Password Strength Checker

A Python-based tool that checks password strength in real-time, providing feedback on complexity, evaluating entropy, checking against common passwords, and verifying if the password has been exposed in data breaches using the "Have I Been Pwned" API.

## Features:
- **Real-Time Feedback**: Provides immediate feedback on password strength as you type.
- **Password Rating System**: Rates the password as "Good", "Fair", or "Poor" based on entropy, breach risk, and character variety.
- **Password Breach Risk**: Checks if the password has been exposed in data breaches and assigns a risk score.
- **Password Complexity Analysis**: Evaluates the password's entropy and variety (length, characters, numbers, symbols).
- **Visualization**: Generates a graphical report of the password's performance in various security criteria.
- **Common Password List**: Uses an up-to-date list of common passwords fetched from an external source.

## Installation:

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/password-strength-checker.git
   ```

2. Navigate into the project directory:
   ```bash
   cd password-strength-checker
   ```

3. Create a virtual environment (optional, but recommended):
   ```bash
   python -m venv venv
   ```

4. Activate the virtual environment:
   - On **Windows**:
     ```bash
     venv\Scripts\activate
     ```
   - On **macOS/Linux**:
     ```bash
     source venv/bin/activate
     ```

5. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage:

To run the script, simply execute:

```bash
python password_strength_checker.py
```

You will be prompted to enter a password. The tool will evaluate the strength of the password and give you real-time feedback. After submitting the password, a visual report will be generated showing how it performs across various security criteria.

## Dependencies:
- `requests` - for making HTTP requests to the "Have I Been Pwned" API.
- `password-strength` - for evaluating password complexity and strength.
- `matplotlib` - for generating graphical reports.
- `colorama` - for adding color to the terminal output.

## License:

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
