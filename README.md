# Breached Password Checker

**Description:** Billions of user accounts have been compromised in data breaches throughout the years - is yours one of them? This script provides a secure way of checking if passwords have been leaked without transmitting any credentials over the wire by implementing a [k-Anonymity](https://en.wikipedia.org/wiki/K-anonymity) model. This method enables search of passwords by partial hash (SHA-1). 

## Instructions

_Please note that [Python](https://www.python.org) must be installed in order to run this shell script._

1. Download the breached_password.py file from this repository.
2. Assuming that Python has already been installed, open a terminal and navigate to the directory where the breached_password.py file is located.
3. Type python3 (or python) followed by breached_passwords.py and the password(s) you would like to check.

e.g.

'''
python breached_passwords.py password1 password2 password3
'''

Learn more about the underlying data and the API used in this project at [Have I Been Pwned](https://haveibeenpwned.com/).