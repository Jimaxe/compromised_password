import requests
import hashlib
import sys


# Fetch password hashes (SHA1) from Pwned Passwords API
def request_api_data(query_string):
    url = f'https://api.pwnedpasswords.com/range/{query_string}'
    res = requests.get(url)
    if res.ok:
        return res
    raise RuntimeError(f'Error fetching data: {res.status_code}, please check the URL and try again!')


# Compare suffix of password hash with suffixes of hashes from breached passwords returned from API
# Return number of times that password has been breached
def get_password_leaks(pw_h_suffix, breached_h_suffixes):
    breached_h_suffixes = (line.split(':') for line in breached_h_suffixes.text.splitlines())
    for h, count in breached_h_suffixes:
        if h == pw_h_suffix:
            return count
    return 0


# Generate hash of user password (in hexadecimal) and pass first 5 characters to API
# Compare suffix of hash with the results returned from the API (k-Anonymity model)
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, pw_suffix = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks(pw_suffix, response)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'The password "{password}" was found {count} times. You should probably change your password!')
        else:
            print(f'{password} was not found. Carry on!')
    return 'Done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
