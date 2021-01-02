import sys
import requests
import hashlib


# request data from password api
def request_api_data(query_chars):
    url = 'https://api.pwnedpasswords.com/range/' + query_chars
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error Fetching: {res.status_code}, check your api')
    return res


# get counts of times password has been leaked.
def get_password_leaks_count(hashes, hash_to_check):
    lines = (line.split(':') for line in hashes.splitlines())
    for line in lines:
        if line[0] == hash_to_check:
            return line


def pwned_api_check(password):
    # hash password to sha1
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_chars = sha1password[:5]  # gets first 5 chars from the hashed password
    last_chars = sha1password[5:]  # gets remaining part of the hashed password
    response = request_api_data(first5_chars)
    return get_password_leaks_count(response.text, last_chars)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} has been leaked {count[1]} times, please try another password.')
        else:
            print(f'{password} has not been leaked at all, go ahead and use the password.')
    return '----------done checking passwords!-----------'


if __name__ == '__main__':
    # change the test passwords list below
    # to the list of passwords you want to check.
    passwords = ['hello', '12345', 'maaam132']
    sys.exit(main(passwords))
