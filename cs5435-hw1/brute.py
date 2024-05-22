from csv import reader
from app.util.hash import hash_pbkdf2

COMMON_PASSWORDS_PATH = 'common_passwords.txt'
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = list(reader(f))
    return pws

def brute_force_attack(target_hash, target_salt):
    common = load_common_passwords()
    for pwd in common:
        salted_pwd = hash_pbkdf2(pwd[0], target_salt)
        if salted_pwd == target_hash:
            return pwd
    return None

def main():
    salted_creds = load_breach(SALTED_BREACH_PATH)
    print(brute_force_attack(salted_creds[0][1], salted_creds[0][2]))

if __name__ == "__main__":
    main()
