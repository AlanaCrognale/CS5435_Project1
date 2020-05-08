from csv import reader
from hashlib import sha256, pbkdf2_hmac

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
    cp = load_common_passwords()
    bf = []
    for j in cp:
        h = hash_pbkdf2(j[0], target_salt)
        if h == target_hash:
            bf.append(j)
            print(target_hash)
            print(j)
    return bf

# Input: string x and string of hex salt; Output: string of hex values
def hash_pbkdf2(x, salt):
    return pbkdf2_hmac('sha256', x.encode('utf-8'), bytes.fromhex(salt), 100000).hex()

def main():
    salted_creds = load_breach(SALTED_BREACH_PATH)
    brute_force_attack(salted_creds[0][1], salted_creds[0][2])

if __name__ == "__main__":
    main()
