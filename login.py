from app.models.breaches import get_breaches
from app.util.hash import hash_sha256, hash_pbkdf2
from stuff import load_breach
from bottle import (
    get,
    post,
    redirect,
    request,
    response,
    jinja2_template as template,
)

from app.models.user import create_user, get_user
from app.models.session import (
    delete_session,
    create_session,
    get_session_by_username,
    logged_in,
)

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"


@get('/login')
def login():
    return template('login')

@post('/login')
def do_login(db):
    username = request.forms.get('username')
    password = request.forms.get('password')
    error = None
    user = get_user(db, username)
    print(user)
    if (request.forms.get("login")):
        if user is None:
            response.status = 401
            error = "{} is not registered.".format(username)
        elif user.password != hash_pbkdf2(password,user.salt):
            response.status = 401
            error = "Wrong password for {}.".format(username)
        else:
            pass  # Successful login
    elif (request.forms.get("register")):
        flag = 0
        if (user is not None):
            response.status = 401
            error = "{} is already taken.".format(username)
        else:
            if get_breaches(db,username) != ([],[],[]):
                pb = load_breach(PLAINTEXT_BREACH_PATH)
                hb = load_breach(HASHED_BREACH_PATH)
                sb = load_breach(SALTED_BREACH_PATH)
                hashed = hash_sha256(password)
                (p,h,s) = get_breaches(db,username)
                print(s)
                if p != []:
                    x = [x for x in pb if username in x][0]
                    if pb[pb.index(x)][1] == password:
                        response.status = 401
                        error = "{}'s password is breached.".format(username)
                        flag = 1
                elif  h != []:
                    x = [x for x in hb if username in x][0]
                    if hb[hb.index(x)][1] == hashed:
                        response.status = 401
                        error = "{}'s password is breached.".format(username)
                        flag = 1
                elif s != []:
                    x = [x for x in sb if username in x][0]
                    salted = hash_pbkdf2(password,sb[sb.index(x)][2])
                    if sb[sb.index(x)][1]==salted:
                        response.status = 401
                        error = "{}'s password is breached.".format(username)
                        flag = 1
                if flag !=1:
                    create_user(db,username,password)
            else:
                create_user(db, username, password)
    else:
        response.status = 400
        error = "Submission error."
    if error is None:  # Perform login
        existing_session = get_session_by_username(db, username)
        if existing_session is not None:
            delete_session(db, existing_session)
        session = create_session(db, username)
        response.set_cookie("session", str(session.get_id()))
        return redirect("/{}".format(username))
    return template("login", error=error)

@post('/logout')
@logged_in
def do_logout(db, session):
    delete_session(db, session)
    response.delete_cookie("session")
    return redirect("/login")


