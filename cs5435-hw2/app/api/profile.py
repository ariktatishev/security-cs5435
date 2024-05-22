from bottle import (
    abort,
    get,
    post,
    request,
    jinja2_template as template,
)
from jinja2 import escape
from app.models.session import logged_in
from app.models.user import get_user

@get("/profile/<username:path>")
@logged_in
def profile(db, session, username):
    username = escape(username)
    user = get_user(db, username)
    session_user = get_user(db, session.get_username())
    if user is None:
        return template(
            "profile",
            user=session_user,
            session_user=session_user,
            session_id=session.get_id(),
            error="User {} does not exist".format(username)
        )
    return template(
        "profile",
        user=user,
        session_user=session_user,
        session_id=session.get_id()
    )

@post('/aboutme')
@logged_in
def update_aboutme(db, session):
    user = get_user(db, session.get_username())
    aboutme = request.forms.get('aboutme')
    aboutme = escape(aboutme)
    user.update_aboutme(aboutme)
    return template(
        "profile",
        user=user,
        session_user=user,
    )

