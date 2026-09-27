"""Sign-in, sessions, MFA, CSRF and HTTP security controls."""
from datetime import timedelta

import pyotp

from conftest import PASSWORD, Browser


def test_setup_is_closed_once_an_admin_exists(master):
    b = Browser()
    r = b.get('/setup')
    assert r.status_code == 302 and '/login' in r.location
    r = b.post('/setup', {'name': 'Intruder', 'username': 'evil', 'email': 'evil@example.test',
                          'password': PASSWORD, 'confirm_password': PASSWORD})
    assert r.status_code == 302 and '/login' in r.location


def test_login_with_username_or_email_and_wrong_password(make_user):
    u = make_user('staff')
    assert Browser().login(u['username']).status_code == 302
    assert Browser().login(f"{u['username']}@example.test".upper()).status_code == 302
    r = Browser().login(u['username'], password='wrong-password-1')
    assert r.status_code == 200 and b'Invalid username/email or password' in r.data


def test_lockout_after_repeated_failures(app, make_user):
    u = make_user('staff')
    for _ in range(5):
        Browser().login(u['username'], password='nope-nope-1')
    r = Browser().login(u['username'])  # correct password, but locked
    assert r.status_code == 429
    with app.app.app_context():
        row = app.db.session.get(app.User, u['id'])
        row.locked_until = app.utcnow() - timedelta(minutes=1)
        app.db.session.commit()
    assert Browser().login(u['username']).status_code == 302


def test_inactive_user_cannot_sign_in(make_user):
    u = make_user('staff', active=False)
    r = Browser().login(u['username'])
    assert r.status_code == 200 and b'Invalid' in r.data


def test_deactivated_user_loses_existing_session(app, login_as):
    b = login_as('staff')
    assert b.get('/samples').status_code == 200
    with app.app.app_context():
        app.db.session.get(app.User, b.user['id']).active = False
        app.db.session.commit()
    r = b.get('/samples')
    assert r.status_code in (302, 401) and (r.status_code == 401 or '/login' in r.location)
    assert b.get('/').status_code == 302


def test_csrf_token_required_on_post(login_as):
    b = login_as('staff')
    r = b.post('/batches', {'name': 'no token'}, csrf=False)
    assert r.status_code == 400
    r = b.post('/batches', {'name': 'bad token', '_csrf_token': 'forged'})
    assert r.status_code == 400


def test_idle_session_times_out(app, login_as):
    b = login_as('staff')
    with b.c.session_transaction() as s:
        s['_last_activity'] = (app.utcnow() - timedelta(minutes=45)).isoformat()
    r = b.get('/samples')
    assert r.status_code == 302 and '/login' in r.location


def test_session_is_rotated_on_login(make_user):
    u = make_user('staff')
    b = Browser()
    before = b.csrf()
    b.login(u['username'])
    assert b.session()['_csrf_token'] != before


def test_mfa_login_requires_valid_code(make_user):
    u = make_user('director')
    b = Browser()
    r = b.post('/login', {'identity': u['username'], 'password': PASSWORD})
    assert r.location.endswith('/mfa')
    assert b.get('/').status_code == 302  # not signed in yet
    r = b.post('/mfa', {'code': '000000'})
    assert b'Invalid authentication code' in r.data
    r = b.post('/mfa', {'code': pyotp.TOTP(u['secret']).now()})
    assert r.status_code == 302 and b.get('/').status_code == 200


def test_mfa_enrolment_with_qr_code(app, login_as):
    b = login_as('staff')
    b.post('/security/mfa', {'action': 'start'})
    html = b.get('/security/mfa').get_data(as_text=True)
    assert '<svg' in html and 'mfa-qr' in html
    secret = b.session()['mfa_setup_secret']
    assert b.post('/security/mfa', {'action': 'enable', 'code': '123456'}).status_code == 302
    with app.app.app_context():
        assert not app.db.session.get(app.User, b.user['id']).mfa_enabled
    b.post('/security/mfa', {'action': 'enable', 'code': pyotp.TOTP(secret).now()})
    with app.app.app_context():
        assert app.db.session.get(app.User, b.user['id']).mfa_enabled


def test_privileged_user_without_mfa_is_blocked_everywhere(make_user):
    """A director who has not enrolled MFA must not be able to use the app (including approving results)."""
    u = make_user('director', mfa=False)
    b = Browser()
    r = b.login(u['username'])
    assert '/security/mfa' in r.location
    for path in ('/', '/orders', '/admin/users', '/finance'):
        r = b.get(path)
        assert r.status_code in (302, 403), path
        if r.status_code == 302:
            assert '/security/mfa' in r.location, path
    assert b.get('/security/mfa').status_code == 200


def test_temporary_password_must_be_changed_before_use(app, make_user):
    u = make_user('staff', must_change=True)
    b = Browser()
    r = b.login(u['username'])
    assert '/account/change-password' in r.location
    r = b.get('/samples')
    assert r.status_code == 302 and '/account/change-password' in r.location
    r = b.post('/account/change-password', {'current_password': PASSWORD, 'new_password': 'short1',
                                            'confirm_password': 'short1'})
    assert b'at least 10 characters' in r.data
    r = b.post('/account/change-password', {'current_password': PASSWORD, 'new_password': 'NewPassword123',
                                            'confirm_password': 'NewPassword123'})
    assert r.status_code == 302
    assert b.get('/samples').status_code == 200


def test_new_password_must_differ_from_temporary(make_user):
    u = make_user('staff', must_change=True)
    b = Browser()
    b.login(u['username'])
    r = b.post('/account/change-password', {'current_password': PASSWORD, 'new_password': PASSWORD,
                                            'confirm_password': PASSWORD})
    assert r.status_code == 200 and b'different' in r.data


def test_logout_ends_session(login_as):
    b = login_as('staff')
    b.get('/logout')
    assert b.get('/').status_code == 302


def test_security_headers(login_as):
    r = login_as('staff').get('/')
    h = r.headers
    assert h['X-Frame-Options'] == 'DENY'
    assert h['X-Content-Type-Options'] == 'nosniff'
    assert "frame-ancestors 'none'" in h['Content-Security-Policy']
    assert 'no-store' in h['Cache-Control']


def test_friendly_error_pages(login_as):
    b = login_as('staff')
    r = b.get('/orders/999999')
    assert r.status_code == 404 and b'LabOS' in r.data
    r = b.get('/admin/users')
    assert r.status_code == 403 and b'LabOS' in r.data


def test_health_endpoint_is_public():
    r = Browser().get('/health')
    assert r.status_code == 200 and r.json['status'] == 'ok'


def test_suite_uses_requested_database(app):
    import os
    expected = 'postgresql' if os.environ.get('LABOS_TEST_DATABASE_URL') else 'sqlite'
    with app.app.app_context():
        assert app.db.engine.dialect.name == expected
