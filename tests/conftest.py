"""Test harness for LabOS.

The app configures itself from environment variables at import time, so the
environment is set here before `app` is imported. Every test run uses a fresh
SQLite database in a temp folder and never touches lis_v7.db or a real database.
Privileged-MFA enforcement is ON, matching production.
"""
import io
import itertools
import os
import sys
import tempfile

import pyotp
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TMP = tempfile.mkdtemp(prefix='labos-tests-')
# Set LABOS_TEST_DATABASE_URL to an empty Postgres database to run the suite against Postgres (as in production).
os.environ['DATABASE_URL'] = os.environ.get('LABOS_TEST_DATABASE_URL') or 'sqlite:///' + os.path.join(_TMP, 'test.db').replace(os.sep, '/')
os.environ['LIS_SECRET_KEY'] = 'test-secret-key-not-for-production'
os.environ['REQUIRE_PRIVILEGED_MFA'] = '1'
os.environ['COOKIE_SECURE'] = '0'
os.environ['LOGIN_FAILURE_LIMIT'] = '5'
os.environ['IDLE_TIMEOUT_MINUTES'] = '20'
sys.path.insert(0, ROOT)

import app as labos  # noqa: E402

PASSWORD = 'Correct-Horse-42x'
_seq = itertools.count(1)


def uniq(prefix):
    return f'{prefix}{next(_seq)}'


class Browser:
    """A test client that behaves like the real browser page: it sends the session CSRF token on every POST."""

    def __init__(self):
        self.c = labos.app.test_client()

    def csrf(self):
        with self.c.session_transaction() as s:
            if '_csrf_token' not in s:
                s['_csrf_token'] = 'test-csrf-token'
            return s['_csrf_token']

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def post(self, url, data=None, csrf=True, **kw):
        data = dict(data or {})
        if csrf:
            data.setdefault('_csrf_token', self.csrf())
        return self.c.post(url, data=data, **kw)

    def login(self, identity, password=PASSWORD, totp_secret=None):
        r = self.post('/login', {'identity': identity, 'password': password})
        if totp_secret and r.status_code == 302 and r.location.endswith('/mfa'):
            r = self.post('/mfa', {'code': pyotp.TOTP(totp_secret).now()})
        return r

    def session(self):
        with self.c.session_transaction() as s:
            return dict(s)


@pytest.fixture(scope='session')
def app():
    labos.app.config['TESTING'] = True
    return labos


@pytest.fixture(scope='session')
def master(app):
    """Runs the real first-run setup flow once and returns the master admin (with MFA enrolled)."""
    b = Browser()
    with app.app.app_context():
        assert app.User.query.count() == 0, 'test DB should start empty'
    r = b.get('/login')
    assert r.status_code == 302 and '/setup' in r.location, 'empty install must redirect to first-run setup'
    r = b.post('/setup', {'name': 'Ada Admin', 'username': 'admin', 'email': 'admin@example.test',
                          'password': PASSWORD, 'confirm_password': PASSWORD})
    assert r.status_code == 302 and '/login' in r.location
    with app.app.app_context():
        u = app.User.query.filter_by(username='admin').one()
        assert u.role == 'master'
        secret = pyotp.random_base32()
        u.mfa_secret, u.mfa_enabled = secret, True
        app.db.session.commit()
        return {'id': u.id, 'username': 'admin', 'secret': secret}


@pytest.fixture
def make_user(app, master):
    """Create a user directly in the DB. Privileged roles get MFA enrolled unless mfa=False."""
    def _make(role, clinic_id=None, mfa=None, must_change=False, active=True):
        name = uniq(role)
        with app.app.app_context():
            secret = pyotp.random_base32() if (mfa if mfa is not None else role in ('director', 'master')) else None
            u = app.User(name=f'Test {name}', username=name, email=f'{name}@example.test',
                         password_hash=app.generate_password_hash(PASSWORD), role=role,
                         organization='Complete Omics Inc.', clinic_id=clinic_id, active=active,
                         must_change_password=must_change, mfa_secret=secret, mfa_enabled=bool(secret))
            app.db.session.add(u)
            app.db.session.commit()
            return {'id': u.id, 'username': name, 'secret': secret, 'role': role, 'clinic_id': clinic_id}
    return _make


@pytest.fixture
def make_clinic(app, master):
    def _make(name=None):
        with app.app.app_context():
            c = app.Clinic(name=name or uniq('Clinic '), code=uniq('CL'), active=True)
            app.db.session.add(c)
            app.db.session.commit()
            return c.id
    return _make


@pytest.fixture
def login_as(make_user):
    """login_as('staff') -> signed-in Browser plus the user record."""
    def _login(role, **kw):
        user = make_user(role, **kw)
        b = Browser()
        r = b.login(user['username'], totp_secret=user['secret'])
        assert r.status_code == 302, r.data[:300]
        b.user = user
        return b
    return _login


@pytest.fixture
def admin_browser(master):
    b = Browser()
    r = b.login('admin', totp_secret=master['secret'])
    assert r.status_code == 302
    return b


def ids_for(app, *codes):
    with app.app.app_context():
        return [app.Test.query.filter_by(code=c).one().id for c in codes]


def xlsx_bytes(rows, sheet='September'):
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = sheet
    for r in rows:
        ws.append(r)
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


def pytest_report_header(config):
    with labos.app.app_context():
        return f"LabOS test database: {labos.db.engine.dialect.name}"
