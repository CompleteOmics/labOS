"""Role-based access and clinic data isolation."""
import pytest

from conftest import Browser, ids_for

LAB_PAGES = ['/samples', '/batches', '/worksheets', '/plates', '/qc', '/qc/lot-comparison', '/quality-policies',
             '/inventory', '/calculations', '/tests', '/diagnostics-menu', '/loinc-mapping', '/toxicology',
             '/reference-intervals', '/instrument-import', '/standing-orders', '/orders/import-clinic-excel',
             '/export/inventory.csv', '/loinc-mapping/export.csv', '/toxicology/export.csv', '/diagnostics-menu/export',
             '/instrument-import/template.csv', '/reference-intervals/template.csv']
ADMIN_PAGES = ['/admin/users', '/admin/clinics', '/share-links', '/finance', '/finance/export.csv', '/audit',
               '/audit/export.csv', '/compliance', '/interoperability', '/admin/branding']
COMMON_PAGES = ['/', '/orders', '/orders/new', '/export/orders.csv', '/security/mfa', '/account/change-password']


@pytest.mark.parametrize('path', LAB_PAGES + ADMIN_PAGES + COMMON_PAGES)
def test_anonymous_is_sent_to_login(master, path):
    r = Browser().get(path)
    assert r.status_code in (302, 401)
    if r.status_code == 302:
        assert '/login' in r.location


def test_provider_access(login_as, make_clinic):
    b = login_as('customer', clinic_id=make_clinic())
    for p in COMMON_PAGES:
        assert b.get(p).status_code == 200, p
    for p in LAB_PAGES + ADMIN_PAGES:
        assert b.get(p).status_code == 403, p


def test_staff_access(login_as):
    b = login_as('staff')
    for p in COMMON_PAGES + LAB_PAGES:
        assert b.get(p).status_code == 200, p
    for p in ADMIN_PAGES:
        assert b.get(p).status_code == 403, p


@pytest.mark.parametrize('role', ['director', 'master'])
def test_director_and_master_access(login_as, role):
    b = login_as(role)
    for p in COMMON_PAGES + LAB_PAGES + ADMIN_PAGES:
        assert b.get(p).status_code == 200, p


def _provider_order(b, app, patient='Iso Patient'):
    tid, = ids_for(app, 'TSH')
    r = b.post('/orders/new', {'patient_name': patient, 'patient_dob': '1980-01-01', 'tests': [str(tid)]})
    assert r.status_code == 302
    return int(r.location.rstrip('/').split('/')[-1])


def test_clinic_isolation(app, login_as, make_clinic):
    ca, cb = make_clinic(), make_clinic()
    doc_a1, doc_a2, doc_b = login_as('customer', clinic_id=ca), login_as('customer', clinic_id=ca), login_as('customer', clinic_id=cb)
    oid_a = _provider_order(doc_a1, app, 'Alpha Patient')
    oid_b = _provider_order(doc_b, app, 'Bravo Patient')

    # Same clinic shares a queue
    assert doc_a2.get(f'/orders/{oid_a}').status_code == 200
    assert b'Alpha Patient' in doc_a2.get('/orders').data
    # Other clinic cannot see, search, export or download
    assert doc_b.get(f'/orders/{oid_a}').status_code == 403
    assert doc_b.get(f'/orders/{oid_a}/report.pdf').status_code == 403
    assert b'Alpha Patient' not in doc_b.get('/orders').data
    assert b'Alpha Patient' not in doc_b.get('/orders?q=Alpha').data
    assert b'Alpha Patient' not in doc_b.get('/export/orders.csv').data
    assert b'Alpha Patient' not in doc_b.get('/').data
    # and cannot modify it
    r = doc_b.post(f'/orders/{oid_a}', {'action': 'provider_cancel'})
    assert r.status_code == 403
    r = doc_b.post(f'/orders/{oid_a}', {'action': 'delete_mistaken_order'})
    assert r.status_code == 403
    with app.app.app_context():
        assert app.db.session.get(app.Order, oid_a).status == 'Submitted'
    assert doc_a1.get(f'/orders/{oid_b}').status_code == 403


def test_provider_without_clinic_sees_only_own_orders(app, login_as):
    d1, d2 = login_as('customer'), login_as('customer')
    oid = _provider_order(d1, app, 'Solo Patient')
    assert d1.get(f'/orders/{oid}').status_code == 200
    assert d2.get(f'/orders/{oid}').status_code == 403


def test_provider_cannot_use_lab_actions(app, login_as, make_clinic):
    doc = login_as('customer', clinic_id=make_clinic())
    oid = _provider_order(doc, app)
    for action in ('receive', 'testing', 'save_results', 'approve', 'billing_update'):
        doc.post(f'/orders/{oid}', {'action': action})
    with app.app.app_context():
        o = app.db.session.get(app.Order, oid)
        assert o.status == 'Submitted' and not o.accession_no


def test_staff_cannot_release_results(app, login_as):
    staff = login_as('staff')
    oid = _provider_order(staff, app)
    staff.post(f'/orders/{oid}', {'action': 'receive'})
    staff.post(f'/orders/{oid}', {'action': 'testing'})
    with app.app.app_context():
        ot = app.OrderTest.query.filter_by(order_id=oid).one()
    staff.post(f'/orders/{oid}', {'action': 'save_results', f'result_{ot.id}': '2.1'})
    staff.post(f'/orders/{oid}', {'action': 'approve'})
    with app.app.app_context():
        assert app.db.session.get(app.Order, oid).status == 'Review'


def test_director_cannot_create_master_or_manage_directors(app, login_as):
    d = login_as('director')
    r = d.post('/admin/users', {'action': 'create', 'role': 'director', 'name': 'X', 'username': 'x_dir', 'email': 'x_dir@example.test'})
    assert r.status_code == 403
    r = d.post('/admin/users', {'action': 'create', 'role': 'master', 'name': 'X', 'username': 'x_m', 'email': 'x_m@example.test'})
    assert r.status_code == 403
    r = d.post('/admin/users', {'action': 'create', 'role': 'superuser', 'name': 'X', 'username': 'x_s', 'email': 'x_s@example.test'})
    assert r.status_code == 400


def test_master_can_create_and_promote_masters(app, login_as, make_user):
    import pyotp
    from conftest import PASSWORD
    admin = login_as('master')
    r = admin.post('/admin/users', {'action': 'create', 'role': 'master', 'name': 'Qing Test', 'username': 'qing_test', 'email': 'qing_test@example.test'}, follow_redirects=True)
    assert b'Temporary password (show once)' in r.data
    with app.app.app_context():
        q = app.User.query.filter_by(username='qing_test').one()
        assert q.role == 'master' and q.must_change_password and not q.mfa_enabled

    # promote an existing staff account; it becomes a full admin but must enrol MFA first
    staff = make_user('staff')
    admin.post('/admin/users', {'action': 'set_role', 'user_id': str(staff['id']), 'role': 'master'})
    with app.app.app_context():
        assert app.db.session.get(app.User, staff['id']).role == 'master'
    b = Browser()
    b.login(staff['username'])
    r = b.get('/admin/users')
    assert r.status_code == 302 and '/security/mfa' in r.location
    b.post('/security/mfa', {'action': 'start'})
    b.post('/security/mfa', {'action': 'enable', 'code': pyotp.TOTP(b.session()['mfa_setup_secret']).now()})
    assert b.get('/admin/users').status_code == 200

    # role changes are audited; customer -> staff clears the clinic link
    doc = make_user('customer', clinic_id=None)
    admin.post('/admin/users', {'action': 'set_role', 'user_id': str(doc['id']), 'role': 'staff'})
    with app.app.app_context():
        assert app.db.session.get(app.User, doc['id']).role == 'staff'
        assert app.Audit.query.filter_by(action='USER_ROLE_CHANGE', entity_id=doc['id']).count() == 1


def test_role_change_guards(app, login_as, make_user):
    admin, director = login_as('master'), login_as('director')
    staff = make_user('staff')
    # directors cannot change roles
    assert director.post('/admin/users', {'action': 'set_role', 'user_id': str(staff['id']), 'role': 'master'}).status_code == 403
    # no invalid roles
    assert admin.post('/admin/users', {'action': 'set_role', 'user_id': str(staff['id']), 'role': 'god'}).status_code == 400
    # cannot change your own role
    admin.post('/admin/users', {'action': 'set_role', 'user_id': str(admin.user['id']), 'role': 'staff'})
    with app.app.app_context():
        assert app.db.session.get(app.User, admin.user['id']).role == 'master'
        assert app.db.session.get(app.User, staff['id']).role == 'staff'


def test_master_can_demote_another_master_but_one_always_remains(app, login_as, make_user):
    admin = login_as('master')
    other = make_user('master')
    admin.post('/admin/users', {'action': 'set_role', 'user_id': str(other['id']), 'role': 'director'})
    with app.app.app_context():
        assert app.db.session.get(app.User, other['id']).role == 'director'
    # the acting admin can never demote themselves, so an active master always remains
    admin.post('/admin/users', {'action': 'set_role', 'user_id': str(admin.user['id']), 'role': 'director'})
    with app.app.app_context():
        assert app.db.session.get(app.User, admin.user['id']).role == 'master'
