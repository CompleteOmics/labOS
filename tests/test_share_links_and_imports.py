"""Public request links, clinic roster, standing orders, clinic Excel import and instrument result import."""
import io
from datetime import timedelta

from conftest import Browser, ids_for, xlsx_bytes


def create_link(app, director, clinic_id=None, codes=('TSH',), days=30):
    ids = ids_for(app, *codes)
    director.post('/share-links', {'label': 'Test link', 'expires_days': str(days), 'clinic_id': str(clinic_id or ''),
                                   'tests': [str(i) for i in ids]})
    with app.app.app_context():
        link = app.ShareLink.query.order_by(app.ShareLink.id.desc()).first()
        return link.id, link.token


def public_form(app, codes=('TSH',), **kw):
    data = {'requester_name': 'Dr. External', 'requester_email': 'ext@example.test', 'provider_name': 'Dr. External',
            'patient_name': 'Public Patient', 'patient_dob': '1990-02-02', 'tests': [str(i) for i in ids_for(app, *codes)]}
    data.update(kw)
    return data


def test_share_link_request_flow(app, login_as, make_clinic):
    clinic = make_clinic()
    director = login_as('director')
    link_id, token = create_link(app, director, clinic_id=clinic)
    assert director.get('/share-links').status_code == 200

    anon = Browser()
    assert anon.get(f'/request/{token}').status_code == 200
    r = anon.post(f'/request/{token}', public_form(app))
    assert r.status_code == 302 and '/submitted/' in r.location
    code = r.location.rstrip('/').split('/')[-1]
    assert anon.get(r.location).status_code == 200
    assert anon.get(f'/request/{token}/submitted/{code}/requisition.pdf').data[:4] == b'%PDF'

    with app.app.app_context():
        o = app.Order.query.filter_by(confirmation_code=code).one()
        assert o.clinic_id == clinic and o.share_link_id == link_id and o.status == 'Submitted'
        assert app.db.session.get(app.ShareLink, link_id).use_count == 1

    # submitter can correct, then cancel, before receipt
    anon.post(f'/request/{token}/submitted/{code}/edit', public_form(app, patient_name='Fixed Name'))
    anon.post(f'/request/{token}/submitted/{code}/edit', {'action': 'cancel_order'})
    with app.app.app_context():
        o = app.Order.query.filter_by(confirmation_code=code).one()
        assert o.patient_name == 'Fixed Name' and o.status == 'Cancelled'


def test_share_link_rejects_bad_input(app, login_as):
    director = login_as('director')
    link_id, token = create_link(app, director, codes=('TSH',))
    anon = Browser()
    with app.app.app_context():
        before = app.Order.query.count()
    anon.post(f'/request/{token}', public_form(app, codes=('NTPROBNP',)))           # test not allowed by link
    anon.post(f'/request/{token}', public_form(app, patient_name=''))               # missing patient
    anon.post(f'/request/{token}', public_form(app, requester_email=''))            # missing requester
    with app.app.app_context():
        assert app.Order.query.count() == before
    assert anon.get('/request/not-a-real-token').status_code == 410


def test_share_link_disable_and_expiry(app, login_as):
    director = login_as('director')
    link_id, token = create_link(app, director)
    director.post(f'/share-links/{link_id}/toggle')
    assert Browser().get(f'/request/{token}').status_code == 410
    director.post(f'/share-links/{link_id}/toggle')
    assert Browser().get(f'/request/{token}').status_code == 200
    with app.app.app_context():
        app.db.session.get(app.ShareLink, link_id).expires_at = app.utcnow() - timedelta(days=1)
        app.db.session.commit()
    assert Browser().get(f'/request/{token}').status_code == 410


def test_share_link_bad_expiry_value(app, login_as):
    director = login_as('director')
    r = director.post('/share-links', {'label': 'x', 'expires_days': 'soon'})
    assert r.status_code in (302, 400)


def test_clinic_create_and_duplicates(app, login_as):
    d = login_as('director')
    d.post('/admin/clinics', {'action': 'create', 'name': 'Harbor Test Clinic'})
    r = d.post('/admin/clinics', {'action': 'create', 'name': 'harbor test clinic'}, follow_redirects=True)
    assert b'already exists' in r.data
    with app.app.app_context():
        assert app.Clinic.query.filter(app.db.func.lower(app.Clinic.name) == 'harbor test clinic').count() == 1


def test_clinic_roster_import_csv_utf8_cp1252_and_xlsx(app, login_as):
    d = login_as('director')
    csv_utf8 = 'clinic_id,clinic_name,hart_cadhs,hart_cve\r\nRST-1,Roster Clinic One,Yes,No\r\nRST-2,Clínica Dos,No,Yes\r\n'.encode('utf-8')
    r = d.post('/admin/clinics', {'action': 'import', 'roster': (io.BytesIO(csv_utf8), 'roster.csv')}, follow_redirects=True)
    assert b'2 clinics created' in r.data
    # re-import is idempotent
    r = d.post('/admin/clinics', {'action': 'import', 'roster': (io.BytesIO(csv_utf8), 'roster.csv')}, follow_redirects=True)
    assert b'0 clinics created, 2 existing' in r.data
    cp = 'clinic_id,clinic_name\r\nRST-3,Caf\xe9 Clinic\r\n'.encode('latin-1')
    r = d.post('/admin/clinics', {'action': 'import', 'roster': (io.BytesIO(cp), 'roster.csv')}, follow_redirects=True)
    assert b'1 clinics created' in r.data
    x = xlsx_bytes([['clinic_id', 'clinic_name'], ['RST-4', 'Excel Clinic']], sheet='Clinics')
    r = d.post('/admin/clinics', {'action': 'import', 'roster': (io.BytesIO(x), 'roster.xlsx')}, follow_redirects=True)
    assert b'1 clinics created' in r.data
    with app.app.app_context():
        c1 = app.Clinic.query.filter_by(code='RST-1').one()
        so = app.StandingOrder.query.filter_by(clinic_id=c1.id).one()
        assert so.hart_cadhs and not so.hart_cve
        assert app.Clinic.query.filter_by(code='RST-3').one().name == 'Café Clinic'
    # conflicting ID aborts the whole import
    bad = 'clinic_id,clinic_name\r\nRST-1,Different Name\r\nRST-9,Should Not Exist\r\n'.encode()
    r = d.post('/admin/clinics', {'action': 'import', 'roster': (io.BytesIO(bad), 'roster.csv')}, follow_redirects=True)
    assert b'Roster not imported' in r.data
    with app.app.app_context():
        assert app.Clinic.query.filter_by(code='RST-9').count() == 0


def test_standing_orders_and_excel_import(app, login_as, make_clinic):
    staff = login_as('staff')
    clinic = make_clinic('Excel Import Clinic')
    staff.post('/standing-orders', {'clinic_id': str(clinic), 'hart_cadhs': '1', 'active': '1'})
    rows = [['Sample ID', 'Date Received', 'Account Name', 'Patient Last Name', 'Patient First Name', 'DOB', 'Sex', 'CVE'],
            ['SAM-9001', '2026-09-01', 'Excel Import Clinic', 'Doe', 'Jane', '1970-03-04', 'F', ''],
            ['SAM-9002', '2026-09-01', 'Excel Import Clinic', 'Roe', 'Rick', '1968-11-30', 'M', 'Yes'],
            ['', '2026-09-01', 'Excel Import Clinic', 'Nobody', 'No', '1960-01-01', 'M', '']]
    data = xlsx_bytes(rows)
    r = staff.post('/orders/import-clinic-excel', {'mode': 'preview', 'workbook': (io.BytesIO(data), 'orders.xlsx')})
    assert r.status_code == 200 and b'SAM-9001' in r.data
    with app.app.app_context():
        assert app.Order.query.filter_by(accession_no='SAM-9001').count() == 0
    r = staff.post('/orders/import-clinic-excel', {'mode': 'commit', 'workbook': (io.BytesIO(data), 'orders.xlsx')})
    assert r.status_code == 200
    with app.app.app_context():
        o1 = app.Order.query.filter_by(accession_no='SAM-9001').one()
        o2 = app.Order.query.filter_by(accession_no='SAM-9002').one()
        codes1 = {app.db.session.get(app.Test, x.test_id).code for x in app.OrderTest.query.filter_by(order_id=o1.id)}
        codes2 = {app.db.session.get(app.Test, x.test_id).code for x in app.OrderTest.query.filter_by(order_id=o2.id)}
        assert codes1 == {'HART-CADHS'}          # standing order applied
        assert codes2 == {'HART-CVE'}            # explicit spreadsheet flag wins
        assert o1.status == 'Received' and o1.clinic_id == clinic
    # duplicate import does not create duplicates
    staff.post('/orders/import-clinic-excel', {'mode': 'commit', 'workbook': (io.BytesIO(data), 'orders.xlsx')})
    with app.app.app_context():
        assert app.Order.query.filter_by(accession_no='SAM-9001').count() == 1
    r = staff.post('/orders/import-clinic-excel', {'mode': 'preview', 'workbook': (io.BytesIO(b'not excel'), 'x.xlsx')})
    assert r.status_code == 200 and b'could not be read' in r.data


def _received_order(app, staff, code='TSH'):
    tid, = ids_for(app, code)
    r = staff.post('/orders/new', {'patient_name': 'Instrument Patient', 'tests': [str(tid)]})
    oid = int(r.location.rstrip('/').split('/')[-1])
    staff.post(f'/orders/{oid}', {'action': 'receive'})
    staff.post(f'/orders/{oid}', {'action': 'testing'})
    with app.app.app_context():
        return oid, app.db.session.get(app.Order, oid).accession_no


def test_instrument_import(app, login_as):
    staff, director = login_as('staff'), login_as('director')
    oid, acc = _received_order(app, staff)
    csv_data = f'accession_no,test_code,result\n{acc},TSH,2.75\nNOPE-1,TSH,1\n{acc},NTPROBNP,5\n'.encode()
    r = staff.post('/instrument-import', {'file': (io.BytesIO(csv_data), 'results.csv')}, follow_redirects=True)
    assert b'Imported 1 result' in r.data
    with app.app.app_context():
        o = app.db.session.get(app.Order, oid)
        ot = app.OrderTest.query.filter_by(order_id=oid).one()
        assert o.status == 'Review' and ot.result == '2.75'
        # imported results go through the same automated checks as manual entry
        assert app.AutoVerificationEvent.query.filter_by(order_test_id=ot.id).count() == 1
    director.post(f'/orders/{oid}', {'action': 'approve', 'override_reason': 'ok'})
    # a later import must not overwrite a released result
    csv2 = f'accession_no,test_code,result\n{acc},TSH,99\n'.encode()
    staff.post('/instrument-import', {'file': (io.BytesIO(csv2), 'results.csv')})
    with app.app.app_context():
        o = app.db.session.get(app.Order, oid)
        ot = app.OrderTest.query.filter_by(order_id=oid).one()
        assert o.status == 'Released' and ot.result == '2.75'


def test_reference_interval_import_and_edit(app, login_as):
    d = login_as('director')
    csv_data = b'Test Code,Sex,Lower Limit,Upper Limit,Unit,Active\nTSH,Any,0.45,4.5,uIU/mL,Yes\nNOPE,Any,1,2,x,Yes\n'
    r = d.post('/reference-intervals', {'file': (io.BytesIO(csv_data), 'ri.csv')}, follow_redirects=True)
    assert b'Imported 1 reference interval' in r.data and b'NOPE' in r.data
    with app.app.app_context():
        ri = app.ReferenceInterval.query.filter_by(lower_limit=0.45).first()
        rid = ri.id
    d.post(f'/reference-intervals/{rid}/edit', {'sex': 'Any', 'lower_limit': '0.5', 'upper_limit': '4.2', 'active': '1'})
    d.post(f'/reference-intervals/{rid}/toggle')
    with app.app.app_context():
        ri = app.db.session.get(app.ReferenceInterval, rid)
        assert ri.lower_limit == 0.5 and ri.active is False
    tid, = ids_for(app, 'TSH')
    d.post('/reference-intervals/add', {'test_id': str(tid), 'lower_limit': '0.3', 'upper_limit': '5', 'active': '1'})
    d.post(f'/reference-intervals/{rid}/delete')
    with app.app.app_context():
        assert app.db.session.get(app.ReferenceInterval, rid) is None
    assert d.get('/reference-intervals/template.xlsx').status_code == 200
