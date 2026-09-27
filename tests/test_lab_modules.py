"""Samples, batches, worksheets, plates, QC, inventory, calculations, admin screens and the audit chain."""
import threading

import pytest

from conftest import ids_for, uniq


def _sample(app, staff):
    tid, = ids_for(app, 'TSH')
    r = staff.post('/orders/new', {'patient_name': 'Bench Patient', 'tests': [str(tid)]})
    oid = int(r.location.rstrip('/').split('/')[-1])
    staff.post(f'/orders/{oid}', {'action': 'receive'})
    with app.app.app_context():
        return app.Sample.query.filter_by(order_id=oid).one().id


def _last_id(app, model):
    with app.app.app_context():
        return app.db.session.query(app.db.func.max(model.id)).scalar()


def test_batch_lifecycle(app, login_as):
    staff = login_as('staff')
    sid = _sample(app, staff)
    r = staff.post('/batches', {'name': 'Luminex run', 'method': 'Luminex', 'instrument': 'FLEXMAP 3D'})
    bid = int(r.location.rstrip('/').split('/')[-1])
    staff.post(f'/batches/{bid}', {'action': 'add_sample', 'sample_id': str(sid), 'position': 'A1'})
    staff.post(f'/batches/{bid}', {'action': 'add_sample', 'sample_id': str(sid), 'position': 'A1'})  # no duplicate
    with app.app.app_context():
        assert app.BatchSample.query.filter_by(batch_id=bid).count() == 1
    assert staff.get(f'/batches/{bid}').status_code == 200
    # a batch with work attached cannot be deleted
    staff.post(f'/batches/{bid}', {'action': 'delete_batch'})
    with app.app.app_context():
        assert app.db.session.get(app.Batch, bid) is not None
    staff.post(f'/batches/{bid}', {'action': 'status', 'status': 'Completed'})
    with app.app.app_context():
        b = app.db.session.get(app.Batch, bid)
        assert b.status == 'Completed' and b.run_at
    # nonsense input is rejected cleanly
    for data in ({'action': 'add_sample', 'sample_id': 'abc'}, {'action': 'add_sample', 'sample_id': '999999'},
                 {'action': 'status', 'status': 'Exploded'}):
        r = staff.post(f'/batches/{bid}', data)
        assert r.status_code in (302, 400), data
    with app.app.app_context():
        assert app.db.session.get(app.Batch, bid).status == 'Completed'
        assert app.BatchSample.query.filter_by(batch_id=bid).count() == 1
    # empty batch can be deleted
    r = staff.post('/batches', {'name': 'Mistake'})
    empty = int(r.location.rstrip('/').split('/')[-1])
    staff.post(f'/batches/{empty}', {'action': 'delete_batch'})
    with app.app.app_context():
        assert app.db.session.get(app.Batch, empty) is None


def test_worksheet_lifecycle(app, login_as):
    staff, director = login_as('staff'), login_as('director')
    r = staff.post('/worksheets', {'title': 'Plate prep sheet'})
    wid = int(r.location.rstrip('/').split('/')[-1])
    staff.post(f'/worksheets/{wid}', {'action': 'add_entry', 'row_label': 'Dilution', 'value': '1:2', 'unit': 'x'})
    staff.post(f'/worksheets/{wid}', {'action': 'approve'})
    with app.app.app_context():
        assert app.db.session.get(app.Worksheet, wid).status == 'Draft'
    director.post(f'/worksheets/{wid}', {'action': 'approve'})
    with app.app.app_context():
        assert app.db.session.get(app.Worksheet, wid).status == 'Approved'
    staff.post(f'/worksheets/{wid}', {'action': 'delete_worksheet'})
    with app.app.app_context():
        assert app.db.session.get(app.Worksheet, wid) is not None
    r = staff.post('/worksheets', {'title': 'Bad batch', 'batch_id': 'xyz'})
    assert r.status_code in (302, 400)


def test_plate_map(app, login_as):
    staff = login_as('staff')
    sid = _sample(app, staff)
    r = staff.post('/plates', {'name': 'Plate 1'})
    pid = int(r.location.rstrip('/').split('/')[-1].split('?')[0])
    staff.post(f'/plates/{pid}', {'well': 'B7', 'well_type': 'Sample', 'sample_id': str(sid), 'label': 'pt'})
    staff.post(f'/plates/{pid}', {'well': 'H12', 'well_type': 'Standard', 'label': 'STD1', 'concentration': '100'})
    assert staff.post(f'/plates/{pid}', {'well': 'Z99'}).status_code == 400
    assert staff.post(f'/plates/{pid}', {'well': 'A1', 'sample_id': '999999'}).status_code == 400
    with app.app.app_context():
        assert app.PlateWell.query.filter_by(plate_id=pid).count() == 2
    staff.post(f'/plates/{pid}', {'well': 'B7', 'action': 'erase'})
    with app.app.app_context():
        assert app.PlateWell.query.filter_by(plate_id=pid).count() == 1
    assert staff.get(f'/plates/{pid}?well=H12').status_code == 200


def test_qc_definition_results_review_and_chart(app, login_as):
    staff, director = login_as('staff'), login_as('director')
    tid, = ids_for(app, 'TSH')
    name = uniq('TSH QC ')
    staff.post('/qc', {'action': 'definition', 'name': 'staff cannot', 'test_id': str(tid), 'level': 'L1', 'target_mean': '5', 'target_sd': '1'})
    director.post('/qc', {'action': 'definition', 'name': name, 'test_id': str(tid), 'level': 'L1', 'target_mean': '5', 'target_sd': '0.5', 'lot': 'LOT1'})
    with app.app.app_context():
        assert app.QCDefinition.query.filter_by(name='staff cannot').count() == 0
        qd = app.QCDefinition.query.filter_by(name=name).one().id
    for v, expected in (('5.1', 'Accept'), ('6.2', 'Warning'), ('7.0', 'Reject')):
        staff.post('/qc', {'action': 'result', 'qc_definition_id': str(qd), 'value': v})
        with app.app.app_context():
            assert app.QCResult.query.order_by(app.QCResult.id.desc()).first().status == expected, v
    qr = _last_id(app, app.QCResult)
    staff.post(f'/qc/review/{qr}', {'decision': 'Rejected run', 'notes': 'recalibrated', 'corrective_action': 'rerun'})
    with app.app.app_context():
        assert app.QCReview.query.filter_by(qc_result_id=qr).count() == 1
    assert staff.get(f'/qc/{qd}/chart').status_code == 200
    # bad numbers / zero SD do not crash
    for data in ({'action': 'result', 'qc_definition_id': str(qd), 'value': 'high'},
                 {'action': 'definition', 'name': 'zero sd', 'test_id': str(tid), 'level': 'L1', 'target_mean': '5', 'target_sd': '0'},
                 {'action': 'definition', 'name': 'bad mean', 'test_id': str(tid), 'level': 'L1', 'target_mean': 'x', 'target_sd': '1'}):
        r = director.post('/qc', data)
        assert r.status_code in (302, 400), data
    with app.app.app_context():
        assert app.QCDefinition.query.filter_by(name='zero sd').count() == 0


def test_lot_comparison(app, login_as):
    staff = login_as('staff')
    tid, = ids_for(app, 'TSH')
    staff.post('/qc/lot-comparison', {'test_id': str(tid), 'old_lot': 'A', 'new_lot': 'B', 'old_values': '10,10.2,9.8', 'new_values': '10.1,10.3,9.9', 'acceptance_limit': '5'})
    with app.app.app_context():
        rec = app.QCLotComparison.query.order_by(app.QCLotComparison.id.desc()).first()
        assert rec.status == 'Accept' and rec.pairs == 3
    r = staff.post('/qc/lot-comparison', {'test_id': str(tid), 'old_lot': 'A', 'new_lot': 'B', 'old_values': '1,x', 'new_values': '1,2'})
    assert r.status_code in (302, 400)


def test_quality_policy_update(app, login_as):
    director = login_as('director')
    with app.app.app_context():
        p = app.QCPolicy.query.first()
        if p is None:
            pytest.skip('no QC policies seeded')
        pid, was = p.id, p.enabled
    with app.app.app_context():
        severity = app.db.session.get(app.QCPolicy, pid).severity
    director.post('/quality-policies', {'policy_id': str(pid), 'enabled': '' if was else 'on', 'severity': 'Hold'})
    with app.app.app_context():
        assert app.db.session.get(app.QCPolicy, pid).enabled != was
    director.post('/quality-policies', {'policy_id': str(pid), 'enabled': 'on' if was else '', 'severity': severity})
    with app.app.app_context():
        assert app.db.session.get(app.QCPolicy, pid).enabled == was


def test_inventory_and_export(app, login_as):
    staff = login_as('staff')
    item = uniq('Reagent ')
    staff.post('/inventory', {'item_name': item, 'lot_no': 'L1', 'quantity': '12', 'expiration_date': '2027-01-01'})
    assert item.encode() in staff.get('/export/inventory.csv').data
    r = staff.post('/inventory', {'item_name': 'Bad qty', 'quantity': 'lots'})
    assert r.status_code in (302, 400)


def test_calculation_rules(app, login_as):
    staff, director = login_as('staff'), login_as('director')
    staff.post('/calculations', {'name': 'x', 'output_code': 'STAFFCALC', 'expression': '1+1'})
    director.post('/calculations', {'name': 'Ratio', 'output_code': 'RATIO1', 'expression': 'KIM1 / 2'})
    with app.app.app_context():
        assert app.CalculationRule.query.filter_by(output_code='STAFFCALC').count() == 0
        assert app.CalculationRule.query.filter_by(output_code='RATIO1').count() == 1


def test_test_catalog_and_loinc(app, login_as):
    director = login_as('director')
    code = uniq('NEWT')
    director.post('/tests', {'code': code, 'name': 'New assay', 'unit': 'mg/dL', 'ref_low': '1', 'ref_high': '2'})
    r = director.post('/tests', {'code': code, 'name': 'Duplicate'}, follow_redirects=True)
    assert b'Could not add test' in r.data
    with app.app.app_context():
        tid = app.Test.query.filter_by(code=code).one().id
    director.post('/loinc-mapping', {'test_id': str(tid), 'loinc_code': '1234-5', 'loinc_status': 'READY'})
    with app.app.app_context():
        assert app.db.session.get(app.Test, tid).loinc_code == '1234-5'
    assert b'1234-5' in director.get('/loinc-mapping/export.csv').data


def test_diagnostics_toggle_and_toxicology_review(app, login_as):
    director = login_as('director')
    with app.app.app_context():
        t = app.Test.query.filter(app.Test.code.in_(list(app.DIAGNOSTIC_META))).first()
        tid, was = t.id, t.active
    director.post(f'/diagnostics-menu/toggle/{tid}')
    with app.app.app_context():
        assert app.db.session.get(app.Test, tid).active != was
    director.post(f'/diagnostics-menu/toggle/{tid}')
    director.post('/toxicology/batch-review', {'run_name': 'Run 1', 'calibrators_ok': '1', 'qc_ok': '1'})
    with app.app.app_context():
        assert app.ToxicologyBatchReview.query.order_by(app.ToxicologyBatchReview.id.desc()).first().decision == 'Hold'


def test_user_admin_lifecycle(app, login_as, master):
    admin = login_as('master')
    uname = uniq('newdoc')
    r = admin.post('/admin/users', {'action': 'create', 'role': 'customer', 'name': 'New Doc', 'username': uname, 'email': f'{uname}@example.test'}, follow_redirects=True)
    assert b'Temporary password (show once)' in r.data
    r = admin.post('/admin/users', {'action': 'create', 'role': 'staff', 'name': 'Dup', 'username': uname, 'email': 'other@example.test'}, follow_redirects=True)
    assert b'already in use' in r.data
    with app.app.app_context():
        target = app.User.query.filter_by(username=uname).one()
        tid = target.id
        assert target.must_change_password
    admin.post('/admin/users', {'action': 'deactivate', 'user_id': str(tid)})
    with app.app.app_context():
        assert app.db.session.get(app.User, tid).active is False
    admin.post('/admin/users', {'action': 'activate', 'user_id': str(tid)})
    r = admin.post('/admin/users', {'action': 'reset', 'user_id': str(tid)}, follow_redirects=True)
    assert b'Temporary password for' in r.data
    # cannot deactivate or delete yourself
    admin.post('/admin/users', {'action': 'deactivate', 'user_id': str(admin.user['id'])})
    admin.post('/admin/users', {'action': 'delete', 'user_id': str(admin.user['id'])})
    with app.app.app_context():
        assert app.db.session.get(app.User, admin.user['id']).active
    # delete an unused account, archive a used one
    admin.post('/admin/users', {'action': 'delete', 'user_id': str(tid)})
    with app.app.app_context():
        u = app.db.session.get(app.User, tid)
        assert u is None or u.active is False


def test_compliance_interop_branding_pages(login_as):
    d = login_as('director')
    for p in ('/compliance', '/interoperability', '/admin/branding', '/audit'):
        assert d.get(p).status_code == 200, p


def test_audit_chain_verifies(app, login_as):
    d = login_as('director')
    r = d.get('/audit/verify', follow_redirects=True)
    assert b'Audit hash chain verified' in r.data
    with app.app.app_context():
        ok, count, bad = app.audit_chain_status()
        assert ok and count > 10


def test_audit_chain_survives_concurrent_writes(app, master):
    """Several requests auditing at the same moment must not fork the hash chain."""
    errors = []

    def worker(n):
        try:
            with app.app.app_context():
                for i in range(15):
                    app.audit('CONCURRENCY_TEST', 'test', n, f'thread={n}; i={i}', user_id=master['id'])
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    with app.app.app_context():
        ok, count, bad = app.audit_chain_status()
        assert ok, f'audit chain broken near record {bad}'


def test_every_page_renders_for_master(app, login_as):
    """Crawl every parameterless GET route as master and make sure nothing 500s."""
    b = login_as('master')
    skip = ('/logout', '/static', '/api/', '/request/')
    for rule in app.app.url_map.iter_rules():
        if 'GET' not in rule.methods or '<' in rule.rule or rule.rule.startswith(skip):
            continue
        r = b.get(rule.rule)
        assert r.status_code < 500, (rule.rule, r.status_code)
