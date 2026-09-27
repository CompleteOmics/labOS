"""Westgard QC rules and patient-result autoverification actually fire (they were silently disabled before 12.1)."""
import json

import pytest

from conftest import ids_for, uniq


@pytest.fixture
def lab(login_as):
    return {'staff': login_as('staff'), 'director': login_as('director')}


def test_default_policies_are_seeded_and_enabled(app, master):
    with app.app.app_context():
        codes = {p.code: p for p in app.QCPolicy.query.all()}
    for code in ('WG_12S', 'WG_13S', 'WG_22S', 'WG_R4S', 'WG_41S', 'WG_10X', 'CRITICAL', 'QC_BLOCK', 'DELTA'):
        assert code in codes and codes[code].enabled, code
    assert json.loads(codes['DELTA'].config_json)['percent'] == 50


def test_westgard_rules(app, master):
    with app.app.app_context():
        wf = app.westgard_flag

        class H:  # history row stand-in
            def __init__(self, z):
                self.z_score = z
        assert wf(10.2, 10, 1)[2] == 'Accept'
        assert wf(12.5, 10, 1) == (2.5, '1_2s', 'Warning')
        assert wf(13.2, 10, 1)[2] == 'Reject' and '1_3s' in wf(13.2, 10, 1)[1]
        assert '2_2s' in wf(12.4, 10, 1, [H(2.3)])[1]
        assert 'R_4s' in wf(12.1, 10, 1, [H(-2.1)])[1]
        assert '4_1s' in wf(11.2, 10, 1, [H(1.3), H(1.5), H(1.1)])[1]
        assert '10x' in wf(10.5, 10, 1, [H(0.4)] * 9)[1]
        assert wf(10, 10, 0)[2] == 'Review'


def _order_in_testing(app, staff, code='TSH', patient=None, mrn=None):
    tid, = ids_for(app, code)
    data = {'patient_name': patient or uniq('AV Patient '), 'tests': [str(tid)]}
    if mrn:
        data['patient_mrn'] = mrn
    r = staff.post('/orders/new', data)
    oid = int(r.location.rstrip('/').split('/')[-1])
    staff.post(f'/orders/{oid}', {'action': 'receive'})
    staff.post(f'/orders/{oid}', {'action': 'testing'})
    with app.app.app_context():
        return oid, app.OrderTest.query.filter_by(order_id=oid).one().id


def _decision(app, ot_id):
    with app.app.app_context():
        ev = app.AutoVerificationEvent.query.filter_by(order_test_id=ot_id).one()
        return ev.decision, json.loads(ev.checks_json)


def test_critical_value_holds_release(app, lab):
    staff, director = lab['staff'], lab['director']
    code = uniq('CRIT')
    with app.app.app_context():
        t = app.Test(code=code, name='Critical assay', unit='mmol/L', active=True)
        app.db.session.add(t)
        app.db.session.flush()
        app.db.session.add(app.ReferenceInterval(test_id=t.id, sex='Any', lower_limit=3.5, upper_limit=5.0,
                                                 critical_low=2.5, critical_high=6.5, active=True))
        app.db.session.commit()
    oid, ot = _order_in_testing(app, staff, code)
    staff.post(f'/orders/{oid}', {'action': 'save_results', f'result_{ot}': '7.1'})
    decision, checks = _decision(app, ot)
    assert decision == 'Hold' and any(c['check'] == 'Critical value' for c in checks)
    director.post(f'/orders/{oid}', {'action': 'approve'})
    with app.app.app_context():
        assert app.db.session.get(app.Order, oid).status == 'Review'
    director.post(f'/orders/{oid}', {'action': 'approve', 'override_reason': 'Called to Dr. Test at 14:05, read back confirmed'})
    with app.app.app_context():
        assert app.db.session.get(app.Order, oid).status == 'Released'


def test_rejected_qc_blocks_patient_results(app, lab):
    staff, director = lab['staff'], lab['director']
    code = uniq('QCB')
    with app.app.app_context():
        t = app.Test(code=code, name='QC-blocked assay', active=True)
        app.db.session.add(t)
        app.db.session.commit()
        tid = t.id
    director.post('/qc', {'action': 'definition', 'name': f'{code} L1', 'test_id': str(tid), 'level': 'L1', 'target_mean': '10', 'target_sd': '1'})
    with app.app.app_context():
        qd = app.QCDefinition.query.filter_by(test_id=tid).one().id
    staff.post('/qc', {'action': 'result', 'qc_definition_id': str(qd), 'value': '14'})  # 4 SD -> reject
    oid, ot = _order_in_testing(app, staff, code)
    staff.post(f'/orders/{oid}', {'action': 'save_results', f'result_{ot}': '11'})
    decision, checks = _decision(app, ot)
    assert decision == 'Hold' and any(c['check'] == 'Latest QC' and c['status'] == 'HOLD' for c in checks)
    # an accepted QC run clears the block for the next result entry
    staff.post('/qc', {'action': 'result', 'qc_definition_id': str(qd), 'value': '10.1'})
    staff.post(f'/orders/{oid}', {'action': 'save_results', f'result_{ot}': '11'})
    assert _decision(app, ot)[0] == 'Pass'


def test_delta_check(app, lab):
    staff, director = lab['staff'], lab['director']
    mrn = uniq('MRN-DELTA-')
    oid1, ot1 = _order_in_testing(app, staff, 'TSH', mrn=mrn)
    staff.post(f'/orders/{oid1}', {'action': 'save_results', f'result_{ot1}': '2.0'})
    director.post(f'/orders/{oid1}', {'action': 'approve', 'override_reason': 'baseline'})
    oid2, ot2 = _order_in_testing(app, staff, 'TSH', mrn=mrn)
    staff.post(f'/orders/{oid2}', {'action': 'save_results', f'result_{ot2}': '5.0'})  # +150%
    decision, checks = _decision(app, ot2)
    assert decision == 'Hold' and any(c['check'] == 'Delta check' and c['status'] == 'HOLD' for c in checks)


def test_disabled_policy_does_not_fire(app, lab, login_as):
    master_b = login_as('master')
    with app.app.app_context():
        pid = app.QCPolicy.query.filter_by(code='WG_12S').one().id
    master_b.post('/quality-policies', {'policy_id': str(pid), 'severity': 'Warning'})  # unchecked = disabled
    try:
        with app.app.app_context():
            assert app.westgard_flag(12.5, 10, 1)[2] == 'Accept'
    finally:
        master_b.post('/quality-policies', {'policy_id': str(pid), 'enabled': 'on', 'severity': 'Warning'})
    with app.app.app_context():
        assert app.db.session.get(app.QCPolicy, pid).enabled
