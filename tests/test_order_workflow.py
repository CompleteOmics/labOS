"""End-to-end order lifecycle: provider order -> receive -> test -> results -> director release -> report."""
import pytest

from conftest import ids_for


@pytest.fixture
def team(login_as, make_clinic):
    clinic = make_clinic()
    return {
        'clinic': clinic,
        'doctor': login_as('customer', clinic_id=clinic),
        'staff': login_as('staff'),
        'director': login_as('director'),
    }


def place_order(b, app, codes=('TSH',), patient='Workflow Patient', **extra):
    ids = ids_for(app, *codes)
    data = {'patient_name': patient, 'patient_dob': '1975-06-15', 'patient_sex': 'Female',
            'provider_name': 'Dr. Test', 'tests': [str(i) for i in ids]}
    data.update(extra)
    r = b.post('/orders/new', data)
    assert r.status_code == 302, r.data[:500]
    return int(r.location.rstrip('/').split('/')[-1])


def order(app, oid):
    with app.app.app_context():
        o = app.db.session.get(app.Order, oid)
        app.db.session.expunge(o)
        return o


def order_tests(app, oid):
    with app.app.app_context():
        rows = app.OrderTest.query.filter_by(order_id=oid).order_by(app.OrderTest.id).all()
        for r in rows:
            app.db.session.expunge(r)
        return rows


def results_form(app, oid, values):
    return {f'result_{ot.id}': v for ot, v in zip(order_tests(app, oid), values)}


def test_full_happy_path(app, team):
    doc, staff, director = team['doctor'], team['staff'], team['director']

    oid = place_order(doc, app, codes=('TSH', 'NTPROBNP'))
    o = order(app, oid)
    assert o.status == 'Submitted' and o.clinic_id == team['clinic'] and o.confirmation_code
    assert director.get('/').status_code == 200

    staff.post(f'/orders/{oid}', {'action': 'receive'})
    o = order(app, oid)
    assert o.status == 'Received' and o.accession_no.startswith('CO-') and o.sample_received_at
    with app.app.app_context():
        sample = app.Sample.query.filter_by(order_id=oid).one()
        sample_id = sample.id
    assert staff.get(f'/samples/{sample_id}/label.pdf').data[:4] == b'%PDF'

    staff.post(f'/orders/{oid}', {'action': 'testing'})
    assert order(app, oid).status == 'Testing'

    staff.post(f'/orders/{oid}', {'action': 'save_results', **results_form(app, oid, ['2.4', '85'])})
    assert order(app, oid).status == 'Review'
    assert all(ot.result_status == 'Entered' and ot.entered_by for ot in order_tests(app, oid))

    # provider cannot download before release
    assert doc.get(f'/orders/{oid}/report.pdf').status_code == 403

    r = director.post(f'/orders/{oid}', {'action': 'approve', 'override_reason': 'test release'})
    assert r.status_code == 302
    assert order(app, oid).status == 'Released'
    assert all(ot.result_status == 'Approved' and ot.approved_at for ot in order_tests(app, oid))

    pdf = doc.get(f'/orders/{oid}/report.pdf')
    assert pdf.status_code == 200 and pdf.data[:4] == b'%PDF'

    # audit trail covers each step
    with app.app.app_context():
        actions = {a.action for a in app.Audit.query.filter_by(entity='order', entity_id=oid).all()}
    assert {'CREATE', 'RECEIVE', 'STATUS', 'RESULTS_ENTERED', 'APPROVE_RELEASE'} <= actions

    # dashboard, FHIR and HL7 render for the released order
    assert director.get('/').status_code == 200
    fhir = staff.get(f'/api/fhir/diagnostic-report/{oid}')
    assert fhir.status_code == 200 and fhir.json['status'] == 'final'
    hl7 = staff.get(f'/api/hl7/oru/{oid}')
    assert hl7.status_code == 200 and b'ORU^R01' in hl7.data


def test_cannot_release_without_results(app, team):
    oid = place_order(team['doctor'], app)
    team['director'].post(f'/orders/{oid}', {'action': 'approve', 'override_reason': 'x'})
    assert order(app, oid).status == 'Submitted'
    team['staff'].post(f'/orders/{oid}', {'action': 'receive'})
    team['staff'].post(f'/orders/{oid}', {'action': 'testing'})
    team['director'].post(f'/orders/{oid}', {'action': 'approve', 'override_reason': 'x'})
    assert order(app, oid).status == 'Testing'


def test_blank_results_do_not_advance_to_review(app, team):
    staff = team['staff']
    oid = place_order(team['doctor'], app, codes=('TSH', 'NTPROBNP'))
    staff.post(f'/orders/{oid}', {'action': 'receive'})
    staff.post(f'/orders/{oid}', {'action': 'testing'})
    staff.post(f'/orders/{oid}', {'action': 'save_results', **results_form(app, oid, ['2.0', ''])})
    assert order(app, oid).status == 'Testing'
    assert order_tests(app, oid)[0].result == '2.0'  # partial work is kept
    staff.post(f'/orders/{oid}', {'action': 'save_results', **results_form(app, oid, ['2.0', '70'])})
    assert order(app, oid).status == 'Review'


def test_stage_transitions_are_enforced(app, team):
    staff, director = team['staff'], team['director']
    oid = place_order(team['doctor'], app)
    # cannot start testing or enter results before receipt
    staff.post(f'/orders/{oid}', {'action': 'testing'})
    assert order(app, oid).status == 'Submitted'
    staff.post(f'/orders/{oid}', {'action': 'save_results', **results_form(app, oid, ['1.0'])})
    assert order(app, oid).status == 'Submitted' and not order_tests(app, oid)[0].result

    staff.post(f'/orders/{oid}', {'action': 'receive'})
    accession = order(app, oid).accession_no
    staff.post(f'/orders/{oid}', {'action': 'receive'})  # second receive is refused
    assert order(app, oid).accession_no == accession
    with app.app.app_context():
        assert app.Sample.query.filter_by(order_id=oid).count() == 1

    staff.post(f'/orders/{oid}', {'action': 'testing'})
    staff.post(f'/orders/{oid}', {'action': 'save_results', **results_form(app, oid, ['1.5'])})
    director.post(f'/orders/{oid}', {'action': 'approve', 'override_reason': 'ok'})
    assert order(app, oid).status == 'Released'

    # released results are locked
    for action in ('receive', 'testing'):
        staff.post(f'/orders/{oid}', {'action': action})
    staff.post(f'/orders/{oid}', {'action': 'save_results', **results_form(app, oid, ['99'])})
    o, ot = order(app, oid), order_tests(app, oid)[0]
    assert o.status == 'Released' and o.accession_no == accession and ot.result == '1.5' and ot.result_status == 'Approved'


def test_cancelled_order_cannot_be_processed(app, team):
    doc, staff = team['doctor'], team['staff']
    oid = place_order(doc, app)
    doc.post(f'/orders/{oid}', {'action': 'provider_cancel', 'cancel_reason': 'duplicate'})
    assert order(app, oid).status == 'Cancelled'
    staff.post(f'/orders/{oid}', {'action': 'receive'})
    assert order(app, oid).status == 'Cancelled' and not order(app, oid).accession_no


def test_quality_hold_requires_director_override(app, team):
    staff, director = team['staff'], team['director']
    oid = place_order(team['doctor'], app)
    staff.post(f'/orders/{oid}', {'action': 'receive'})
    staff.post(f'/orders/{oid}', {'action': 'testing'})
    ot = order_tests(app, oid)[0]
    with app.app.app_context():
        app.db.session.add(app.AutoVerificationEvent(order_id=oid, order_test_id=ot.id, test_id=ot.test_id, decision='Hold', checks_json='[]'))
        app.db.session.commit()
    staff.post(f'/orders/{oid}', {'action': 'save_results', f'result_{ot.id}': '3.3'})
    # save_results recomputes autoverification; force a hold again to test the release gate
    with app.app.app_context():
        app.AutoVerificationEvent.query.filter_by(order_id=oid).delete()
        app.db.session.add(app.AutoVerificationEvent(order_id=oid, order_test_id=ot.id, test_id=ot.test_id, decision='Hold', checks_json='[]'))
        app.db.session.commit()
    director.post(f'/orders/{oid}', {'action': 'approve'})
    assert order(app, oid).status == 'Review'
    director.post(f'/orders/{oid}', {'action': 'approve', 'override_reason': 'Reviewed chromatogram; acceptable'})
    assert order(app, oid).status == 'Released'


def test_out_of_range_result_is_flagged(app, team):
    staff = team['staff']
    oid = place_order(team['doctor'], app)
    ot = order_tests(app, oid)[0]
    with app.app.app_context():
        app.db.session.add(app.ReferenceInterval(test_id=ot.test_id, sex='Any', lower_limit=0.4, upper_limit=4.0, unit='uIU/mL', active=True))
        app.db.session.commit()
    staff.post(f'/orders/{oid}', {'action': 'receive'})
    staff.post(f'/orders/{oid}', {'action': 'testing'})
    staff.post(f'/orders/{oid}', {'action': 'save_results', f'result_{ot.id}': '12.5'})
    assert order_tests(app, oid)[0].result_flag in ('H', 'HIGH', 'High', 'HH', 'Critical High')


def test_provider_can_correct_and_delete_before_receipt_only(app, team):
    doc, staff = team['doctor'], team['staff']
    tsh, bnp = ids_for(app, 'TSH', 'NTPROBNP')
    oid = place_order(doc, app)
    doc.post(f'/orders/{oid}', {'action': 'provider_correct', 'patient_name': 'Corrected Name', 'tests': [str(tsh), str(bnp)]})
    o = order(app, oid)
    assert o.patient_name == 'Corrected Name' and len(order_tests(app, oid)) == 2

    staff.post(f'/orders/{oid}', {'action': 'receive'})
    doc.post(f'/orders/{oid}', {'action': 'provider_correct', 'patient_name': 'Too Late', 'tests': [str(tsh)]})
    doc.post(f'/orders/{oid}', {'action': 'delete_mistaken_order'})
    o = order(app, oid)
    assert o.patient_name == 'Corrected Name' and o.status == 'Received'

    oid2 = place_order(doc, app)
    r = doc.post(f'/orders/{oid2}', {'action': 'delete_mistaken_order'})
    assert r.status_code == 302
    with app.app.app_context():
        assert app.db.session.get(app.Order, oid2) is None


def test_new_order_validation(app, team):
    doc = team['doctor']
    tsh, = ids_for(app, 'TSH')
    with app.app.app_context():
        before = app.Order.query.count()
        inactive = app.Test(code='INACTIVE-X', name='Retired assay', active=False)
        app.db.session.add(inactive)
        app.db.session.commit()
        inactive_id = inactive.id
    cases = [
        {'patient_name': 'No Tests'},
        {'patient_name': '   ', 'tests': [str(tsh)]},
        {'patient_name': 'Bad Id', 'tests': ['abc']},
        {'patient_name': 'Missing Id', 'tests': ['999999']},
        {'patient_name': 'Inactive', 'tests': [str(inactive_id)]},
    ]
    for data in cases:
        r = doc.post('/orders/new', data)
        assert r.status_code in (200, 400), (data, r.status_code)
    with app.app.app_context():
        assert app.Order.query.count() == before


def test_orders_search_and_filter(app, team):
    doc = team['doctor']
    place_order(doc, app, patient='Zebulon Searchable')
    assert b'Zebulon Searchable' in doc.get('/orders?q=zebulon').data
    assert b'Zebulon Searchable' not in doc.get('/orders?q=zebulon&status=Released').data
    assert b'Zebulon Searchable' in doc.get('/orders?status=Submitted').data


def test_internal_lab_order_and_billing(app, team):
    staff, director = team['staff'], team['director']
    oid = place_order(staff, app, patient='Internal Order', payment_type='Self-pay')
    director.post(f'/orders/{oid}', {'action': 'billing_update', 'payment_type': 'Self-pay', 'billing_status': 'Paid',
                                     'charge_amount': '250', 'amount_collected': '250', 'direct_lab_cost': '40'})
    o = order(app, oid)
    assert o.billing_status == 'Paid' and o.charge_amount == 250
    assert director.get('/finance').status_code == 200
    assert b'Internal Order' in director.get('/finance/export.csv').data
    # malformed numbers must not crash the page
    r = director.post(f'/orders/{oid}', {'action': 'billing_update', 'performed_by_user_id': 'abc'})
    assert r.status_code in (302, 400)
