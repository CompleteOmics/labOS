import os, tempfile
# Use an isolated database for this verification.
tmp=tempfile.mkdtemp(prefix='labos-hl7-test-')
os.environ['DATABASE_URL']='sqlite:///'+os.path.join(tmp,'test.db').replace('\\','/')
os.environ['LIS_SECRET_KEY']='test-only-secret-key-not-for-production'
import app as lab

with lab.app.app_context():
    # Find one READY LOINC and verify dual coding structure.
    t=lab.Test.query.filter(lab.Test.loinc_status=='READY', lab.Test.loinc_code.isnot(None)).first()
    assert t is not None, 'No READY LOINC-mapped test found'
    cwe=lab.hl7_test_cwe(t)
    assert '^99COI^' in cwe, cwe
    assert '^LN' in cwe, cwe
    assert t.loinc_code in cwe, cwe
    codings=lab.fhir_test_codings(t)
    assert any(c.get('system')=='http://loinc.org' and c.get('code')==t.loinc_code for c in codings), codings
    print('[OK] HL7 CWE dual coding:', cwe)
    print('[OK] FHIR LOINC coding:', [c for c in codings if c.get('system')=='http://loinc.org'][0])
print('HL7/FHIR LOINC mapping self-test passed.')
