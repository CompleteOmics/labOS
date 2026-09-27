from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, Response, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime, timedelta, timezone, date
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.graphics.barcode import code128
from reportlab.lib.utils import ImageReader
import os, io, csv, secrets, math, json, ast, operator, string, re, zipfile, shutil, tempfile, hashlib
from openpyxl import load_workbook

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LABOS_VERSION = '12.0'
BRANDING_DIR = os.path.join(BASE_DIR, 'branding')
os.makedirs(BRANDING_DIR, exist_ok=True)
DEFAULT_LOGO = os.path.join(BASE_DIR, 'static', 'complete_omics_logo.png')
LETTERHEAD_DOCX = os.path.join(BASE_DIR, 'Complete_Omics_Letterhead.docx')
LOINC_MAPPING_FILE = os.path.join(BASE_DIR, 'Complete_Omics_LOINC_Mapping_v2.json')
LOINC_VERSION = '2.83'

def load_loinc_mapping():
    try:
        with open(LOINC_MAPPING_FILE,'r',encoding='utf-8') as f:
            rows=json.load(f)
        return {str(r.get('code') or '').strip(): r for r in rows if str(r.get('code') or '').strip()}
    except Exception:
        return {}

LOINC_MAPPING = load_loinc_mapping()

def loinc_exchange_code(test):
    """Return a production-safe single LOINC only for rows marked READY."""
    code=(getattr(test,'loinc_code',None) or '').strip()
    status=(getattr(test,'loinc_status',None) or '').strip().upper()
    return code if status=='READY' and re.fullmatch(r'\d+-\d',code) else None


def hl7_escape(value):
    """Escape HL7 v2 delimiter characters in free text fields."""
    if value is None:
        return ''
    value=str(value)
    return (value.replace('\\','\\E\\')
                 .replace('|','\\F\\')
                 .replace('^','\\S\\')
                 .replace('~','\\R\\')
                 .replace('&','\\T\\'))

def hl7_test_cwe(test):
    """Return a CWE/CE test identifier with Complete Omics local coding and, when approved, LOINC as alternate coding.

    Example: AU_NA^Sodium^99COI^2951-2^Sodium [Moles/volume] in Serum or Plasma^LN
    """
    local_code=hl7_escape(getattr(test,'code','') or '')
    local_name=hl7_escape(getattr(test,'name','') or '')
    loinc=loinc_exchange_code(test)
    if loinc:
        loinc_name=hl7_escape(getattr(test,'loinc_name','') or local_name)
        return f'{local_code}^{local_name}^99COI^{loinc}^{loinc_name}^LN'
    return f'{local_code}^{local_name}^99COI'

def fhir_test_codings(test):
    """FHIR Coding array preserving the local LIS code plus approved LOINC."""
    codings=[{'system':'urn:complete-omics:test-code','code':test.code,'display':test.name}]
    loinc=loinc_exchange_code(test)
    if loinc:
        codings.append({'system':'http://loinc.org','code':loinc,'display':test.loinc_name or test.name,'version':test.loinc_version or LOINC_VERSION})
    return codings

def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)

def fmt_dt(dt):
    if not dt:
        return ''
    if isinstance(dt, str):
        return dt
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

def configure_tesseract():
    """Locate Tesseract on Windows/Linux even when it is not on PATH."""
    try:
        import pytesseract
    except Exception:
        return None
    candidates=[]
    env_cmd=(os.environ.get('TESSERACT_CMD') or '').strip()
    if env_cmd:
        candidates.append(env_cmd)
    found=shutil.which('tesseract')
    if found:
        candidates.append(found)
    for base in [os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)'), os.environ.get('LOCALAPPDATA')]:
        if base:
            candidates.extend([
                os.path.join(base,'Tesseract-OCR','tesseract.exe'),
                os.path.join(base,'Programs','Tesseract-OCR','tesseract.exe'),
            ])
    # Common UB-Mannheim and Chocolatey locations.
    candidates.extend([
        r'C:\\Program Files\\Tesseract-OCR\\tesseract.exe',
        r'C:\\Program Files (x86)\\Tesseract-OCR\\tesseract.exe',
        r'C:\\tools\\tesseract\\tesseract.exe',
    ])
    for cmd in candidates:
        if cmd and os.path.isfile(cmd):
            try:
                pytesseract.pytesseract.tesseract_cmd=cmd
                return cmd
            except Exception:
                pass
    return found

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
_env_secret=os.environ.get('LIS_SECRET_KEY')
if _env_secret:
    app.secret_key=_env_secret
else:
    _secret_file=os.path.join(BASE_DIR,'.labos_secret')
    try:
        if os.path.exists(_secret_file):
            app.secret_key=open(_secret_file,'r',encoding='utf-8').read().strip()
        else:
            app.secret_key=secrets.token_urlsafe(48)
            with open(_secret_file,'w',encoding='utf-8') as _sf:_sf.write(app.secret_key)
    except Exception:
        app.secret_key=secrets.token_urlsafe(48)
raw_db = os.environ.get('DATABASE_URL')
# Use the psycopg (v3) driver that requirements.txt installs; bare postgresql:// would load psycopg2.
if raw_db and raw_db.startswith('postgres://'):
    raw_db = 'postgresql+psycopg://' + raw_db[len('postgres://'):]
elif raw_db and raw_db.startswith('postgresql://'):
    raw_db = 'postgresql+psycopg://' + raw_db[len('postgresql://'):]
app.config['SQLALCHEMY_DATABASE_URI'] = raw_db or 'sqlite:///' + os.path.join(BASE_DIR, 'lis_v7.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE', '0') == '1'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
# Optional canonical public HTTPS address, e.g. https://labos.completeomics.com
# When set, shared clinic/provider links always use this address instead of localhost.
app.config['PUBLIC_BASE_URL'] = (os.environ.get('PUBLIC_BASE_URL') or '').strip().rstrip('/')
app.config['IDLE_TIMEOUT_MINUTES'] = int(os.environ.get('IDLE_TIMEOUT_MINUTES','20'))
app.config['LOGIN_FAILURE_LIMIT'] = int(os.environ.get('LOGIN_FAILURE_LIMIT','5'))
app.config['LOGIN_LOCKOUT_MINUTES'] = int(os.environ.get('LOGIN_LOCKOUT_MINUTES','15'))
app.config['REQUIRE_PRIVILEGED_MFA'] = os.environ.get('REQUIRE_PRIVILEGED_MFA','1') == '1'
app.config['AUDIT_RETENTION_YEARS'] = int(os.environ.get('AUDIT_RETENTION_YEARS','6'))
db = SQLAlchemy(app)

class Clinic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True, index=True)
    code = db.Column(db.String(80), unique=True, index=True)
    address = db.Column(db.String(255))
    city = db.Column(db.String(120))
    state = db.Column(db.String(40))
    phone = db.Column(db.String(80))
    contact_name = db.Column(db.String(160))
    contact_email = db.Column(db.String(255))
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class StandingOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    clinic_id = db.Column(db.Integer, db.ForeignKey('clinic.id'), nullable=False, unique=True, index=True)
    hart_cadhs = db.Column(db.Boolean, default=False, nullable=False)
    hart_cve = db.Column(db.Boolean, default=False, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    notes = db.Column(db.Text)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    username = db.Column(db.String(120), unique=True, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False)
    organization = db.Column(db.String(255))
    clinic_id = db.Column(db.Integer, db.ForeignKey('clinic.id'), index=True)
    active = db.Column(db.Boolean, default=True, nullable=False)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    last_login_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    mfa_secret = db.Column(db.String(80))
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    failed_login_count = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True))

class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    specimen = db.Column(db.String(120))
    unit = db.Column(db.String(80))
    ref_low = db.Column(db.Float)
    ref_high = db.Column(db.Float)
    method = db.Column(db.String(160))
    loinc_code = db.Column(db.String(120))
    loinc_name = db.Column(db.String(500))
    loinc_version = db.Column(db.String(40))
    loinc_status = db.Column(db.String(80))
    loinc_notes = db.Column(db.Text)
    loinc_source = db.Column(db.String(500))
    active = db.Column(db.Boolean, default=True, nullable=False)

class ReferenceInterval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False, index=True)
    specimen = db.Column(db.String(120))
    method = db.Column(db.String(160))
    sex = db.Column(db.String(20), default='Any', nullable=False)
    age_min = db.Column(db.Float)
    age_max = db.Column(db.Float)
    age_unit = db.Column(db.String(20), default='Years')
    lower_limit = db.Column(db.Float)
    upper_limit = db.Column(db.Float)
    text_reference = db.Column(db.String(255))
    critical_low = db.Column(db.Float)
    critical_high = db.Column(db.Float)
    unit = db.Column(db.String(80))
    source = db.Column(db.Text)
    effective_date = db.Column(db.Date)
    version = db.Column(db.String(80))
    active = db.Column(db.Boolean, default=True, nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class BrandingSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lab_name = db.Column(db.String(255), default='Complete Omics Inc.', nullable=False)
    accreditation = db.Column(db.String(255), default='CLIA/CAP Accredited High Complexity Laboratory')
    address1 = db.Column(db.String(255), default='1448 S Rolling Rd Suite 218')
    city_state_zip = db.Column(db.String(255), default='Halethorpe, MD 21227')
    clia = db.Column(db.String(80), default='21D2304851')
    npi = db.Column(db.String(80), default='1750119814')
    website = db.Column(db.String(255), default='www.completeomics.com')
    logo_path = db.Column(db.String(500))
    source_docx = db.Column(db.String(500))
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class ShareLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(96), unique=True, nullable=False, index=True)
    label = db.Column(db.String(255), nullable=False)
    organization_hint = db.Column(db.String(255))
    clinic_id = db.Column(db.Integer, db.ForeignKey('clinic.id'), index=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True))
    active = db.Column(db.Boolean, default=True, nullable=False)
    allowed_test_ids = db.Column(db.Text)  # comma-separated IDs; blank = all active
    use_count = db.Column(db.Integer, default=0, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_no = db.Column(db.String(80), unique=True, nullable=False, index=True)
    customer_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    share_link_id = db.Column(db.Integer, db.ForeignKey('share_link.id'))
    clinic_id = db.Column(db.Integer, db.ForeignKey('clinic.id'), index=True)
    requester_name = db.Column(db.String(160))
    requester_email = db.Column(db.String(255))
    requester_phone = db.Column(db.String(80))
    requester_organization = db.Column(db.String(255))
    patient_name = db.Column(db.String(255), nullable=False)
    patient_dob = db.Column(db.String(20))
    patient_sex = db.Column(db.String(20))
    patient_mrn = db.Column(db.String(120))
    patient_phone = db.Column(db.String(80))
    patient_email = db.Column(db.String(255))
    patient_address = db.Column(db.String(255))
    patient_city = db.Column(db.String(120))
    patient_state = db.Column(db.String(40))
    patient_zip = db.Column(db.String(20))
    height_in = db.Column(db.Float)
    weight_lb = db.Column(db.Float)
    bmi = db.Column(db.Float)
    systolic_bp = db.Column(db.Integer)
    diastolic_bp = db.Column(db.Integer)
    stent_history = db.Column(db.String(20))
    stent_date = db.Column(db.String(20))
    cabg_history = db.Column(db.String(20))
    cabg_date = db.Column(db.String(20))
    intervention_notes = db.Column(db.Text)
    serum_creatinine_mg_dl = db.Column(db.Float)
    egfr_ckd_epi_2021 = db.Column(db.Float)
    provider_name = db.Column(db.String(255))
    status = db.Column(db.String(40), default='Submitted', nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    accession_no = db.Column(db.String(80))
    sample_received_at = db.Column(db.DateTime(timezone=True))
    notes = db.Column(db.Text)
    confirmation_code = db.Column(db.String(32), unique=True, nullable=False, index=True)
    # V9.6 billing / payer workflow
    payment_type = db.Column(db.String(40), default='Insurance', nullable=False, index=True)
    payer_name = db.Column(db.String(255))
    insurance_member_id = db.Column(db.String(160))
    insurance_group_no = db.Column(db.String(160))
    claim_no = db.Column(db.String(160))
    billing_status = db.Column(db.String(40), default='Not Billed', nullable=False, index=True)
    charge_amount = db.Column(db.Float, default=0.0, nullable=False)
    expected_reimbursement = db.Column(db.Float, default=0.0, nullable=False)
    amount_collected = db.Column(db.Float, default=0.0, nullable=False)
    adjustments = db.Column(db.Float, default=0.0, nullable=False)
    direct_lab_cost = db.Column(db.Float, default=0.0, nullable=False)
    other_cost = db.Column(db.Float, default=0.0, nullable=False)
    free_reason = db.Column(db.String(255))
    performed_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    director_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    charity_approved = db.Column(db.Boolean, default=False, nullable=False)

class OrderTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False, index=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    result = db.Column(db.String(255))
    result_flag = db.Column(db.String(20))
    ref_low_used = db.Column(db.Float)
    ref_high_used = db.Column(db.Float)
    ref_text_used = db.Column(db.String(255))
    ref_unit_used = db.Column(db.String(80))
    ref_version_used = db.Column(db.String(80))
    ref_source_used = db.Column(db.Text)
    result_status = db.Column(db.String(40), default='Pending')
    entered_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    entered_at = db.Column(db.DateTime(timezone=True))
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    approved_at = db.Column(db.DateTime(timezone=True))

class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(80), nullable=False)
    entity = db.Column(db.String(80), nullable=False)
    entity_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    prev_hash = db.Column(db.String(64))
    record_hash = db.Column(db.String(64), index=True)


class ComplianceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    record_type = db.Column(db.String(60), nullable=False, index=True)  # Risk, Incident, Vendor/BAA, Training, Policy, Assessment
    title = db.Column(db.String(255), nullable=False)
    owner = db.Column(db.String(160))
    status = db.Column(db.String(60), default='Open', nullable=False, index=True)
    due_date = db.Column(db.String(20))
    completed_date = db.Column(db.String(20))
    severity = db.Column(db.String(30))
    evidence_ref = db.Column(db.String(500))
    notes = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class ComplianceSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    value = db.Column(db.Text)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class ExchangeTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(160), unique=True, nullable=False, index=True)
    direction = db.Column(db.String(20), nullable=False)  # Inbound / Outbound
    framework = db.Column(db.String(80))  # DxF, QHIO, Carequality, CommonWell, eHealth Exchange, Direct
    message_type = db.Column(db.String(80))  # HL7 ORU, ADT, FHIR DiagnosticReport, Query, Delivery
    counterparty = db.Column(db.String(255))
    patient_reference = db.Column(db.String(160))  # use MRN/token, avoid names in this log
    status = db.Column(db.String(40), default='Logged', nullable=False)
    details = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False, index=True)


class Sample(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sample_no = db.Column(db.String(80), unique=True, nullable=False, index=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False, index=True)
    specimen_type = db.Column(db.String(120))
    container_type = db.Column(db.String(120))
    status = db.Column(db.String(40), default='Received', nullable=False, index=True)
    received_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    collected_at = db.Column(db.String(40))
    location = db.Column(db.String(255))
    aliquot_of_id = db.Column(db.Integer, db.ForeignKey('sample.id'))
    notes = db.Column(db.Text)

class Batch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_no = db.Column(db.String(80), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    method = db.Column(db.String(160))
    instrument = db.Column(db.String(160))
    status = db.Column(db.String(40), default='Open', nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    run_at = db.Column(db.DateTime(timezone=True))
    notes = db.Column(db.Text)

class BatchSample(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.Integer, db.ForeignKey('batch.id'), nullable=False, index=True)
    sample_id = db.Column(db.Integer, db.ForeignKey('sample.id'), nullable=False, index=True)
    position = db.Column(db.String(40))

class Worksheet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    batch_id = db.Column(db.Integer, db.ForeignKey('batch.id'), index=True)
    status = db.Column(db.String(40), default='Draft', nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    approved_at = db.Column(db.DateTime(timezone=True))
    notes = db.Column(db.Text)

class WorksheetEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    worksheet_id = db.Column(db.Integer, db.ForeignKey('worksheet.id'), nullable=False, index=True)
    row_label = db.Column(db.String(120), nullable=False)
    value = db.Column(db.String(255))
    unit = db.Column(db.String(80))
    entered_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    entered_at = db.Column(db.DateTime(timezone=True))

class PlateMap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    batch_id = db.Column(db.Integer, db.ForeignKey('batch.id'), index=True)
    plate_format = db.Column(db.Integer, default=96, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class PlateWell(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    plate_id = db.Column(db.Integer, db.ForeignKey('plate_map.id'), nullable=False, index=True)
    well = db.Column(db.String(10), nullable=False)
    well_type = db.Column(db.String(40), default='Sample')
    sample_id = db.Column(db.Integer, db.ForeignKey('sample.id'))
    label = db.Column(db.String(160))
    concentration = db.Column(db.String(80))
    UNIQUE = db.UniqueConstraint('plate_id','well',name='uq_plate_well')

class QCDefinition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False, index=True)
    level = db.Column(db.String(80), nullable=False)
    target_mean = db.Column(db.Float, nullable=False)
    target_sd = db.Column(db.Float, nullable=False)
    lot = db.Column(db.String(120))
    active = db.Column(db.Boolean, default=True, nullable=False)

class QCResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    qc_definition_id = db.Column(db.Integer, db.ForeignKey('qc_definition.id'), nullable=False, index=True)
    batch_id = db.Column(db.Integer, db.ForeignKey('batch.id'), index=True)
    value = db.Column(db.Float, nullable=False)
    z_score = db.Column(db.Float)
    rule_flag = db.Column(db.String(120))
    status = db.Column(db.String(30), default='Accept')
    entered_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    entered_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class QCReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    qc_result_id = db.Column(db.Integer, db.ForeignKey('qc_result.id'), nullable=False, index=True)
    decision = db.Column(db.String(40), nullable=False)  # Reviewed / Rejected / Corrected
    notes = db.Column(db.Text)
    corrective_action = db.Column(db.Text)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewed_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class QCPolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    severity = db.Column(db.String(30), default='Hold')
    config_json = db.Column(db.Text)
    source_note = db.Column(db.Text)

class AutoVerificationEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False, index=True)
    order_test_id = db.Column(db.Integer, db.ForeignKey('order_test.id'), nullable=False, index=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False, index=True)
    decision = db.Column(db.String(30), nullable=False)  # Pass / Hold
    checks_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class QCLotComparison(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False, index=True)
    old_lot = db.Column(db.String(120), nullable=False)
    new_lot = db.Column(db.String(120), nullable=False)
    pairs = db.Column(db.Integer, default=0)
    mean_old = db.Column(db.Float)
    mean_new = db.Column(db.Float)
    bias_percent = db.Column(db.Float)
    acceptance_limit = db.Column(db.Float)
    status = db.Column(db.String(30), default='Review')
    notes = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class ToxicologyBatchReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.Integer, db.ForeignKey('batch.id'), index=True)
    run_name = db.Column(db.String(160), nullable=False)
    calibrators_ok = db.Column(db.Boolean, default=False, nullable=False)
    qc_ok = db.Column(db.Boolean, default=False, nullable=False)
    retention_time_ok = db.Column(db.Boolean, default=False, nullable=False)
    ion_ratio_ok = db.Column(db.Boolean, default=False, nullable=False)
    carryover_ok = db.Column(db.Boolean, default=False, nullable=False)
    internal_standards_ok = db.Column(db.Boolean, default=False, nullable=False)
    specimen_validity_ok = db.Column(db.Boolean, default=False, nullable=False)
    decision = db.Column(db.String(40), default='Hold', nullable=False)
    notes = db.Column(db.Text)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewed_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class InventoryLot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(255), nullable=False, index=True)
    category = db.Column(db.String(120))
    supplier = db.Column(db.String(255))
    catalog_no = db.Column(db.String(120))
    lot_no = db.Column(db.String(120))
    quantity = db.Column(db.Float, default=0)
    unit = db.Column(db.String(80))
    received_date = db.Column(db.String(20))
    expiration_date = db.Column(db.String(20))
    storage_location = db.Column(db.String(255))
    status = db.Column(db.String(40), default='Active')

class CalculationRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    output_code = db.Column(db.String(80), nullable=False, unique=True)
    expression = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    active = db.Column(db.Boolean, default=True, nullable=False)


# Extended clinical diagnostics catalog used by the provider ordering menu.
# In this revised build the complete configured menu is visible/orderable to providers.
# The Laboratory Director can still deactivate individual assays from Diagnostics Menu.
DIAGNOSTIC_MENU = [
    # Beckman Coulter AU680: chemistry / proteins / lipids / TDM / drugs of abuse
    # General & critical care chemistry
    {'code':'AU_ALB','name':'Albumin','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'g/dL'},
    {'code':'AU_ALP','name':'Alkaline Phosphatase (ALP)','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'U/L'},
    {'code':'AU_ALT','name':'Alanine Aminotransferase (ALT)','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'U/L'},
    {'code':'AU_AMMONIA','name':'Ammonia','platform':'Beckman AU680','category':'General Chemistry','specimen':'Plasma','unit':'umol/L'},
    {'code':'AU_AMY','name':'Amylase','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma/Urine','unit':'U/L'},
    {'code':'AU_PAMY','name':'Pancreatic Amylase','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'U/L'},
    {'code':'AU_AST','name':'Aspartate Aminotransferase (AST)','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'U/L'},
    {'code':'AU_CO2','name':'Carbon Dioxide (CO2)','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'mmol/L'},
    {'code':'AU_DBIL','name':'Direct Bilirubin','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'mg/dL'},
    {'code':'AU_TBIL','name':'Total Bilirubin','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'mg/dL'},
    {'code':'AU_CA','name':'Calcium','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma/Urine','unit':'mg/dL'},
    {'code':'AU_CL','name':'Chloride','platform':'Beckman AU680','category':'Electrolytes','specimen':'Serum/Plasma/Urine','unit':'mmol/L'},
    {'code':'AU_CK','name':'Creatine Kinase (CK)','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'U/L'},
    {'code':'AU_CREAT','name':'Creatinine','platform':'Beckman AU680','category':'Renal','specimen':'Serum/Plasma/Urine','unit':'mg/dL'},
    {'code':'AU_GGT','name':'Gamma-Glutamyl Transferase (GGT)','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'U/L'},
    {'code':'AU_GLU','name':'Glucose','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma/Urine/CSF','unit':'mg/dL'},
    {'code':'AU_FE','name':'Iron','platform':'Beckman AU680','category':'Iron Studies','specimen':'Serum/Plasma','unit':'ug/dL'},
    {'code':'AU_LACT','name':'Lactate','platform':'Beckman AU680','category':'General Chemistry','specimen':'Plasma','unit':'mmol/L'},
    {'code':'AU_LDH','name':'Lactate Dehydrogenase (LDH)','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'U/L'},
    {'code':'AU_LIP','name':'Lipase','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma','unit':'U/L'},
    {'code':'AU_MG','name':'Magnesium','platform':'Beckman AU680','category':'Electrolytes','specimen':'Serum/Plasma/Urine','unit':'mg/dL'},
    {'code':'AU_K','name':'Potassium','platform':'Beckman AU680','category':'Electrolytes','specimen':'Serum/Plasma/Urine','unit':'mmol/L'},
    {'code':'AU_NA','name':'Sodium','platform':'Beckman AU680','category':'Electrolytes','specimen':'Serum/Plasma/Urine','unit':'mmol/L'},
    {'code':'AU_TP','name':'Total Protein','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma/Urine/CSF','unit':'g/dL'},
    {'code':'AU_UIBC','name':'Unsaturated Iron-Binding Capacity (UIBC)','platform':'Beckman AU680','category':'Iron Studies','specimen':'Serum/Plasma','unit':'ug/dL'},
    {'code':'AU_URIC','name':'Uric Acid','platform':'Beckman AU680','category':'Renal','specimen':'Serum/Plasma/Urine','unit':'mg/dL'},
    {'code':'AU_BUN','name':'Urea Nitrogen (BUN)','platform':'Beckman AU680','category':'Renal','specimen':'Serum/Plasma/Urine','unit':'mg/dL'},
    {'code':'AU_PHOS','name':'Phosphorus','platform':'Beckman AU680','category':'General Chemistry','specimen':'Serum/Plasma/Urine','unit':'mg/dL'},
    # Lipids / diabetes
    {'code':'AU_CHOL','name':'Total Cholesterol','platform':'Beckman AU680','category':'Lipids','specimen':'Serum/Plasma','unit':'mg/dL'},
    {'code':'AU_HDL','name':'HDL Cholesterol','platform':'Beckman AU680','category':'Lipids','specimen':'Serum/Plasma','unit':'mg/dL'},
    {'code':'AU_LDL','name':'LDL Cholesterol','platform':'Beckman AU680','category':'Lipids','specimen':'Serum/Plasma','unit':'mg/dL'},
    {'code':'AU_TRIG','name':'Triglycerides','platform':'Beckman AU680','category':'Lipids','specimen':'Serum/Plasma','unit':'mg/dL'},
    {'code':'AU_APOA1','name':'Apolipoprotein A1','platform':'Beckman AU680','category':'Lipids','specimen':'Serum/Plasma','unit':'mg/dL'},
    {'code':'AU_APOB','name':'Apolipoprotein B','platform':'Beckman AU680','category':'Lipids','specimen':'Serum/Plasma','unit':'mg/dL'},
    {'code':'AU_HBA1C','name':'Hemoglobin A1c','platform':'Beckman AU680','category':'Diabetes','specimen':'Whole Blood','unit':'%'},
    # Protein chemistry / inflammation
    {'code':'AU_ASO','name':'Anti-Streptolysin O (ASO)','platform':'Beckman AU680','category':'Protein Chemistry','specimen':'Serum','unit':'IU/mL'},
    {'code':'AU_C3','name':'Complement C3','platform':'Beckman AU680','category':'Protein Chemistry','specimen':'Serum','unit':'mg/dL'},
    {'code':'AU_C4','name':'Complement C4','platform':'Beckman AU680','category':'Protein Chemistry','specimen':'Serum','unit':'mg/dL'},
    {'code':'AU_CHOLIN','name':'Cholinesterase','platform':'Beckman AU680','category':'Protein Chemistry','specimen':'Serum/Plasma','unit':'U/L'},
    {'code':'AU_CKMB','name':'CK-MB','platform':'Beckman AU680','category':'Cardiac','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'AU_CRP','name':'C-Reactive Protein (CRP)','platform':'Beckman AU680','category':'Inflammation','specimen':'Serum/Plasma','unit':'mg/L'},
    {'code':'AU_HSCRP','name':'High-Sensitivity CRP','platform':'Beckman AU680','category':'Inflammation','specimen':'Serum/Plasma','unit':'mg/L'},
    {'code':'AU_HAPTO','name':'Haptoglobin','platform':'Beckman AU680','category':'Protein Chemistry','specimen':'Serum','unit':'mg/dL'},
    {'code':'AU_HCY','name':'Homocysteine','platform':'Beckman AU680','category':'Cardiac','specimen':'Plasma','unit':'umol/L'},
    {'code':'AU_IGA','name':'Immunoglobulin A (IgA)','platform':'Beckman AU680','category':'Immunoglobulins','specimen':'Serum','unit':'mg/dL'},
    {'code':'AU_IGG','name':'Immunoglobulin G (IgG)','platform':'Beckman AU680','category':'Immunoglobulins','specimen':'Serum/CSF','unit':'mg/dL'},
    {'code':'AU_IGM','name':'Immunoglobulin M (IgM)','platform':'Beckman AU680','category':'Immunoglobulins','specimen':'Serum','unit':'mg/dL'},
    {'code':'AU_RF','name':'Rheumatoid Factor','platform':'Beckman AU680','category':'Protein Chemistry','specimen':'Serum','unit':'IU/mL'},
    {'code':'AU_UALB','name':'Urine Microalbumin','platform':'Beckman AU680','category':'Urine Chemistry','specimen':'Urine','unit':'mg/L'},
    {'code':'AU_PREALB','name':'Prealbumin','platform':'Beckman AU680','category':'Protein Chemistry','specimen':'Serum','unit':'mg/dL'},
    {'code':'AU_TRANSF','name':'Transferrin','platform':'Beckman AU680','category':'Iron Studies','specimen':'Serum','unit':'mg/dL'},
    {'code':'AU_AAG','name':'Alpha-1-Acid Glycoprotein','platform':'Beckman AU680','category':'Protein Chemistry','specimen':'Serum','unit':'mg/dL'},
    {'code':'AU_A1AT','name':'Alpha-1-Antitrypsin','platform':'Beckman AU680','category':'Protein Chemistry','specimen':'Serum','unit':'mg/dL'},
    {'code':'AU_B2M','name':'Beta-2 Microglobulin','platform':'Beckman AU680','category':'Protein Chemistry','specimen':'Serum/Urine','unit':'mg/L'},
    {'code':'AU_CERULO','name':'Ceruloplasmin','platform':'Beckman AU680','category':'Protein Chemistry','specimen':'Serum','unit':'mg/dL'},
    {'code':'AU_DDIMER','name':'D-Dimer','platform':'Beckman AU680','category':'Coagulation Adjunct','specimen':'Plasma','unit':'ug/mL FEU'},
    {'code':'AU_FERR','name':'Ferritin','platform':'Beckman AU680','category':'Iron Studies','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'AU_MYO','name':'Myoglobin','platform':'Beckman AU680','category':'Cardiac','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'AU_CYSC','name':'Cystatin C','platform':'Beckman AU680','category':'Renal','specimen':'Serum/Plasma','unit':'mg/L'},
    # Therapeutic drug monitoring / toxicology capabilities on AU family
    {'code':'AU_ACET','name':'Acetaminophen','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ug/mL'},
    {'code':'AU_AMIK','name':'Amikacin','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ug/mL'},
    {'code':'AU_CAFF','name':'Caffeine','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ug/mL'},
    {'code':'AU_CARB','name':'Carbamazepine','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ug/mL'},
    {'code':'AU_DIG','name':'Digoxin','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'AU_GENT','name':'Gentamicin','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ug/mL'},
    {'code':'AU_LITH','name':'Lithium','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'mmol/L'},
    {'code':'AU_PHENO','name':'Phenobarbital','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ug/mL'},
    {'code':'AU_PHENY','name':'Phenytoin','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ug/mL'},
    {'code':'AU_SAL','name':'Salicylate','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'mg/dL'},
    {'code':'AU_THEO','name':'Theophylline','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ug/mL'},
    {'code':'AU_TOBRA','name':'Tobramycin','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ug/mL'},
    {'code':'AU_VALP','name':'Valproic Acid','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ug/mL'},
    {'code':'AU_VANC','name':'Vancomycin','platform':'Beckman AU680','category':'Therapeutic Drug Monitoring','specimen':'Serum/Plasma','unit':'ug/mL'},
    {'code':'AU_TACRO','name':'Tacrolimus','platform':'Beckman AU680','category':'Immunosuppressants','specimen':'Whole Blood','unit':'ng/mL'},
    {'code':'AU_EVERO','name':'Everolimus','platform':'Beckman AU680','category':'Immunosuppressants','specimen':'Whole Blood','unit':'ng/mL'},
    {'code':'AU_CYCLO','name':'Cyclosporine','platform':'Beckman AU680','category':'Immunosuppressants','specimen':'Whole Blood','unit':'ng/mL'},
    {'code':'AU_MPA','name':'Mycophenolic Acid','platform':'Beckman AU680','category':'Immunosuppressants','specimen':'Plasma','unit':'ug/mL'},
    # Access 2 immunoassay menu
    {'code':'ACC_CORT','name':'Cortisol','platform':'Beckman Access 2','category':'Adrenal/Pituitary','specimen':'Serum/Plasma/Urine','unit':'ug/dL'},
    {'code':'ACC_EPO','name':'Erythropoietin (EPO)','platform':'Beckman Access 2','category':'Anemia','specimen':'Serum/Plasma','unit':'mIU/mL'},
    {'code':'ACC_FERR','name':'Ferritin','platform':'Beckman Access 2','category':'Anemia','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'ACC_FOL','name':'Folate','platform':'Beckman Access 2','category':'Anemia','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'ACC_B12','name':'Vitamin B12','platform':'Beckman Access 2','category':'Anemia','specimen':'Serum/Plasma','unit':'pg/mL'},
    {'code':'ACC_PTH','name':'Intact PTH','platform':'Beckman Access 2','category':'Bone Metabolism','specimen':'Serum/Plasma','unit':'pg/mL'},
    {'code':'ACC_OSTASE','name':'Bone-Specific Alkaline Phosphatase (Ostase)','platform':'Beckman Access 2','category':'Bone Metabolism','specimen':'Serum','unit':'ug/L'},
    {'code':'ACC_HGH','name':'Ultrasensitive Growth Hormone','platform':'Beckman Access 2','category':'Bone Metabolism','specimen':'Serum','unit':'ng/mL'},
    {'code':'ACC_VITD','name':'25-OH Vitamin D Total','platform':'Beckman Access 2','category':'Bone Metabolism','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'ACC_TNI','name':'Troponin I','platform':'Beckman Access 2','category':'Cardiac','specimen':'Serum/Plasma','unit':'ng/L'},
    {'code':'ACC_CKMB','name':'CK-MB','platform':'Beckman Access 2','category':'Cardiac','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'ACC_DIG','name':'Digoxin','platform':'Beckman Access 2','category':'Cardiac','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'ACC_MYO','name':'Myoglobin','platform':'Beckman Access 2','category':'Cardiac','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'ACC_BNP','name':'BNP','platform':'Beckman Access 2','category':'Cardiac','specimen':'Whole Blood/Plasma','unit':'pg/mL'},
    {'code':'ACC_INS','name':'Ultrasensitive Insulin','platform':'Beckman Access 2','category':'Diabetes','specimen':'Serum/Plasma','unit':'uIU/mL'},
    {'code':'ACC_RUBIGG','name':'Rubella IgG','platform':'Beckman Access 2','category':'Infectious Disease','specimen':'Serum','unit':'IU/mL'},
    {'code':'ACC_TOXIGG','name':'Toxoplasma IgG','platform':'Beckman Access 2','category':'Infectious Disease','specimen':'Serum','unit':'IU/mL'},
    {'code':'ACC_TOXIGM','name':'Toxoplasma IgM','platform':'Beckman Access 2','category':'Infectious Disease','specimen':'Serum','unit':'Index'},
    {'code':'ACC_AFPONTD','name':'AFP, Open Neural Tube Defect','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum/Amniotic Fluid','unit':'ng/mL'},
    {'code':'ACC_AMH','name':'Anti-Mullerian Hormone (AMH)','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'ACC_DHEAS','name':'DHEA-S','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum/Plasma','unit':'ug/dL'},
    {'code':'ACC_FSH','name':'FSH','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum/Plasma','unit':'mIU/mL'},
    {'code':'ACC_LH','name':'LH','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum/Plasma','unit':'mIU/mL'},
    {'code':'ACC_INHA','name':'Inhibin A','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum','unit':'pg/mL'},
    {'code':'ACC_PROG','name':'Progesterone','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'ACC_PRL','name':'Prolactin','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum/Plasma','unit':'ng/mL'},
    {'code':'ACC_E2','name':'Sensitive Estradiol','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum/Plasma','unit':'pg/mL'},
    {'code':'ACC_SHBG','name':'Sex Hormone-Binding Globulin (SHBG)','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum/Plasma','unit':'nmol/L'},
    {'code':'ACC_TESTO','name':'Testosterone','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum/Plasma','unit':'ng/dL'},
    {'code':'ACC_BHCG','name':'Total beta-hCG','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum/Plasma','unit':'mIU/mL'},
    {'code':'ACC_UE3','name':'Unconjugated Estriol','platform':'Beckman Access 2','category':'Reproductive','specimen':'Serum','unit':'ng/mL'},
    {'code':'ACC_FT3','name':'Free T3','platform':'Beckman Access 2','category':'Thyroid','specimen':'Serum/Plasma','unit':'pg/mL'},
    {'code':'ACC_T3','name':'Total T3','platform':'Beckman Access 2','category':'Thyroid','specimen':'Serum/Plasma','unit':'ng/dL'},
    {'code':'ACC_FT4','name':'Free T4','platform':'Beckman Access 2','category':'Thyroid','specimen':'Serum/Plasma','unit':'ng/dL'},
    {'code':'ACC_T4','name':'Total T4','platform':'Beckman Access 2','category':'Thyroid','specimen':'Serum/Plasma','unit':'ug/dL'},
    {'code':'ACC_TG','name':'Thyroglobulin','platform':'Beckman Access 2','category':'Thyroid','specimen':'Serum','unit':'ng/mL'},
    {'code':'ACC_TGAB','name':'Thyroglobulin Antibody','platform':'Beckman Access 2','category':'Thyroid','specimen':'Serum','unit':'IU/mL'},
    {'code':'ACC_TUP','name':'Thyroid Uptake','platform':'Beckman Access 2','category':'Thyroid','specimen':'Serum','unit':'%'},
    {'code':'ACC_TPO','name':'Thyroid Peroxidase Antibody','platform':'Beckman Access 2','category':'Thyroid','specimen':'Serum','unit':'IU/mL'},
    {'code':'ACC_TSH','name':'TSH (3rd IS)','platform':'Beckman Access 2','category':'Thyroid','specimen':'Serum/Plasma','unit':'uIU/mL'},
    {'code':'ACC_AFP','name':'AFP','platform':'Beckman Access 2','category':'Tumor Markers','specimen':'Serum','unit':'ng/mL'},
    {'code':'ACC_CEA','name':'CEA','platform':'Beckman Access 2','category':'Tumor Markers','specimen':'Serum','unit':'ng/mL'},
    {'code':'ACC_CA153','name':'CA 15-3','platform':'Beckman Access 2','category':'Tumor Markers','specimen':'Serum','unit':'U/mL'},
    {'code':'ACC_CA199','name':'CA 19-9','platform':'Beckman Access 2','category':'Tumor Markers','specimen':'Serum','unit':'U/mL'},
    {'code':'ACC_CA125','name':'CA 125','platform':'Beckman Access 2','category':'Tumor Markers','specimen':'Serum','unit':'U/mL'},
    {'code':'ACC_PSA','name':'Total PSA','platform':'Beckman Access 2','category':'Tumor Markers','specimen':'Serum','unit':'ng/mL'},
    {'code':'ACC_FPSA','name':'Free PSA','platform':'Beckman Access 2','category':'Tumor Markers','specimen':'Serum','unit':'ng/mL'},
    {'code':'ACC_P2PSA','name':'[-2]proPSA','platform':'Beckman Access 2','category':'Tumor Markers','specimen':'Serum','unit':'pg/mL'},
    # Sysmex XN-530 routine reportable CBC + differential parameters
    {'code':'XN_WBC','name':'White Blood Cell Count (WBC)','platform':'Sysmex XN-530','category':'CBC','specimen':'Whole Blood','unit':'10^3/uL'},
    {'code':'XN_RBC','name':'Red Blood Cell Count (RBC)','platform':'Sysmex XN-530','category':'CBC','specimen':'Whole Blood','unit':'10^6/uL'},
    {'code':'XN_HGB','name':'Hemoglobin','platform':'Sysmex XN-530','category':'CBC','specimen':'Whole Blood','unit':'g/dL'},
    {'code':'XN_HCT','name':'Hematocrit','platform':'Sysmex XN-530','category':'CBC','specimen':'Whole Blood','unit':'%'},
    {'code':'XN_MCV','name':'MCV','platform':'Sysmex XN-530','category':'RBC Indices','specimen':'Whole Blood','unit':'fL'},
    {'code':'XN_MCH','name':'MCH','platform':'Sysmex XN-530','category':'RBC Indices','specimen':'Whole Blood','unit':'pg'},
    {'code':'XN_MCHC','name':'MCHC','platform':'Sysmex XN-530','category':'RBC Indices','specimen':'Whole Blood','unit':'g/dL'},
    {'code':'XN_PLT','name':'Platelet Count','platform':'Sysmex XN-530','category':'Platelets','specimen':'Whole Blood','unit':'10^3/uL'},
    {'code':'XN_RDWSD','name':'RDW-SD','platform':'Sysmex XN-530','category':'RBC Indices','specimen':'Whole Blood','unit':'fL'},
    {'code':'XN_RDWCV','name':'RDW-CV','platform':'Sysmex XN-530','category':'RBC Indices','specimen':'Whole Blood','unit':'%'},
    {'code':'XN_MPV','name':'MPV','platform':'Sysmex XN-530','category':'Platelets','specimen':'Whole Blood','unit':'fL'},
    {'code':'XN_NEUTABS','name':'Neutrophils, Absolute','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'10^3/uL'},
    {'code':'XN_NEUTP','name':'Neutrophils, %','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'%'},
    {'code':'XN_IGABS','name':'Immature Granulocytes, Absolute','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'10^3/uL'},
    {'code':'XN_IGP','name':'Immature Granulocytes, %','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'%'},
    {'code':'XN_LYMPHABS','name':'Lymphocytes, Absolute','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'10^3/uL'},
    {'code':'XN_LYMPHP','name':'Lymphocytes, %','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'%'},
    {'code':'XN_MONOABS','name':'Monocytes, Absolute','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'10^3/uL'},
    {'code':'XN_MONOP','name':'Monocytes, %','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'%'},
    {'code':'XN_EOABS','name':'Eosinophils, Absolute','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'10^3/uL'},
    {'code':'XN_EOP','name':'Eosinophils, %','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'%'},
    {'code':'XN_BASOABS','name':'Basophils, Absolute','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'10^3/uL'},
    {'code':'XN_BASOP','name':'Basophils, %','platform':'Sysmex XN-530','category':'Differential','specimen':'Whole Blood','unit':'%'},
    # Optional/configuration-dependent XN-L parameters
    {'code':'XN_NRBCABS','name':'NRBC, Absolute','platform':'Sysmex XN-530','category':'Advanced Hematology','specimen':'Whole Blood','unit':'10^3/uL'},
    {'code':'XN_NRBCL','name':'NRBC / 100 WBC','platform':'Sysmex XN-530','category':'Advanced Hematology','specimen':'Whole Blood','unit':'/100 WBC'},
    {'code':'XN_RETP','name':'Reticulocytes, %','platform':'Sysmex XN-530','category':'Reticulocytes (if configured)','specimen':'Whole Blood','unit':'%'},
    {'code':'XN_RETABS','name':'Reticulocytes, Absolute','platform':'Sysmex XN-530','category':'Reticulocytes (if configured)','specimen':'Whole Blood','unit':'10^6/uL'},
    {'code':'XN_IRF','name':'Immature Reticulocyte Fraction (IRF)','platform':'Sysmex XN-530','category':'Reticulocytes (if configured)','specimen':'Whole Blood','unit':'%'},
    {'code':'XN_RETHE','name':'Reticulocyte Hemoglobin Equivalent (RET-He)','platform':'Sysmex XN-530','category':'Reticulocytes (if configured)','specimen':'Whole Blood','unit':'pg'},
    # Complete Omics urine toxicology LC-MS/MS menu
    {'code':'TOX_7ACLNZ','name':'7-Aminoclonazepam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_AOHALP','name':'alpha-Hydroxyalprazolam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_AOHMID','name':'alpha-Hydroxymidazolam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_AOHTRI','name':'alpha-Hydroxytriazolam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_ALP','name':'Alprazolam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_CHLORD','name':'Chlordiazepoxide','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_CLON','name':'Clonazepam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_DIAZ','name':'Diazepam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_FLUR','name':'Flurazepam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_LORA','name':'Lorazepam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_MIDA','name':'Midazolam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_NORD','name':'Nordiazepam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_OXAZ','name':'Oxazepam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_TEMAZ','name':'Temazepam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_TRIAZ','name':'Triazolam','platform':'Complete Omics LC-MS/MS Toxicology','category':'Benzodiazepines & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_CODE','name':'Codeine','platform':'Complete Omics LC-MS/MS Toxicology','category':'Opioids & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_HYCO','name':'Hydrocodone','platform':'Complete Omics LC-MS/MS Toxicology','category':'Opioids & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_HYMO','name':'Hydromorphone','platform':'Complete Omics LC-MS/MS Toxicology','category':'Opioids & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_MORPH','name':'Morphine','platform':'Complete Omics LC-MS/MS Toxicology','category':'Opioids & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_OXYC','name':'Oxycodone','platform':'Complete Omics LC-MS/MS Toxicology','category':'Opioids & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_OXYM','name':'Oxymorphone','platform':'Complete Omics LC-MS/MS Toxicology','category':'Opioids & Metabolites','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_FENT','name':'Fentanyl','platform':'Complete Omics LC-MS/MS Toxicology','category':'Fentanyl','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_NORFENT','name':'Norfentanyl','platform':'Complete Omics LC-MS/MS Toxicology','category':'Fentanyl','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_METHAD','name':'Methadone','platform':'Complete Omics LC-MS/MS Toxicology','category':'Methadone','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_EDDP','name':'EDDP','platform':'Complete Omics LC-MS/MS Toxicology','category':'Methadone','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_BUP','name':'Buprenorphine','platform':'Complete Omics LC-MS/MS Toxicology','category':'Buprenorphine','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_NORBUP','name':'Norbuprenorphine','platform':'Complete Omics LC-MS/MS Toxicology','category':'Buprenorphine','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_TRAM','name':'Tramadol','platform':'Complete Omics LC-MS/MS Toxicology','category':'Tramadol','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_ODMT','name':'O-Desmethyltramadol','platform':'Complete Omics LC-MS/MS Toxicology','category':'Tramadol','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_AMP','name':'Amphetamine','platform':'Complete Omics LC-MS/MS Toxicology','category':'Stimulants','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_MAMP','name':'Methamphetamine','platform':'Complete Omics LC-MS/MS Toxicology','category':'Stimulants','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_BE','name':'Benzoylecgonine','platform':'Complete Omics LC-MS/MS Toxicology','category':'Cocaine Metabolite','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_PCP','name':'Phencyclidine (PCP)','platform':'Complete Omics LC-MS/MS Toxicology','category':'Other Drugs','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_MEP','name':'Meperidine','platform':'Complete Omics LC-MS/MS Toxicology','category':'Other Drugs','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_PROP','name':'Propoxyphene','platform':'Complete Omics LC-MS/MS Toxicology','category':'Other Drugs','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_M3G','name':'Morphine-3-Glucuronide','platform':'Complete Omics LC-MS/MS Toxicology','category':'Hydrolysis Performance Marker','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_OXG','name':'Oxazepam Glucuronide','platform':'Complete Omics LC-MS/MS Toxicology','category':'Hydrolysis Performance Marker','specimen':'Urine','unit':'ng/mL'},
    {'code':'TOX_UCREAT','name':'Urine Creatinine, Specimen Validity','platform':'Complete Omics LC-MS/MS Toxicology','category':'Specimen Validity','specimen':'Urine','unit':'mg/dL'},
    {'code':'TOX_SG','name':'Urine Specific Gravity','platform':'Complete Omics LC-MS/MS Toxicology','category':'Specimen Validity','specimen':'Urine','unit':''},
    {'code':'TOX_PH','name':'Urine pH','platform':'Complete Omics LC-MS/MS Toxicology','category':'Specimen Validity','specimen':'Urine','unit':''},
    {'code':'TOX_THC_SCREEN','name':'THC Screen, Presumptive','platform':'Complete Omics LC-MS/MS Toxicology','category':'Pre-Screen / Adjunct','specimen':'Urine','unit':'Qualitative'},
    {'code':'TOX_BAR_SCREEN','name':'Barbiturate Screen, Presumptive','platform':'Complete Omics LC-MS/MS Toxicology','category':'Pre-Screen / Adjunct','specimen':'Urine','unit':'Qualitative'},

]

DIAGNOSTIC_META = {x['code']: x for x in DIAGNOSTIC_MENU}

TOX_SPECS = [
    # code, internal standard, LLOQ, reporting cutoff, ULOQ
    ('TOX_7ACLNZ','Temazepam-d5',10,50,2000),
    ('TOX_AOHALP','Temazepam-d5',10,50,2000),
    ('TOX_AOHMID','Temazepam-d5',10,50,2000),
    ('TOX_AOHTRI','Temazepam-d5',10,50,2000),
    ('TOX_ALP','Temazepam-d5',10,50,2000),
    ('TOX_AMP','Amphetamine-d5',50,200,10000),
    ('TOX_BE','Benzoylecgonine-d8',20,100,4000),
    ('TOX_CHLORD','Temazepam-d5',10,50,2000),
    ('TOX_CLON','Temazepam-d5',10,50,2000),
    ('TOX_CODE','Codeine-d6',20,100,4000),
    ('TOX_DIAZ','Nordiazepam-d5',10,50,2000),
    ('TOX_EDDP','Methadone-d9',20,100,4000),
    ('TOX_FENT','Fentanyl-d5',0.4,0.5,80),
    ('TOX_FLUR','Temazepam-d5',10,50,2000),
    ('TOX_HYCO','Hydrocodone-d6',10,100,2000),
    ('TOX_HYMO','Hydromorphone-d6',10,100,2000),
    ('TOX_LORA','Temazepam-d5',10,50,2000),
    ('TOX_MEP','Benzoylecgonine-d8',10,50,2000),
    ('TOX_METHAD','Methadone-d9',20,100,4000),
    ('TOX_MAMP','Methamphetamine-d5',20,200,4000),
    ('TOX_MIDA','PCP-d5',10,50,2000),
    ('TOX_MORPH','Morphine-d6',20,100,4000),
    ('TOX_NORD','Nordiazepam-d5',10,50,2000),
    ('TOX_NORFENT','Fentanyl-d5',2,0.5,400),
    ('TOX_ODMT','Tramadol-13C,d3',20,50,4000),
    ('TOX_OXAZ','Temazepam-d5',10,50,2000),
    ('TOX_OXYC','Codeine-d6',10,50,2000),
    ('TOX_OXYM','Oxymorphone-d3',10,50,2000),
    ('TOX_PCP','PCP-d5',4,10,800),
    ('TOX_PROP','PCP-d5',10,50,2000),
    ('TOX_TEMAZ','Temazepam-d5',10,50,2000),
    ('TOX_TRAM','Tramadol-13C,d3',10,50,2000),
    ('TOX_TRIAZ','Temazepam-d5',10,50,2000),
    ('TOX_BUP','Buprenorphine-D4',2,10,400),
    ('TOX_NORBUP','Norbuprenorphine-D3',2,10,400),
]
TOX_SPEC_BY_CODE = {code:{'internal_standard':istd,'lloq':lloq,'cutoff':cutoff,'uloq':uloq} for code,istd,lloq,cutoff,uloq in TOX_SPECS}

TOX_BATCH_RULES = [
    ('Calibrators','Back-calculated calibrators within ±20% of target; LLOQ within ±25%.'),
    ('Quality controls','QC concentrations at each level within ±25% of target.'),
    ('Calibrator exclusions','No more than two calibrators excluded; LLOQ and ULOQ cannot both be excluded for one analyte.'),
    ('QC exclusions','No more than one QC excluded at each level.'),
    ('Retention time','QC/analyte retention time within ±0.05 min of calibrator mean; paired transitions within ±0.01 min.'),
    ('Ion ratio','Ion ratio within ±20% of calibrator mean.'),
    ('Carryover','Blank response after carryover challenge not greater than 30% of LLOQ response.'),
    ('Quantitation','Linear regression with 1/x² weighting; quantifier transition used for quantitation.'),
    ('Above ULOQ','Do not report a numeric concentration above ULOQ without validated dilution/reanalysis.'),
]

def toxicology_interpret(code, value):
    spec=TOX_SPEC_BY_CODE.get(code)
    if not spec:
        return None
    if value > spec['uloq']:
        return '>ULOQ'
    if value < spec['cutoff']:
        return 'NEG'
    return 'POS'

def toxicology_report_text(code, raw_value, flag):
    spec=TOX_SPEC_BY_CODE.get(code)
    if not spec:
        return None
    try:
        value=float(raw_value)
    except Exception:
        return raw_value
    if flag=='NEG':
        return 'Negative'
    if flag=='>ULOQ':
        return f'>{spec["uloq"]:g}'
    return f'{value:g}'

def toxicology_specimen_comment(order):
    values={}
    for ot in OrderTest.query.filter_by(order_id=order.id).all():
        t=db.session.get(Test,ot.test_id)
        if not t:
            continue
        try:
            values[t.code]=float(ot.result)
        except Exception:
            pass
    if values.get('TOX_SG') is not None and values.get('TOX_UCREAT') is not None:
        if values['TOX_SG'] < 1.005 and values['TOX_UCREAT'] < 25:
            return 'Specific gravity and urine creatinine low. Interpret the results with caution.'
    if values.get('TOX_PH') is not None and values['TOX_PH'] > 9.0:
        return 'Specimen validity alert: urine pH exceeds the configured acceptance threshold.'
    return None


def role_label(role):
    return {'customer':'Provider','staff':'Staff','director':'Laboratory Director','master':'Master Administrator'}.get(role, role.title())


def is_master(u=None):
    u = u or current_user()
    return bool(u and u.role == 'master')


def is_director(u=None):
    u = u or current_user()
    return bool(u and u.role in ('director','master'))


def ensure_v93_user_schema():
    """Small in-place upgrade for existing SQLite/PostgreSQL databases.

    create_all() creates new tables but does not add columns to an existing user table.
    These ALTERs let a V9.2 database move forward without deleting orders/QC history.
    """
    from sqlalchemy import inspect, text
    inspector=inspect(db.engine)
    if 'user' not in inspector.get_table_names():
        return
    cols={c['name'] for c in inspector.get_columns('user')}
    dialect=db.engine.dialect.name
    statements=[]
    if 'username' not in cols:
        statements.append('ALTER TABLE "user" ADD COLUMN username VARCHAR(120)')
    if 'must_change_password' not in cols:
        statements.append('ALTER TABLE "user" ADD COLUMN must_change_password BOOLEAN DEFAULT FALSE NOT NULL')
    if 'last_login_at' not in cols:
        statements.append('ALTER TABLE "user" ADD COLUMN last_login_at TIMESTAMP')
    if 'created_at' not in cols:
        statements.append('ALTER TABLE "user" ADD COLUMN created_at TIMESTAMP')
    with db.engine.begin() as conn:
        for stmt in statements:
            conn.execute(text(stmt))
        # Existing users receive a stable username based on the email local part.
        users=conn.execute(text('SELECT id,email,username FROM "user"')).mappings().all()
        used=set()
        for row in users:
            if row.get('username'):
                used.add(str(row['username']).lower())
        for row in users:
            if row.get('username'):
                continue
            base=(str(row['email']).split('@')[0] or f'user{row["id"]}').lower()
            base=re.sub(r'[^a-z0-9._-]+','',base) or f'user{row["id"]}'
            candidate=base; n=2
            while candidate.lower() in used:
                candidate=f'{base}{n}'; n+=1
            conn.execute(text('UPDATE "user" SET username=:u WHERE id=:i'),{'u':candidate,'i':row['id']})
            used.add(candidate.lower())
    # Best-effort unique index for username.
    try:
        with db.engine.begin() as conn:
            conn.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS ix_user_username ON "user" (username)'))
    except Exception:
        pass


def ensure_v94_multiclinic_schema():
    """Upgrade V9.3 databases for clinic-level account and order segregation."""
    from sqlalchemy import inspect, text
    inspector=inspect(db.engine)
    tables=set(inspector.get_table_names())
    statements=[]
    if 'user' in tables:
        cols={c['name'] for c in inspector.get_columns('user')}
        if 'clinic_id' not in cols: statements.append('ALTER TABLE "user" ADD COLUMN clinic_id INTEGER')
    if 'share_link' in tables:
        cols={c['name'] for c in inspector.get_columns('share_link')}
        if 'clinic_id' not in cols: statements.append('ALTER TABLE share_link ADD COLUMN clinic_id INTEGER')
    if 'order' in tables:
        cols={c['name'] for c in inspector.get_columns('order')}
        if 'clinic_id' not in cols: statements.append('ALTER TABLE "order" ADD COLUMN clinic_id INTEGER')
    with db.engine.begin() as conn:
        for stmt in statements:
            conn.execute(text(stmt))
    # Best-effort indexes.
    for stmt in [
        'CREATE INDEX IF NOT EXISTS ix_user_clinic_id ON "user" (clinic_id)',
        'CREATE INDEX IF NOT EXISTS ix_order_clinic_id ON "order" (clinic_id)',
        'CREATE INDEX IF NOT EXISTS ix_share_link_clinic_id ON share_link (clinic_id)']:
        try:
            with db.engine.begin() as conn: conn.execute(text(stmt))
        except Exception: pass
    # Map legacy organization strings into Clinic records for provider accounts.
    db.session.expire_all()
    providers=User.query.filter_by(role='customer').all()
    for u in providers:
        if u.clinic_id: continue
        org=(u.organization or '').strip()
        if not org: continue
        clinic=Clinic.query.filter(db.func.lower(Clinic.name)==org.lower()).first()
        if not clinic:
            base=re.sub(r'[^A-Za-z0-9]+','-',org).strip('-').upper()[:24] or f'CLINIC-{u.id}'
            code=base; n=2
            while Clinic.query.filter_by(code=code).first(): code=f'{base[:20]}-{n}'; n+=1
            clinic=Clinic(name=org,code=code,active=True)
            db.session.add(clinic); db.session.flush()
        u.clinic_id=clinic.id
    db.session.commit()
    # Backfill clinic ownership for orders and share links.
    for o in Order.query.filter(Order.clinic_id.is_(None)).all():
        clinic=None
        if o.customer_user_id:
            pu=db.session.get(User,o.customer_user_id)
            if pu and pu.clinic_id: clinic=db.session.get(Clinic,pu.clinic_id)
        if not clinic and (o.requester_organization or '').strip():
            clinic=Clinic.query.filter(db.func.lower(Clinic.name)==o.requester_organization.strip().lower()).first()
        if clinic: o.clinic_id=clinic.id
    for link in ShareLink.query.filter(ShareLink.clinic_id.is_(None)).all():
        hint=(link.organization_hint or '').strip()
        if hint:
            clinic=Clinic.query.filter(db.func.lower(Clinic.name)==hint.lower()).first()
            if clinic: link.clinic_id=clinic.id
    db.session.commit()


def ensure_v96_billing_schema():
    """Upgrade existing LabOS databases with payer, billing and profitability fields."""
    from sqlalchemy import inspect, text
    inspector=inspect(db.engine)
    if 'order' not in inspector.get_table_names():
        return
    cols={c['name'] for c in inspector.get_columns('order')}
    defs={
        'payment_type': "VARCHAR(40) DEFAULT 'Insurance' NOT NULL",
        'payer_name': 'VARCHAR(255)',
        'insurance_member_id': 'VARCHAR(160)',
        'insurance_group_no': 'VARCHAR(160)',
        'claim_no': 'VARCHAR(160)',
        'billing_status': "VARCHAR(40) DEFAULT 'Not Billed' NOT NULL",
        'charge_amount': 'FLOAT DEFAULT 0 NOT NULL',
        'expected_reimbursement': 'FLOAT DEFAULT 0 NOT NULL',
        'amount_collected': 'FLOAT DEFAULT 0 NOT NULL',
        'adjustments': 'FLOAT DEFAULT 0 NOT NULL',
        'direct_lab_cost': 'FLOAT DEFAULT 0 NOT NULL',
        'other_cost': 'FLOAT DEFAULT 0 NOT NULL',
        'free_reason': 'VARCHAR(255)',
        'performed_by_user_id': 'INTEGER',
        'director_user_id': 'INTEGER',
        'charity_approved': 'BOOLEAN DEFAULT FALSE NOT NULL',
    }
    with db.engine.begin() as conn:
        for col,definition in defs.items():
            if col not in cols:
                conn.execute(text(f'ALTER TABLE "order" ADD COLUMN {col} {definition}'))
        for stmt in [
            'CREATE INDEX IF NOT EXISTS ix_order_payment_type ON "order" (payment_type)',
            'CREATE INDEX IF NOT EXISTS ix_order_billing_status ON "order" (billing_status)'
        ]:
            try: conn.execute(text(stmt))
            except Exception: pass


def ensure_v100_final_schema():
    """Final upgrade: demographics, intervention history, calculations, and branding."""
    from sqlalchemy import inspect, text
    inspector=inspect(db.engine)
    if 'order' in inspector.get_table_names():
        cols={c['name'] for c in inspector.get_columns('order')}
        defs={
            'patient_phone':'VARCHAR(80)','patient_email':'VARCHAR(255)','patient_address':'VARCHAR(255)',
            'patient_city':'VARCHAR(120)','patient_state':'VARCHAR(40)','patient_zip':'VARCHAR(20)',
            'height_in':'FLOAT','weight_lb':'FLOAT','bmi':'FLOAT','systolic_bp':'INTEGER','diastolic_bp':'INTEGER',
            'stent_history':'VARCHAR(20)','stent_date':'VARCHAR(20)','cabg_history':'VARCHAR(20)','cabg_date':'VARCHAR(20)',
            'intervention_notes':'TEXT','serum_creatinine_mg_dl':'FLOAT','egfr_ckd_epi_2021':'FLOAT'
        }
        with db.engine.begin() as conn:
            for col,definition in defs.items():
                if col not in cols:
                    conn.execute(text(f'ALTER TABLE "order" ADD COLUMN {col} {definition}'))


def ensure_v114_loinc_schema():
    """Add LOINC fields non-destructively and backfill the approved v2 mapping."""
    from sqlalchemy import inspect, text
    inspector=inspect(db.engine)
    if 'test' not in inspector.get_table_names():
        return
    cols={c['name'] for c in inspector.get_columns('test')}
    defs={
        'loinc_code':'VARCHAR(120)',
        'loinc_name':'VARCHAR(500)',
        'loinc_version':'VARCHAR(40)',
        'loinc_status':'VARCHAR(80)',
        'loinc_notes':'TEXT',
        'loinc_source':'VARCHAR(500)',
    }
    with db.engine.begin() as conn:
        for col,definition in defs.items():
            if col not in cols:
                conn.execute(text(f'ALTER TABLE test ADD COLUMN {col} {definition}'))
        try: conn.execute(text('CREATE INDEX IF NOT EXISTS ix_test_loinc_code ON test (loinc_code)'))
        except Exception: pass
        try: conn.execute(text('CREATE INDEX IF NOT EXISTS ix_test_loinc_status ON test (loinc_status)'))
        except Exception: pass
    db.session.expire_all()
    # Backfill only blank fields, preserving later director edits.
    changed=False
    for t in Test.query.all():
        m=LOINC_MAPPING.get(t.code)
        if not m: continue
        if not (t.loinc_code or '').strip() and m.get('loinc_code'):
            t.loinc_code=m.get('loinc_code'); changed=True
        if not (t.loinc_name or '').strip() and m.get('loinc_name'):
            t.loinc_name=m.get('loinc_name'); changed=True
        if not (t.loinc_status or '').strip() and m.get('status'):
            t.loinc_status=m.get('status'); changed=True
        if not (t.loinc_notes or '').strip() and m.get('notes'):
            t.loinc_notes=m.get('notes'); changed=True
        if not (t.loinc_source or '').strip() and m.get('source'):
            t.loinc_source=m.get('source'); changed=True
        if not (t.loinc_version or '').strip():
            t.loinc_version=LOINC_VERSION; changed=True
    if changed: db.session.commit()


def _audit_timestamp(dt):
    if not dt: return ''
    try:
        return dt.replace(tzinfo=None).isoformat(sep=' ', timespec='seconds')
    except Exception:
        return str(dt).replace('+00:00','')


def ensure_v110_security_schema():
    """Non-destructive upgrade for LabOS 11 security/compliance fields."""
    from sqlalchemy import inspect, text
    inspector=inspect(db.engine)
    tables=set(inspector.get_table_names())
    with db.engine.begin() as conn:
        if 'user' in tables:
            cols={c['name'] for c in inspector.get_columns('user')}
            if 'failed_login_count' not in cols: conn.execute(text('ALTER TABLE "user" ADD COLUMN failed_login_count INTEGER DEFAULT 0 NOT NULL'))
            if 'locked_until' not in cols: conn.execute(text('ALTER TABLE "user" ADD COLUMN locked_until TIMESTAMP'))
        if 'audit' in tables:
            cols={c['name'] for c in inspector.get_columns('audit')}
            if 'prev_hash' not in cols: conn.execute(text('ALTER TABLE audit ADD COLUMN prev_hash VARCHAR(64)'))
            if 'record_hash' not in cols: conn.execute(text('ALTER TABLE audit ADD COLUMN record_hash VARCHAR(64)'))
            try: conn.execute(text('CREATE INDEX IF NOT EXISTS ix_audit_record_hash ON audit (record_hash)'))
            except Exception: pass
    db.session.expire_all()
    # Backfill a tamper-evident hash chain for legacy audit rows.
    prev='GENESIS'
    changed=False
    for row in Audit.query.order_by(Audit.id.asc()).all():
        payload=f'{prev}|{row.id}|{row.user_id}|{row.action}|{row.entity}|{row.entity_id}|{row.details or ""}|{_audit_timestamp(row.created_at)}'
        h=hashlib.sha256(payload.encode('utf-8')).hexdigest()
        if row.prev_hash!=prev or row.record_hash!=h:
            row.prev_hash=prev; row.record_hash=h; changed=True
        prev=h
    if changed: db.session.commit()


def compliance_setting(key, default=''):
    row=ComplianceSetting.query.filter_by(key=key).first()
    return row.value if row else default


def set_compliance_setting(key, value, user_id=None):
    row=ComplianceSetting.query.filter_by(key=key).first()
    if not row:
        row=ComplianceSetting(key=key); db.session.add(row)
    row.value=str(value or '').strip(); row.updated_by=user_id; row.updated_at=utcnow()
    db.session.commit()
    return row


def audit_chain_status():
    prev='GENESIS'; checked=0
    for row in Audit.query.order_by(Audit.id.asc()).all():
        payload=f'{prev}|{row.id}|{row.user_id}|{row.action}|{row.entity}|{row.entity_id}|{row.details or ""}|{_audit_timestamp(row.created_at)}'
        expected=hashlib.sha256(payload.encode('utf-8')).hexdigest()
        if row.prev_hash!=prev or row.record_hash!=expected:
            return False, checked, row.id
        prev=expected; checked+=1
    return True, checked, None


def age_years_from_dob(dob):
    if not dob: return None
    try:
        d=datetime.strptime(str(dob)[:10],'%Y-%m-%d').date()
        today=utcnow().date()
        return today.year-d.year-((today.month,today.day)<(d.month,d.day))
    except Exception:
        return None


def calculate_bmi(height_in, weight_lb):
    try:
        h=float(height_in); w=float(weight_lb)
        if h<=0 or w<=0: return None
        return round((w/(h*h))*703.0,1)
    except (TypeError,ValueError):
        return None


def calculate_egfr_2021(creatinine_mg_dl, age, sex):
    """2021 CKD-EPI creatinine equation; adults >=18, race-free."""
    try:
        scr=float(creatinine_mg_dl); age=float(age)
    except (TypeError,ValueError):
        return None
    sex=(sex or '').strip().lower()
    if scr<=0 or age<18 or sex not in ('male','female'):
        return None
    if sex=='female':
        k=0.7; alpha=-0.241; sex_factor=1.012
    else:
        k=0.9; alpha=-0.302; sex_factor=1.0
    value=142.0*(min(scr/k,1.0)**alpha)*(max(scr/k,1.0)**-1.200)*(0.9938**age)*sex_factor
    return round(value,1)


def update_order_calculated_demographics(o):
    o.bmi=calculate_bmi(o.height_in,o.weight_lb)
    o.egfr_ckd_epi_2021=calculate_egfr_2021(o.serum_creatinine_mg_dl,age_years_from_dob(o.patient_dob),o.patient_sex)


def get_branding():
    b=BrandingSetting.query.first()
    if not b:
        b=BrandingSetting(logo_path=DEFAULT_LOGO if os.path.exists(DEFAULT_LOGO) else None,
                          source_docx=LETTERHEAD_DOCX if os.path.exists(LETTERHEAD_DOCX) else None)
        db.session.add(b);db.session.commit()
    return b


def extract_docx_branding(docx_path):
    """Extract first embedded logo plus recognizable Complete Omics letterhead text."""
    result={}
    with zipfile.ZipFile(docx_path) as z:
        media=[n for n in z.namelist() if n.startswith('word/media/')]
        if media:
            n=media[0];ext=os.path.splitext(n)[1].lower() or '.png'
            logo=os.path.join(BRANDING_DIR,'letterhead_logo'+ext)
            with open(logo,'wb') as f:f.write(z.read(n))
            result['logo_path']=logo
    # python-docx is optional at runtime; XML fallback keeps upload useful.
    try:
        from docx import Document
        d=Document(docx_path)
        text='\n'.join(p.text.strip() for p in d.paragraphs if p.text.strip())
    except Exception:
        text=''
    if text:
        lines=[x.strip() for x in text.splitlines() if x.strip()]
        joined=' | '.join(lines)
        result['raw_text']=joined
        for line in lines:
            low=line.lower()
            if 'rolling rd' in low: result['address1']=line.rstrip(',.')
            elif re.search(r'\\bmd\\s+\\d{5}',line,re.I): result['city_state_zip']=line.rstrip(',.')
            elif low.startswith('clia:'): result['clia']=line.split(':',1)[1].strip()
            elif low.startswith('npi:'): result['npi']=line.split(':',1)[1].strip()
            elif 'completeomics.com' in low: result['website']=line.replace('https://','').replace('http://','').strip()
    return result


def draw_letterhead(c, branding, W, H):
    logo=(branding.logo_path if branding and branding.logo_path and os.path.exists(branding.logo_path) else DEFAULT_LOGO)
    if logo and os.path.exists(logo):
        try:c.drawImage(ImageReader(logo),.55*inch,H-.62*inch,width=2.55*inch,height=.425*inch,mask='auto',preserveAspectRatio=True)
        except Exception:pass
    c.setFont('Helvetica-Bold',8.5); c.drawRightString(7.95*inch,H-.38*inch,(branding.accreditation if branding else 'CLIA/CAP Accredited High Complexity Laboratory') or '')
    c.setFont('Helvetica',7.5)
    right=[(branding.address1 if branding else '1448 S Rolling Rd Suite 218'),(branding.city_state_zip if branding else 'Halethorpe, MD 21227'),
           'CLIA: '+((branding.clia if branding else '21D2304851') or ''),'NPI: '+((branding.npi if branding else '1750119814') or ''),(branding.website if branding else 'www.completeomics.com') or '']
    yy=H-.52*inch
    for line in right:
        c.drawRightString(7.95*inch,yy,line); yy-=.12*inch
    c.line(.55*inch,H-1.08*inch,7.95*inch,H-1.08*inch)
    return H-1.28*inch

def money(v):
    try: return float(v or 0)
    except (TypeError,ValueError): return 0.0

def order_financials(o):
    revenue=money(o.amount_collected)
    expected=money(o.expected_reimbursement)
    total_cost=money(o.direct_lab_cost)+money(o.other_cost)
    return {
        'revenue': revenue, 'expected': expected, 'cost': total_cost,
        'net_profit': revenue-total_cost, 'expected_profit': expected-total_cost,
        'margin_pct': ((revenue-total_cost)/revenue*100.0) if revenue else None
    }

def payment_type_from_form(default='Insurance'):
    v=(request.form.get('payment_type') or default).strip()
    allowed={'Insurance','Self-Pay','Employer/Contract','Charity/Free'}
    return v if v in allowed else default

def temporary_password(length=14):
    alphabet=string.ascii_letters+string.digits+'!@#$%'
    while True:
        pw=''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in '!@#$%' for c in pw)):
            return pw


def seed():
    # Production seed: test catalog only. No demo clinic, demo provider, demo orders, or draft reference intervals.
    tests = [
        ('KIM1','KIM-1','Serum','pg/mL',None,None,'Luminex'),
        ('ADIPO','Adiponectin','Serum','ug/mL',None,None,'Luminex'),
        ('NTPROBNP','NT-proBNP','Serum','pg/mL',None,None,'Luminex'),
        ('OPN','Osteopontin','Serum','ng/mL',None,None,'Luminex'),
        ('TIMP1','TIMP-1','Serum','ng/mL',None,None,'Luminex'),
        ('HART-CADHS','HART-CADhs','Serum','Risk Score',None,None,'Prevencio HART'),
        ('HART-CVE','HART-CVE','Serum','Risk Score',None,None,'Prevencio HART'),
        ('TSH','TSH','Serum','uIU/mL',None,None,'Beckman Access 2'),
    ]
    for code,name,specimen,unit,low,high,method in tests:
        if not Test.query.filter_by(code=code).first():
            db.session.add(Test(code=code,name=name,specimen=specimen,unit=unit,ref_low=low,ref_high=high,method=method,active=True))
    existing_menu=[Test.query.filter_by(code=item['code']).first() for item in DIAGNOSTIC_MENU]
    legacy_all_inactive=bool(existing_menu) and all((t is None or not t.active) for t in existing_menu)
    for item,t in zip(DIAGNOSTIC_MENU,existing_menu):
        if not t:
            db.session.add(Test(code=item['code'],name=item['name'],specimen=item['specimen'],unit=item['unit'],ref_low=None,ref_high=None,method=item['platform'],active=True))
        elif legacy_all_inactive:
            t.active=True
    # Older installs stored menu names with em dashes ("Neutrophils — Absolute"); normalise to "Neutrophils, Absolute".
    for t in Test.query.filter(Test.name.contains('—')).all():
        t.name=t.name.replace(' — ',', ').replace('—',', ')
    db.session.commit()
    # Apply the bundled LOINC v2 mapping to newly seeded tests while preserving later manual edits.
    for t in Test.query.all():
        m=LOINC_MAPPING.get(t.code)
        if not m: continue
        if not (t.loinc_code or '').strip(): t.loinc_code=m.get('loinc_code') or None
        if not (t.loinc_name or '').strip(): t.loinc_name=m.get('loinc_name') or None
        if not (t.loinc_status or '').strip(): t.loinc_status=m.get('status') or None
        if not (t.loinc_notes or '').strip(): t.loinc_notes=m.get('notes') or None
        if not (t.loinc_source or '').strip(): t.loinc_source=m.get('source') or None
        if not (t.loinc_version or '').strip(): t.loinc_version=LOINC_VERSION
    db.session.commit()
    get_branding()


def audit(action, entity, entity_id=None, details='', user_id=None):
    last=Audit.query.order_by(Audit.id.desc()).first()
    prev=(last.record_hash if last and last.record_hash else 'GENESIS')
    row=Audit(user_id=user_id if user_id is not None else session.get('user_id'), action=action, entity=entity, entity_id=entity_id, details=details, prev_hash=prev)
    db.session.add(row); db.session.flush()
    payload=f'{prev}|{row.id}|{row.user_id}|{row.action}|{row.entity}|{row.entity_id}|{row.details or ""}|{_audit_timestamp(row.created_at)}'
    row.record_hash=hashlib.sha256(payload.encode('utf-8')).hexdigest()
    db.session.commit()


def current_user():
    uid = session.get('user_id')
    return db.session.get(User, uid) if uid else None


def require_login():
    if not current_user():
        return redirect(url_for('login', next=request.path))


def role_required(*roles):
    u = current_user()
    if not u:
        abort(401)
    if app.config.get('REQUIRE_PRIVILEGED_MFA') and u.role in ('director','master') and not u.mfa_enabled and request.endpoint not in ('mfa_settings','logout','change_password'):
        flash('MFA enrollment is required for privileged accounts.','warning')
        abort(403)
    # Master Administrator inherits laboratory-director access without impersonating another user.
    if u.role == 'master' and ('director' in roles or 'staff' in roles or 'master' in roles):
        return u
    if u.role not in roles:
        abort(403)
    return u


def patient_age_value(order, unit='Years'):
    if not order.patient_dob:
        return None
    try:
        dob=datetime.strptime(order.patient_dob[:10], '%Y-%m-%d').date()
        days=(date.today()-dob).days
        if unit=='Days': return float(days)
        if unit=='Months': return days/30.4375
        return days/365.2425
    except Exception:
        return None


def reference_interval_for(order, test):
    candidates=ReferenceInterval.query.filter_by(test_id=test.id,active=True).all()
    matches=[]
    sex=(order.patient_sex or 'Any').strip().lower()
    for ri in candidates:
        if ri.specimen and test.specimen and ri.specimen.strip().lower()!=test.specimen.strip().lower():
            continue
        if ri.method and test.method and ri.method.strip().lower()!=test.method.strip().lower():
            continue
        rsex=(ri.sex or 'Any').strip().lower()
        if rsex not in ('any','all','') and sex and rsex!=sex:
            continue
        age=patient_age_value(order,ri.age_unit or 'Years')
        if (ri.age_min is not None or ri.age_max is not None) and age is None:
            continue
        if ri.age_min is not None and age < ri.age_min: continue
        if ri.age_max is not None and age > ri.age_max: continue
        specificity=(2 if rsex not in ('any','all','') else 0)+(1 if ri.age_min is not None or ri.age_max is not None else 0)+(1 if ri.method else 0)
        matches.append((specificity,ri.effective_date or date.min,ri.id,ri))
    if not matches:
        return None
    matches.sort(key=lambda x:(x[0],x[1],x[2]),reverse=True)
    return matches[0][3]


def apply_reference(order, test, order_test, numeric_value):
    ri=reference_interval_for(order,test)
    if ri:
        order_test.ref_low_used=ri.lower_limit
        order_test.ref_high_used=ri.upper_limit
        order_test.ref_text_used=ri.text_reference
        order_test.ref_unit_used=ri.unit or test.unit
        order_test.ref_version_used=ri.version
        order_test.ref_source_used=ri.source
        flag=''
        if ri.critical_low is not None and numeric_value < ri.critical_low: return 'CL'
        if ri.critical_high is not None and numeric_value > ri.critical_high: return 'CH'
        if ri.lower_limit is not None and numeric_value < ri.lower_limit: flag='L'
        if ri.upper_limit is not None and numeric_value > ri.upper_limit: flag='H'
        return flag
    # Legacy fallback only when no controlled interval is active.
    flag=''
    if test.ref_low is not None and numeric_value < test.ref_low: flag='L'
    if test.ref_high is not None and numeric_value > test.ref_high: flag='H'
    order_test.ref_low_used=test.ref_low
    order_test.ref_high_used=test.ref_high
    order_test.ref_unit_used=test.unit
    order_test.ref_version_used='Legacy test catalog'
    return flag

_ALLOWED_BINOPS={ast.Add:operator.add,ast.Sub:operator.sub,ast.Mult:operator.mul,ast.Div:operator.truediv,ast.Pow:operator.pow}
_ALLOWED_UNARY={ast.UAdd:operator.pos,ast.USub:operator.neg}
def safe_calc(expression, values):
    def ev(node):
        if isinstance(node,ast.Expression): return ev(node.body)
        if isinstance(node,ast.Constant) and isinstance(node.value,(int,float)): return float(node.value)
        if isinstance(node,ast.Name):
            if node.id not in values: raise ValueError(f'Missing {node.id}')
            return float(values[node.id])
        if isinstance(node,ast.BinOp) and type(node.op) in _ALLOWED_BINOPS: return _ALLOWED_BINOPS[type(node.op)](ev(node.left),ev(node.right))
        if isinstance(node,ast.UnaryOp) and type(node.op) in _ALLOWED_UNARY: return _ALLOWED_UNARY[type(node.op)](ev(node.operand))
        raise ValueError('Unsupported expression')
    return ev(ast.parse(expression,mode='eval'))


def run_calculations(order, user_id=None):
    ots=OrderTest.query.filter_by(order_id=order.id).all()
    values={}
    by_code={}
    for ot in ots:
        t=db.session.get(Test,ot.test_id)
        by_code[t.code]=ot
        try: values[t.code]=float(ot.result)
        except Exception: pass
    changed=[]
    for rule in CalculationRule.query.filter_by(active=True).all():
        out=by_code.get(rule.output_code)
        if not out: continue
        try:
            value=safe_calc(rule.expression,values)
        except Exception:
            continue
        t=db.session.get(Test,out.test_id)
        out.result=f'{value:.6g}'
        out.result_flag=apply_reference(order,t,out,float(value))
        out.result_status='Calculated'
        out.entered_by=user_id
        out.entered_at=utcnow()
        values[t.code]=value
        changed.append(t.code)
    return changed

# Provider-facing test menu. This intentionally groups tests by clinical use rather than analyzer.
# Panels are ordering conveniences only: selecting a panel checks its component tests, and the
# LIS continues to store/report each component as an individual OrderTest for traceability.
PROVIDER_PANEL_DEFINITIONS = [
    {'key':'cmp','name':'Complete Metabolic Panel (CMP)','group':'Chemistry / Metabolic',
     'codes':['AU_GLU','AU_CA','AU_NA','AU_K','AU_CO2','AU_CL','AU_BUN','AU_CREAT','AU_TP','AU_ALB','AU_TBIL','AU_ALP','AU_AST','AU_ALT']},
    {'key':'bmp','name':'Basic Metabolic Panel (BMP)','group':'Chemistry / Metabolic',
     'codes':['AU_GLU','AU_CA','AU_NA','AU_K','AU_CO2','AU_CL','AU_BUN','AU_CREAT']},
    {'key':'lft','name':'Liver Function / Hepatic Panel','group':'Liver Function',
     'codes':['AU_ALB','AU_TP','AU_ALP','AU_ALT','AU_AST','AU_TBIL','AU_DBIL','AU_GGT']},
    {'key':'lipid','name':'Lipid Panel','group':'Lipids / Cardiovascular',
     'codes':['AU_CHOL','AU_HDL','AU_LDL','AU_TRIG']},
    {'key':'iron','name':'Iron Studies','group':'Hematology / Anemia',
     'codes':['AU_FE','AU_UIBC','AU_FERR','AU_TRANSF']},
    {'key':'thyroid','name':'Thyroid Function Panel','group':'Thyroid / Endocrine',
     'codes':['ACC_TSH','ACC_FT4','ACC_FT3']},
    {'key':'tumor','name':'Oncology / Tumor Marker Panel','group':'Oncology / Cancer Markers',
     'codes':['ACC_AFP','ACC_CEA','ACC_CA153','ACC_CA199','ACC_CA125','ACC_PSA','ACC_FPSA','ACC_P2PSA']},
    {'key':'cbc','name':'CBC','group':'CBC / Hematology',
     'codes':['XN_WBC','XN_RBC','XN_HGB','XN_HCT','XN_MCV','XN_MCH','XN_MCHC','XN_PLT','XN_RDWSD','XN_RDWCV','XN_MPV']},
    {'key':'cbcdiff','name':'CBC with Differential','group':'CBC / Hematology',
     'codes':['XN_WBC','XN_RBC','XN_HGB','XN_HCT','XN_MCV','XN_MCH','XN_MCHC','XN_PLT','XN_RDWSD','XN_RDWCV','XN_MPV','XN_NEUTABS','XN_NEUTP','XN_LYMPHABS','XN_LYMPHP','XN_MONOABS','XN_MONOP','XN_EOABS','XN_EOP','XN_BASOABS','XN_BASOP','XN_IGABS','XN_IGP']},
    {'key':'tox_benzo','name':'Urine Benzodiazepines Panel','group':'Urine Drug Toxicology',
     'codes':['TOX_7ACLNZ','TOX_AOHALP','TOX_AOHMID','TOX_AOHTRI','TOX_ALP','TOX_CHLORD','TOX_CLON','TOX_DIAZ','TOX_FLUR','TOX_LORA','TOX_MIDA','TOX_NORD','TOX_OXAZ','TOX_TEMAZ','TOX_TRIAZ']},
    {'key':'tox_opioid','name':'Urine Opioids Panel','group':'Urine Drug Toxicology',
     'codes':['TOX_CODE','TOX_HYCO','TOX_HYMO','TOX_MORPH','TOX_OXYC','TOX_OXYM','TOX_FENT','TOX_NORFENT','TOX_METHAD','TOX_EDDP','TOX_BUP','TOX_NORBUP','TOX_TRAM','TOX_ODMT']},
    {'key':'tox_comprehensive','name':'Comprehensive Urine Drug Toxicology','group':'Urine Drug Toxicology',
     'codes':['TOX_7ACLNZ','TOX_AOHALP','TOX_AOHMID','TOX_AOHTRI','TOX_ALP','TOX_CHLORD','TOX_CLON','TOX_DIAZ','TOX_FLUR','TOX_LORA','TOX_MIDA','TOX_NORD','TOX_OXAZ','TOX_TEMAZ','TOX_TRIAZ','TOX_CODE','TOX_HYCO','TOX_HYMO','TOX_MORPH','TOX_OXYC','TOX_OXYM','TOX_FENT','TOX_NORFENT','TOX_METHAD','TOX_EDDP','TOX_BUP','TOX_NORBUP','TOX_TRAM','TOX_ODMT','TOX_AMP','TOX_MAMP','TOX_BE','TOX_PCP','TOX_MEP','TOX_PROP','TOX_UCREAT','TOX_SG','TOX_PH']},
]

PROVIDER_GROUP_ORDER = [
    'CBC / Hematology','Hematology / Anemia','Chemistry / Metabolic','Liver Function','Renal / Kidney',
    'Lipids / Cardiovascular','Thyroid / Endocrine','Oncology / Cancer Markers',
    'Immunology / Inflammation','Urine Testing','Urine Drug Toxicology',
    'Therapeutic Drug Monitoring','Reproductive / Hormones','Bone / Vitamins',
    'Infectious Disease','Specialty / Proteomics','Other Tests'
]

def provider_group_for_test(t):
    code=t.code or ''
    meta=DIAGNOSTIC_META.get(code,{})
    cat=(meta.get('category') or '').lower()
    platform=(meta.get('platform') or t.method or '').lower()
    name=(t.name or '').lower()
    if code.startswith('XN_'): return 'CBC / Hematology'
    if code.startswith('TOX_'): return 'Urine Drug Toxicology'
    if 'tumor marker' in cat: return 'Oncology / Cancer Markers'
    if cat in ('thyroid','adrenal/pituitary') or any(x in name for x in ('thyroid','tsh','free t3','free t4')): return 'Thyroid / Endocrine'
    if cat in ('reproductive',): return 'Reproductive / Hormones'
    if cat in ('bone metabolism',): return 'Bone / Vitamins'
    if cat in ('infectious disease',): return 'Infectious Disease'
    if cat in ('lipids','cardiac','coagulation adjunct'): return 'Lipids / Cardiovascular'
    if cat in ('renal',): return 'Renal / Kidney'
    if cat in ('urine chemistry',): return 'Urine Testing'
    if cat in ('immunoglobulins','inflammation','protein chemistry'): return 'Immunology / Inflammation'
    if cat in ('therapeutic drug monitoring','immunosuppressants'): return 'Therapeutic Drug Monitoring'
    if cat in ('anemia','iron studies'): return 'Hematology / Anemia'
    if code in {'AU_ALB','AU_ALP','AU_ALT','AU_AST','AU_DBIL','AU_TBIL','AU_GGT','AU_TP','AU_AMMONIA','AU_CHOLIN'}: return 'Liver Function'
    if 'luminex' in platform or 'prevencio' in platform or code in {'KIM1','ADIPO','NTPROBNP','OPN','TIMP1','HART-CADHS','HART-CVE'}: return 'Specialty / Proteomics'
    if cat in ('general chemistry','electrolytes','diabetes'): return 'Chemistry / Metabolic'
    return 'Other Tests'

def provider_ordering_menu(tests):
    by_code={t.code:t for t in tests}
    groups={}
    for t in tests:
        g=provider_group_for_test(t)
        groups.setdefault(g,{'tests':[],'panels':[]})['tests'].append(t)
    for g in groups.values():
        g['tests'].sort(key=lambda x:(x.name or '').lower())
    for panel in PROVIDER_PANEL_DEFINITIONS:
        members=[by_code[c] for c in panel['codes'] if c in by_code]
        # Only offer a panel when it represents a meaningful bundle in the currently allowed catalog.
        if len(members)>=2:
            p=dict(panel)
            p['test_ids']=[t.id for t in members]
            p['member_names']=[t.name for t in members]
            p['component_count']=len(members)
            groups.setdefault(panel['group'],{'tests':[],'panels':[]})['panels'].append(p)
    ordered=[]
    seen=set()
    for name in PROVIDER_GROUP_ORDER:
        if name in groups and (groups[name]['tests'] or groups[name]['panels']):
            ordered.append((name,groups[name])); seen.add(name)
    for name in sorted(groups):
        if name not in seen and (groups[name]['tests'] or groups[name]['panels']):
            ordered.append((name,groups[name]))
    return ordered

def grouped_ordering_tests(tests):
    # Retained for older templates/routes; provider_ordering_menu is preferred for ordering screens.
    grouped={}
    for t in tests:
        platform=t.method or 'Other'
        item=DIAGNOSTIC_META.get(t.code)
        category=item['category'] if item else ('Core / Specialty' if platform=='Luminex' else 'Other')
        grouped.setdefault(platform,{}).setdefault(category,[]).append(t)
    for categories in grouped.values():
        for rows in categories.values(): rows.sort(key=lambda x:(x.name or '').lower())
    return grouped


def available_tests_for_link(link):
    q = Test.query.filter_by(active=True)
    if link.allowed_test_ids:
        ids = [int(x) for x in link.allowed_test_ids.split(',') if x.strip().isdigit()]
        return q.filter(Test.id.in_(ids)).order_by(Test.name).all() if ids else []
    return q.order_by(Test.name).all()


def link_valid(link):
    if not link or not link.active:
        return False
    if link.expires_at:
        exp = link.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if utcnow() > exp:
            return False
    return True

@app.context_processor
def inject_helpers():
    if '_csrf_token' not in session:
        session['_csrf_token']=secrets.token_urlsafe(32)
    return {'fmt_dt': fmt_dt, 'csrf_token': session.get('_csrf_token'), 'labos_version': LABOS_VERSION, 'role_label': role_label}

@app.after_request
def security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options','nosniff')
    resp.headers.setdefault('X-Frame-Options','DENY')
    resp.headers.setdefault('Referrer-Policy','same-origin')
    resp.headers.setdefault('Permissions-Policy','camera=(self), microphone=(), geolocation=()')
    resp.headers.setdefault('Content-Security-Policy',"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    resp.headers.setdefault('Cache-Control','no-store, private')
    if request.is_secure:
        resp.headers.setdefault('Strict-Transport-Security','max-age=31536000; includeSubDomains')
    return resp

@app.route('/health')
def health():
    return {'status':'ok','service':'Complete Omics LabOS '+LABOS_VERSION,'public_links':'enabled'}, 200

# Routes in this set intentionally do not require an LIS account.  They are protected
# by the unguessable ShareLink token and by link active/expiration checks.
PUBLIC_ENDPOINTS = {
    'static', 'health', 'public_link_check',
    'public_request', 'public_request_success', 'public_request_edit', 'public_requisition_pdf'
}

def canonical_public_url(endpoint, **values):
    path = url_for(endpoint, **values)
    base = app.config.get('PUBLIC_BASE_URL')
    if base:
        return base + path
    return request.url_root.rstrip('/') + path

@app.route('/public-link-check')
def public_link_check():
    return {
        'status':'ok',
        'message':'This endpoint is public and does not require an LIS login.',
        'service':'Complete Omics LabOS '+LABOS_VERSION
    }, 200

@app.before_request
def require_first_run_setup():
    # Never intercept secure external request links with login/first-run setup.
    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint == 'setup':
        return None
    try:
        if User.query.count()==0:
            return redirect(url_for('setup'))
    except Exception:
        return None

@app.before_request
def security_request_controls():
    # CSRF protection for state-changing browser requests. Card-scan uses same-origin fetch and is checked by Origin/Referer.
    if request.method in ('POST','PUT','PATCH','DELETE') and request.endpoint not in ('card_scan',):
        supplied=request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
        expected=session.get('_csrf_token')
        if not expected or not supplied or not secrets.compare_digest(str(expected),str(supplied)):
            abort(400, description='Security token missing or expired. Reload the page and try again.')
    uid=session.get('user_id')
    if uid and request.endpoint not in PUBLIC_ENDPOINTS:
        now=utcnow()
        last=session.get('_last_activity')
        if last:
            try:
                last_dt=datetime.fromisoformat(last)
                if last_dt.tzinfo is None: last_dt=last_dt.replace(tzinfo=timezone.utc)
                if now-last_dt > timedelta(minutes=app.config['IDLE_TIMEOUT_MINUTES']):
                    try: audit('SESSION_TIMEOUT','user',uid,'Idle session expired',user_id=uid)
                    except Exception: pass
                    session.clear(); flash('Your session expired because of inactivity. Please sign in again.','warning')
                    return redirect(url_for('login'))
            except Exception: pass
        session['_last_activity']=now.isoformat()

@app.route('/setup',methods=['GET','POST'])
def setup():
    if User.query.count()>0:
        return redirect(url_for('login'))
    if request.method=='POST':
        name=(request.form.get('name') or '').strip()
        username=(request.form.get('username') or '').strip().lower()
        email=(request.form.get('email') or '').strip().lower()
        pw=request.form.get('password') or ''
        pw2=request.form.get('confirm_password') or ''
        if not all([name,username,email,pw]): flash('Complete all required setup fields.','danger')
        elif pw!=pw2: flash('Passwords do not match.','danger')
        elif len(pw)<12 or not any(c.isalpha() for c in pw) or not any(c.isdigit() for c in pw): flash('Use at least 12 characters with letters and numbers.','danger')
        else:
            u=User(name=name,username=username,email=email,password_hash=generate_password_hash(pw),role='master',organization='Complete Omics Inc.',active=True)
            db.session.add(u);db.session.commit();audit('FIRST_RUN_SETUP','user',u.id,'Master administrator created',user_id=u.id)
            flash('Master administrator created. Sign in to continue.','success');return redirect(url_for('login'))
    return render_template('setup.html',u=None)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        identity = request.form['identity'].strip().lower()
        u = User.query.filter(((db.func.lower(User.email)==identity) | (db.func.lower(User.username)==identity)), User.active==True).first()
        now=utcnow()
        if u and u.locked_until:
            locked=u.locked_until
            if locked.tzinfo is None: locked=locked.replace(tzinfo=timezone.utc)
            if locked > now:
                audit('LOGIN_BLOCKED','user',u.id,'Attempt while account temporarily locked',user_id=u.id)
                flash('This account is temporarily locked after repeated unsuccessful sign-in attempts. Try again later or contact an administrator.','danger')
                return render_template('login.html',u=None), 429
            u.locked_until=None; u.failed_login_count=0; db.session.commit()
        if u and check_password_hash(u.password_hash, request.form['password']):
            u.failed_login_count=0; u.locked_until=None; u.last_login_at=now; db.session.commit()
            session.clear(); session.permanent=True; session['_csrf_token']=secrets.token_urlsafe(32); session['_last_activity']=now.isoformat()
            if u.mfa_enabled and u.mfa_secret:
                session['pending_mfa_user_id']=u.id
                return redirect(url_for('mfa_verify'))
            session['user_id']=u.id; session['role']=u.role
            audit('LOGIN','user',u.id)
            if app.config['REQUIRE_PRIVILEGED_MFA'] and u.role in ('director','master'):
                flash('Multi-factor authentication is required for privileged accounts. Enroll an authenticator before continuing with routine use.','warning')
                return redirect(url_for('mfa_settings'))
            if u.must_change_password:
                return redirect(url_for('change_password'))
            return redirect(url_for('dashboard'))
        if u:
            u.failed_login_count=int(u.failed_login_count or 0)+1
            details=f'Failed login count={u.failed_login_count}'
            if u.failed_login_count >= app.config['LOGIN_FAILURE_LIMIT']:
                u.locked_until=now+timedelta(minutes=app.config['LOGIN_LOCKOUT_MINUTES']); details+='; temporary lockout applied'
            db.session.commit(); audit('LOGIN_FAILED','user',u.id,details,user_id=u.id)
        flash('Invalid username/email or password.','danger')
    return render_template('login.html', u=None)

@app.route('/mfa',methods=['GET','POST'])
def mfa_verify():
    uid=session.get('pending_mfa_user_id')
    u=db.session.get(User,uid) if uid else None
    if not u or not u.mfa_enabled or not u.mfa_secret: return redirect(url_for('login'))
    if request.method=='POST':
        import pyotp
        if pyotp.TOTP(u.mfa_secret).verify(request.form.get('code','').strip(),valid_window=1):
            session.pop('pending_mfa_user_id',None);session['user_id']=u.id;session['role']=u.role;u.last_login_at=utcnow();db.session.commit();audit('LOGIN_MFA','user',u.id);return redirect(url_for('change_password') if u.must_change_password else url_for('dashboard'))
        flash('Invalid authentication code.','danger')
    return render_template('mfa_verify.html',u=None)

@app.route('/security/mfa',methods=['GET','POST'])
def mfa_settings():
    r=require_login()
    if r:return r
    u=current_user();import pyotp
    if request.method=='POST':
        action=request.form.get('action')
        if action=='start':
            session['mfa_setup_secret']=pyotp.random_base32();return redirect(url_for('mfa_settings'))
        if action=='enable':
            secret=session.get('mfa_setup_secret');code=request.form.get('code','').strip()
            if secret and pyotp.TOTP(secret).verify(code,valid_window=1):
                u.mfa_secret=secret;u.mfa_enabled=True;db.session.commit();session.pop('mfa_setup_secret',None);audit('MFA_ENABLE','user',u.id);flash('Authenticator MFA enabled.','success')
            else: flash('The authentication code did not verify.','danger')
        if action=='disable':
            code=request.form.get('code','').strip()
            if u.mfa_secret and pyotp.TOTP(u.mfa_secret).verify(code,valid_window=1):
                u.mfa_enabled=False;u.mfa_secret=None;db.session.commit();audit('MFA_DISABLE','user',u.id);flash('MFA disabled.','warning')
            else: flash('Enter a valid current authentication code to disable MFA.','danger')
        return redirect(url_for('mfa_settings'))
    secret=session.get('mfa_setup_secret')
    uri=pyotp.totp.TOTP(secret).provisioning_uri(name=u.email,issuer_name='Complete Omics LabOS') if secret else None
    return render_template('mfa_settings.html',u=u,secret=secret,uri=uri)

@app.route('/account/change-password',methods=['GET','POST'])
def change_password():
    r=require_login()
    if r:return r
    u=current_user()
    if request.method=='POST':
        current=request.form.get('current_password','')
        new1=request.form.get('new_password','')
        new2=request.form.get('confirm_password','')
        if not check_password_hash(u.password_hash,current):
            flash('Current password is incorrect.','danger')
        elif new1!=new2:
            flash('New passwords do not match.','danger')
        elif len(new1)<10 or not any(c.isalpha() for c in new1) or not any(c.isdigit() for c in new1):
            flash('Use at least 10 characters with both letters and numbers.','danger')
        else:
            u.password_hash=generate_password_hash(new1);u.must_change_password=False;db.session.commit();audit('PASSWORD_CHANGE','user',u.id);flash('Password changed successfully.','success');return redirect(url_for('dashboard'))
    return render_template('change_password.html',u=u)


@app.route('/admin/users',methods=['GET','POST'])
def user_admin():
    u=role_required('master','director')
    # Directors can manage providers/staff; only the master can create/manage director/master accounts.
    if request.method=='POST':
        action=request.form.get('action','create')
        if action=='create':
            role=request.form.get('role','customer')
            if role not in ('customer','staff','director'):
                abort(400)
            if role=='director' and not is_master(u):
                abort(403)
            name=(request.form.get('name') or '').strip()
            username=(request.form.get('username') or '').strip().lower()
            email=(request.form.get('email') or '').strip().lower()
            clinic_id=int(request.form.get('clinic_id')) if request.form.get('clinic_id') else None
            clinic=db.session.get(Clinic,clinic_id) if clinic_id else None
            organization=(clinic.name if clinic else (request.form.get('organization') or '').strip())
            if not name or not username or not email:
                flash('Name, username and email are required.','danger')
            elif User.query.filter((db.func.lower(User.username)==username) | (db.func.lower(User.email)==email)).first():
                flash('That username or email is already in use.','danger')
            else:
                pw=(request.form.get('temporary_password') or '').strip() or temporary_password()
                nu=User(name=name,username=username,email=email,password_hash=generate_password_hash(pw),role=role,organization=organization,clinic_id=(clinic.id if (clinic and role=='customer') else None),active=True,must_change_password=True)
                db.session.add(nu);db.session.commit();audit('USER_CREATE','user',nu.id,f'role={role}; organization={organization}')
                flash(f'Account created. Temporary password (show once): {pw}','success')
        elif action in ('activate','deactivate','reset','set_password','delete'):
            target=db.session.get(User,int(request.form['user_id'])) or abort(404)
            if target.role in ('master','director') and not is_master(u):
                abort(403)
            if action=='delete':
                if target.id==u.id:
                    flash('You cannot delete the account you are currently signed in with.','danger')
                elif target.role=='master' and User.query.filter_by(role='master').count() <= 1:
                    flash('The last Master Administrator cannot be deleted. Create another Master Administrator first.','danger')
                else:
                    # A laboratory account that has already been used must remain attributable in the audit/clinical record.
                    # Permit true deletion only when no other database row references this user.
                    refs=[]
                    for table in db.metadata.tables.values():
                        if table.name=='user':
                            continue
                        for col in table.columns:
                            for fk in col.foreign_keys:
                                if fk.column.table.name=='user':
                                    try:
                                        count=db.session.query(db.func.count()).select_from(table).filter(col==target.id).scalar() or 0
                                    except Exception:
                                        count=0
                                    if count:
                                        refs.append((table.name,col.name,int(count)))
                    if refs:
                        target.active=False
                        target.failed_login_count=0
                        target.locked_until=None
                        target.mfa_enabled=False
                        target.mfa_secret=None
                        # Revoke the old password while preserving attribution to historical records.
                        target.password_hash=generate_password_hash(secrets.token_urlsafe(48))
                        db.session.commit()
                        summary=', '.join(f'{t}.{c}={n}' for t,c,n in refs[:5])
                        audit('USER_ARCHIVE','user',target.id,f'by={u.id}; linked_records={sum(n for _,_,n in refs)}; {summary}')
                        flash(f'{target.name} has historical/audit-linked records, so the account was securely archived instead of erased. Sign-in is revoked and the account is inactive.','warning')
                    else:
                        target_id=target.id
                        target_name=target.name
                        audit('USER_DELETE','user',target_id,f'by={u.id}; name={target_name}; unused_account=true')
                        db.session.delete(target)
                        db.session.commit()
                        flash(f'{target_name} was permanently deleted.','success')
            elif target.id==u.id and action=='deactivate':
                flash('You cannot deactivate your own account.','danger')
            elif action in ('reset','set_password'):
                requested=(request.form.get('new_password') or '').strip()
                if action=='set_password' and requested:
                    if len(requested) < 10 or not re.search(r'[A-Za-z]', requested) or not re.search(r'\d', requested):
                        flash('Password must be at least 10 characters and contain both letters and numbers.','danger')
                        return redirect(url_for('user_admin'))
                    pw=requested
                    generated=False
                else:
                    pw=temporary_password()
                    generated=True
                target.password_hash=generate_password_hash(pw)
                target.must_change_password=(request.form.get('force_change','1')=='1')
                target.mfa_enabled=False;target.mfa_secret=None
                db.session.commit();audit('PASSWORD_RESET','user',target.id,f'by={u.id}; generated={generated}; force_change={target.must_change_password}')
                if generated:
                    flash(f'Temporary password for {target.name} (show once): {pw}','warning')
                else:
                    flash(f'Password updated for {target.name}.','success')
            else:
                target.active=(action=='activate');db.session.commit();audit('USER_STATUS','user',target.id,f'active={target.active}')
                flash('User status updated.','success')
        return redirect(url_for('user_admin'))
    rows=User.query.order_by(User.organization,User.role,User.name).all()
    counts={
        'providers':User.query.filter_by(role='customer',active=True).count(),
        'staff':User.query.filter_by(role='staff',active=True).count(),
        'directors':User.query.filter(User.role.in_(['director','master']),User.active==True).count(),
    }
    return render_template('user_admin.html',u=u,users=rows,counts=counts,clinics=Clinic.query.filter_by(active=True).order_by(Clinic.name).all(),role_label=role_label,is_master=is_master)



@app.route('/admin/clinics',methods=['GET','POST'])
def clinic_admin():
    u=role_required('master','director')
    if request.method=='POST':
        action=request.form.get('action','create')
        if action=='create':
            name=(request.form.get('name') or '').strip()
            code=(request.form.get('code') or '').strip().upper()
            if not name:
                flash('Clinic name is required.','danger')
            elif Clinic.query.filter(db.func.lower(Clinic.name)==name.lower()).first():
                flash('A clinic with that name already exists.','danger')
            else:
                if not code:
                    code=re.sub(r'[^A-Za-z0-9]+','-',name).strip('-').upper()[:24] or f'CLINIC-{secrets.token_hex(2).upper()}'
                if Clinic.query.filter_by(code=code).first():
                    flash('Clinic code is already in use.','danger')
                else:
                    c=Clinic(name=name,code=code,address=(request.form.get('address') or '').strip(),city=(request.form.get('city') or '').strip(),state=(request.form.get('state') or '').strip(),phone=(request.form.get('phone') or '').strip(),contact_name=(request.form.get('contact_name') or '').strip(),contact_email=(request.form.get('contact_email') or '').strip().lower(),active=True)
                    db.session.add(c);db.session.commit();audit('CLINIC_CREATE','clinic',c.id,c.name);flash('Clinic created. You can now assign provider accounts to it.','success')
        elif action in ('activate','deactivate'):
            c=db.session.get(Clinic,int(request.form['clinic_id'])) or abort(404)
            c.active=(action=='activate');db.session.commit();audit('CLINIC_STATUS','clinic',c.id,f'active={c.active}');flash('Clinic status updated.','success')
        elif action=='import':
            upload=request.files.get('roster')
            if not upload or not (upload.filename or '').lower().endswith(('.csv','.xlsx')):
                flash('Select a CSV or XLSX clinic roster.','danger')
            else:
                try:
                    data=upload.read(2_000_001)
                    if len(data)>2_000_000: raise ValueError('File exceeds the 2 MB roster limit.')
                    if upload.filename.lower().endswith('.csv'):
                        try:
                            decoded=data.decode('utf-8-sig')
                        except UnicodeDecodeError:
                            # Excel's legacy "CSV (Comma delimited)" export commonly uses Windows-1252.
                            decoded=data.decode('cp1252')
                        reader=csv.reader(io.StringIO(decoded))
                        records=list(reader)
                    else:
                        wb=load_workbook(io.BytesIO(data),read_only=True,data_only=True)
                        try: records=list(wb.active.values)
                        finally: wb.close()
                    if not records: raise ValueError('The roster is empty.')
                    aliases={'clinic_id':'code','clinic_code':'code','account_id':'code','code':'code',
                             'clinic':'name','clinic_name':'name','practice_name':'name','name':'name',
                             'hart_cadhs':'hart_cadhs','hart_cad_hs':'hart_cadhs',
                             'hart_cves':'hart_cve','hart_cve':'hart_cve'}
                    headers=[aliases.get(re.sub(r'[^a-z0-9]+','_',str(h or '').strip().lower()).strip('_')) for h in records[0]]
                    if 'code' not in headers or 'name' not in headers: raise ValueError('Headers must include clinic_id and clinic_name (or code and name).')
                    def flag(value):
                        s=str(value or '').strip().lower()
                        if s in ('1','yes','y','true','x'): return True
                        if s in ('0','no','n','false',''): return False
                        raise ValueError(f'Invalid HART flag: {value}')
                    parsed=[];seen=set()
                    for line,raw in enumerate(records[1:],2):
                        if not any(v is not None and str(v).strip() for v in raw): continue
                        row=dict(zip(headers,raw))
                        code=str(row.get('code') or '').strip().upper();name=str(row.get('name') or '').strip()
                        if not code or not name or len(code)>80 or len(name)>255: raise ValueError(f'Row {line}: clinic ID and name are required and must fit their fields.')
                        if code in seen: raise ValueError(f'Row {line}: duplicate clinic ID {code}.')
                        seen.add(code)
                        cad=flag(row['hart_cadhs']) if 'hart_cadhs' in headers else None
                        cve=flag(row['hart_cve']) if 'hart_cve' in headers else None
                        parsed.append((code,name,cad,cve,line))
                    if not parsed: raise ValueError('No clinic rows found.')
                    existing_codes={c.code:c for c in Clinic.query.all() if c.code}
                    used_names={c.name.casefold():c.code for c in Clinic.query.all()}
                    named_rows=[];disambiguated=0
                    for code,name,cad,cve,line in parsed:
                        c=existing_codes.get(code)
                        suffix=f' [{code}]'
                        if c:
                            if c.name.casefold() not in (name.casefold(),(name[:255-len(suffix)]+suffix).casefold()):
                                raise ValueError(f'Row {line}: ID {code} already belongs to {c.name}.')
                            display_name=c.name
                        else:
                            display_name=name
                            if name.casefold() in used_names:
                                display_name=name[:255-len(suffix)]+suffix
                                disambiguated+=1
                            if display_name.casefold() in used_names:
                                raise ValueError(f'Row {line}: clinic name conflicts with an existing record.')
                            used_names[display_name.casefold()]=code
                        named_rows.append((code,display_name,cad,cve,line))
                    created=updated=0
                    for code,name,cad,cve,_ in named_rows:
                        c=existing_codes.get(code)
                        if not c:
                            c=Clinic(code=code,name=name,active=True);db.session.add(c);db.session.flush();created+=1
                        else: updated+=1
                        if cad is not None or cve is not None:
                            so=StandingOrder.query.filter_by(clinic_id=c.id).first()
                            if not so: so=StandingOrder(clinic_id=c.id);db.session.add(so)
                            if cad is not None: so.hart_cadhs=cad
                            if cve is not None: so.hart_cve=cve
                            so.active=True;so.updated_by=u.id;so.updated_at=utcnow()
                    db.session.commit();audit('CLINIC_ROSTER_IMPORT','clinic',None,f'created={created}; existing={updated}; name_suffixes={disambiguated}; rows={len(parsed)}')
                    flash(f'Roster imported: {created} clinics created, {updated} existing IDs matched; {disambiguated} repeated names labeled with their clinic ID.','success')
                except Exception as exc:
                    db.session.rollback();flash(f'Roster not imported: {exc}','danger')
        return redirect(url_for('clinic_admin'))
    clinics=Clinic.query.order_by(Clinic.active.desc(),Clinic.name).all()
    stats=[]
    for c in clinics:
        stats.append({'clinic':c,'providers':User.query.filter_by(clinic_id=c.id,role='customer',active=True).count(),'orders':Order.query.filter_by(clinic_id=c.id).count()})
    return render_template('clinic_admin.html',u=u,rows=stats)

@app.route('/admin/clinics/roster-template.csv')
def clinic_roster_template():
    role_required('master','director')
    return Response('clinic_id,clinic_name,hart_cadhs,hart_cve\r\nEXAMPLE-001,Example Clinic,Yes,Yes\r\n',mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=clinic_roster_template.csv'})

@app.route('/admin/users/<int:user_id>/clinic',methods=['POST'])
def assign_user_clinic(user_id):
    u=role_required('master','director')
    target=db.session.get(User,user_id) or abort(404)
    if target.role!='customer': abort(400)
    cid=int(request.form.get('clinic_id')) if request.form.get('clinic_id') else None
    clinic=db.session.get(Clinic,cid) if cid else None
    target.clinic_id=clinic.id if clinic else None
    if clinic: target.organization=clinic.name
    db.session.commit();audit('USER_CLINIC_ASSIGN','user',target.id,f'clinic_id={target.clinic_id}');flash('Provider clinic assignment updated.','success')
    return redirect(url_for('user_admin'))


@app.route('/logout')
def logout():
    u=current_user()
    if u: audit('LOGOUT','user',u.id)
    session.clear(); return redirect(url_for('login'))

def provider_order_query(u):
    if u.role!='customer':
        return Order.query
    if u.clinic_id:
        return Order.query.filter_by(clinic_id=u.clinic_id)
    return Order.query.filter_by(customer_user_id=u.id)


def clinic_for_user(u):
    return db.session.get(Clinic,u.clinic_id) if u and u.clinic_id else None


@app.route('/')
def dashboard():
    r=require_login()
    if r:return r
    u=current_user()
    statuses=['Submitted','Received','Testing','Review','Released']
    lab=u.role!='customer'
    base=Order.query if lab else provider_order_query(u)
    counts={s:base.filter(Order.status==s).count() for s in statuses}
    now=utcnow()
    def aware(d):
        return d.replace(tzinfo=timezone.utc) if d and d.tzinfo is None else d
    day0=now.replace(hour=0,minute=0,second=0,microsecond=0)
    window=base.filter(Order.created_at>=day0-timedelta(days=60)).all()
    created=[aware(o.created_at) for o in window if o.created_at]
    # 30-day daily order volume for the chart
    volume=[]
    for k in range(29,-1,-1):
        d0=day0-timedelta(days=k); d1=d0+timedelta(days=1)
        volume.append({'d':d0.strftime('%b %d'),'n':sum(1 for c in created if d0<=c<d1)})
    week=sum(1 for c in created if c>=day0-timedelta(days=6))
    prev_week=sum(1 for c in created if day0-timedelta(days=13)<=c<day0-timedelta(days=6))
    today=sum(1 for c in created if c>=day0)
    # Turnaround: order creation -> last approved result, for orders released in the last 30 days
    tat=[]
    released_30=0
    for o in window:
        if o.status!='Released' or not o.created_at: continue
        last=db.session.query(db.func.max(OrderTest.approved_at)).filter(OrderTest.order_id==o.id).scalar()
        last=aware(last)
        if last and last>=now-timedelta(days=30):
            released_30+=1
            tat.append((last-aware(o.created_at)).total_seconds()/3600)
    tat.sort()
    tat_median=(tat[len(tat)//2] if len(tat)%2 else (tat[len(tat)//2-1]+tat[len(tat)//2])/2) if tat else None
    # Worklist: open orders, oldest first
    worklist=base.filter(Order.status.in_(['Submitted','Received','Testing','Review'])).order_by(Order.created_at.asc()).limit(8).all()
    for o in worklist:
        o.age_hours=(now-aware(o.created_at)).total_seconds()/3600 if o.created_at else 0
    recent=base.order_by(Order.id.desc()).limit(8).all()
    quality={}; activity=[]
    if lab:
        recent_qc=QCResult.query.order_by(QCResult.id.desc()).limit(100).all()
        quality={
            'qc_rejects': sum(1 for x in recent_qc if x.status=='Reject'),
            'qc_warnings': sum(1 for x in recent_qc if x.status=='Warning'),
            'qc_total': len(recent_qc),
            'av_holds': AutoVerificationEvent.query.filter_by(decision='Hold').count(),
            'open_batches': Batch.query.filter_by(status='Open').count(),
            'samples_today': Sample.query.filter(Sample.received_at>=day0).count(),
        }
        quality['qc_accepts']=quality['qc_total']-quality['qc_rejects']-quality['qc_warnings']
        rows=Audit.query.order_by(Audit.id.desc()).limit(8).all()
        names={x.id:x.name for x in User.query.filter(User.id.in_({a.user_id for a in rows if a.user_id})).all()} if rows else {}
        activity=[{'who':names.get(a.user_id,'System'),'action':' '.join(w if w in ('PHI','QC','MFA','CSV','PDF','HL7','FHIR','LOINC','BAA') else w.capitalize() for w in (a.action or '').split('_')),'entity':a.entity,'entity_id':a.entity_id,'at':a.created_at} for a in rows]
    stats={'today':today,'week':week,'prev_week':prev_week,'released_30':released_30,'tat_median':tat_median,
           'in_progress':counts['Received']+counts['Testing'],'open':sum(counts[s] for s in statuses[:4])}
    return render_template('dashboard.html',u=u,counts=counts,recent=recent,quality=quality,stats=stats,volume=volume,worklist=worklist,activity=activity,now=now)



def _clean_cell(v):
    if v is None:
        return ''
    if isinstance(v, datetime):
        return v.strftime('%Y-%m-%d')
    if isinstance(v, date):
        return v.isoformat()
    return str(v).strip()


def _as_date(v):
    if not v:
        return None
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    txt=str(v).strip()
    for fmt in ('%Y-%m-%d','%m/%d/%Y','%m/%d/%y','%m-%d-%Y'):
        try:
            return datetime.strptime(txt,fmt).date()
        except Exception:
            pass
    return None


def _flag_value(v):
    if v is None or str(v).strip()=='' or str(v).strip().lower() in ('nan','none'):
        return None
    txt=str(v).strip().lower()
    if txt in ('1','1.0','yes','y','true','x','ordered'):
        return True
    if txt in ('0','0.0','no','n','false','not ordered'):
        return False
    try:
        return float(txt) != 0
    except Exception:
        return None


def _norm_header(v):
    return re.sub(r'[^a-z0-9]+',' ',str(v or '').strip().lower()).strip()


ORDER_ALIASES={
    'sample_id':['order id','sample id','sample','accession','accession no','accession number'],
    'received':['date received','received date','received'],
    'collected':['date collected','collection date','collected'],
    'account_id':['account id','account id#','account','innovati','clinic id'],
    'clinic':['account name','clinic','clinic name','organization','practice','practice name'],
    'last':['patient last name','last name','patient last'],
    'first':['patient first name','first name','patient first'],
    'dob':['patient dob','dob','date of birth','birth date'],
    'sex':['sex','gender'],
    'cadhs':['cadhs','hart cadhs','hart-cadhs'],
    'cve':['cve','cves','hart cve','hart cves','hart-cve'],
    'received_by':['received by','receiver'],
    'fedex':['fedex #','fedex','tracking','tracking number'],
    'notes':['notes','note'],
}


def _header_map(values):
    normalized={_norm_header(v):i for i,v in enumerate(values) if _norm_header(v)}
    result={}
    for key,aliases in ORDER_ALIASES.items():
        for a in aliases:
            if a in normalized:
                result[key]=normalized[a];break
    return result


def parse_clinic_order_workbook(file_storage, sheet_name=None):
    wb=load_workbook(file_storage, data_only=True, read_only=True)
    sheets=[sheet_name] if sheet_name and sheet_name in wb.sheetnames else wb.sheetnames
    parsed=[]; warnings=[]
    for sname in sheets:
        # Skip process/status tabs unless explicitly selected.
        if not sheet_name and sname.strip().lower() in ('quality assurance (qa)','lab clinical review','rejected','customers','sheet1'):
            continue
        ws=wb[sname]
        hrow=None; hmap=None
        for idx,row in enumerate(ws.iter_rows(min_row=1,max_row=min(ws.max_row,10),values_only=True),start=1):
            m=_header_map(row)
            # Some historical monthly spreadsheets leave A1 blank even though column A contains SAM/order IDs.
            if 'sample_id' not in m and 'clinic' in m and ('received' in m or 'collected' in m) and ('first' in m or 'last' in m):
                if len(row) and (row[0] is None or _norm_header(row[0]) in ('','unnamed 0')):
                    m['sample_id']=0
            if 'sample_id' in m and 'clinic' in m and ('first' in m or 'last' in m):
                hrow=idx;hmap=m;break
        if not hrow:
            warnings.append(f'{sname}: no recognizable order header found.')
            continue
        for excel_row,row in enumerate(ws.iter_rows(min_row=hrow+1,values_only=True),start=hrow+1):
            def val(key):
                i=hmap.get(key)
                return row[i] if i is not None and i < len(row) else None
            sid=_clean_cell(val('sample_id')).rstrip(',')
            clinic=_clean_cell(val('clinic'))
            first=_clean_cell(val('first')); last=_clean_cell(val('last'))
            if not sid and not clinic and not first and not last:
                continue
            parsed.append({
                'sheet':sname,'excel_row':excel_row,'sample_id':sid,
                'date_received':_as_date(val('received')),'date_collected':_as_date(val('collected')),
                'account_id':_clean_cell(val('account_id')),'clinic':clinic,
                'last':last,'first':first,'dob':_as_date(val('dob')),'dob_raw':_clean_cell(val('dob')),
                'sex':_clean_cell(val('sex')),'cadhs':_flag_value(val('cadhs')),'cve':_flag_value(val('cve')),
                'received_by':_clean_cell(val('received_by')),'fedex':_clean_cell(val('fedex')),'notes':_clean_cell(val('notes')),
            })
    return parsed,warnings


def clinic_for_import(name, account_id='', create=False):
    name=(name or '').strip()
    account=(account_id or '').strip()
    clinic=None
    if account and account.lower() not in ('nan','none'):
        clinic=Clinic.query.filter(db.func.lower(Clinic.code)==account.lower()).first()
    if not clinic and name:
        clinic=Clinic.query.filter(db.func.lower(Clinic.name)==name.lower()).first()
    if clinic or not create or not name:
        return clinic
    base=re.sub(r'[^A-Za-z0-9]+','-',account if account and account.lower()!='nan' else name).strip('-').upper()[:24] or 'CLINIC'
    code=base;n=2
    while Clinic.query.filter_by(code=code).first():
        code=f'{base[:20]}-{n}';n+=1
    clinic=Clinic(name=name,code=code,active=True)
    db.session.add(clinic);db.session.flush()
    return clinic


def selected_hart_tests_for_row(row, clinic):
    standing=StandingOrder.query.filter_by(clinic_id=clinic.id,active=True).first() if clinic else None
    cadhs=row.get('cadhs')
    cve=row.get('cve')
    if cadhs is None:
        cadhs=bool(standing and standing.hart_cadhs)
    if cve is None:
        cve=bool(standing and standing.hart_cve)
    tests=[]
    if cadhs:
        t=Test.query.filter_by(code='HART-CADHS').first()
        if t: tests.append(t)
    if cve:
        t=Test.query.filter_by(code='HART-CVE').first()
        if t: tests.append(t)
    return tests


@app.route('/standing-orders',methods=['GET','POST'])
def standing_orders():
    role_required('staff','director','master')
    u=current_user()
    if request.method=='POST':
        cid=int(request.form.get('clinic_id') or 0)
        clinic=db.session.get(Clinic,cid) or abort(404)
        so=StandingOrder.query.filter_by(clinic_id=clinic.id).first()
        if not so:
            so=StandingOrder(clinic_id=clinic.id)
            db.session.add(so)
        so.hart_cadhs=bool(request.form.get('hart_cadhs'))
        so.hart_cve=bool(request.form.get('hart_cve'))
        so.active=bool(request.form.get('active'))
        so.notes=(request.form.get('notes') or '').strip()
        so.updated_by=u.id;so.updated_at=utcnow()
        db.session.commit();audit('STANDING_ORDER_UPDATE','clinic',clinic.id,f'CADhs={so.hart_cadhs}; CVE={so.hart_cve}; active={so.active}')
        flash(f'Standing order updated for {clinic.name}.','success')
        return redirect(url_for('standing_orders'))
    clinics=Clinic.query.order_by(Clinic.name).all()
    by_clinic={x.clinic_id:x for x in StandingOrder.query.all()}
    return render_template('standing_orders.html',u=u,clinics=clinics,by_clinic=by_clinic)


@app.route('/orders/import-clinic-excel',methods=['GET','POST'])
def import_clinic_orders():
    role_required('staff','director','master')
    u=current_user(); preview=[]; summary=None; warnings=[]
    if request.method=='POST':
        f=request.files.get('workbook')
        if not f or not (f.filename or '').lower().endswith(('.xlsx','.xlsm')):
            flash('Choose an Excel .xlsx workbook.','danger')
            return render_template('import_clinic_orders.html',u=u,preview=[],summary=None,warnings=[])
        try:
            rows,warnings=parse_clinic_order_workbook(f, request.form.get('sheet_name') or None)
        except Exception as e:
            flash(f'Workbook could not be read: {e}','danger')
            return render_template('import_clinic_orders.html',u=u,preview=[],summary=None,warnings=[])
        commit=request.form.get('mode')=='commit'
        counts={'rows':len(rows),'ready':0,'imported':0,'duplicates':0,'missing_clinic':0,'missing_patient':0,'no_tests':0,'invalid_dob':0,'clinics_created':0}
        for row in rows:
            issues=[]
            if not row['sample_id']:
                issues.append('Missing sample/order ID')
            if not row['clinic']:
                issues.append('Missing clinic')
            if not (row['first'] or row['last']):
                issues.append('Missing patient name')
            if row['dob_raw'] and not row['dob']:
                issues.append('DOB needs review'); counts['invalid_dob']+=1
            dup=bool(row['sample_id'] and (Order.query.filter_by(accession_no=row['sample_id']).first() or Sample.query.filter_by(sample_no=row['sample_id']).first()))
            if dup:
                issues.append('Already imported');counts['duplicates']+=1
            clinic=clinic_for_import(row['clinic'],row['account_id'],create=commit and not dup)
            if not clinic:
                if commit and row['clinic']:
                    counts['missing_clinic']+=1
                elif not commit and row['clinic']:
                    # preview a prospective clinic without creating it
                    pass
            # In preview, infer default tests from an existing matching clinic only.
            tests=selected_hart_tests_for_row(row,clinic) if clinic else []
            if not tests and (row['cadhs'] or row['cve']):
                # test definitions still resolve even for a prospective new clinic
                if row['cadhs']:
                    t=Test.query.filter_by(code='HART-CADHS').first(); tests += [t] if t else []
                if row['cve']:
                    t=Test.query.filter_by(code='HART-CVE').first(); tests += [t] if t else []
            if not tests:
                issues.append('No HART test selected / no clinic standing order');counts['no_tests']+=1
            if not row['clinic']: counts['missing_clinic']+=1
            if not (row['first'] or row['last']): counts['missing_patient']+=1
            ready=not any(x in issues for x in ('Missing sample/order ID','Missing clinic','Missing patient name','Already imported','No HART test selected / no clinic standing order'))
            if ready: counts['ready']+=1
            if commit and ready:
                # clinic may have just been created above; count it if it has no prior order and was newly flushed this transaction
                clinic=clinic_for_import(row['clinic'],row['account_id'],create=True)
                testlist=selected_hart_tests_for_row(row,clinic)
                # Explicit spreadsheet flags take precedence even if a new clinic has no standing-order row.
                if row['cadhs'] is not None or row['cve'] is not None:
                    testlist=[]
                    if row['cadhs']:
                        t=Test.query.filter_by(code='HART-CADHS').first(); testlist += [t] if t else []
                    if row['cve']:
                        t=Test.query.filter_by(code='HART-CVE').first(); testlist += [t] if t else []
                if not testlist:
                    continue
                order_no='IMP-'+re.sub(r'[^A-Za-z0-9-]','',row['sample_id'])[:60]
                if Order.query.filter_by(order_no=order_no).first():
                    order_no='IMP-'+utcnow().strftime('%Y%m%d%H%M%S')+'-'+secrets.token_hex(2).upper()
                conf=secrets.token_urlsafe(8).replace('-','').replace('_','')[:10].upper()
                patient_name=(' '.join(x for x in [row['first'],row['last']] if x)).strip()
                notes='; '.join(x for x in [row['notes'],f'Imported from clinic Excel: {row["sheet"]} row {row["excel_row"]}',f'FedEx: {row["fedex"]}' if row['fedex'] else '',f'Received by: {row["received_by"]}' if row['received_by'] else ''] if x)
                recv_dt=datetime.combine(row['date_received'],datetime.min.time(),tzinfo=timezone.utc) if row['date_received'] else utcnow()
                o=Order(order_no=order_no,clinic_id=clinic.id,requester_organization=clinic.name,patient_name=patient_name,
                        patient_dob=row['dob'].isoformat() if row['dob'] else row['dob_raw'][:20],patient_sex=row['sex'][:20],patient_mrn=row['sample_id'],
                        provider_name='',status='Received',created_at=recv_dt,accession_no=row['sample_id'],sample_received_at=recv_dt,notes=notes,confirmation_code=conf)
                db.session.add(o);db.session.flush()
                for t in testlist: db.session.add(OrderTest(order_id=o.id,test_id=t.id))
                sample=Sample(sample_no=row['sample_id'],order_id=o.id,specimen_type='Serum',status='Received',received_at=recv_dt,collected_at=row['date_collected'].isoformat() if row['date_collected'] else '')
                db.session.add(sample); counts['imported']+=1
                audit('EXCEL_STANDING_ORDER_IMPORT','order',o.id,f'{o.order_no}; clinic={clinic.name}; tests={",".join(t.code for t in testlist)}; source={row["sheet"]}:{row["excel_row"]}',user_id=u.id)
            preview.append({**row,'clinic_match':clinic.name if clinic else row['clinic'],'tests':', '.join(t.name for t in tests if t),'issues':'; '.join(issues) if issues else 'Ready'})
        if commit:
            db.session.commit()
            flash(f'Imported {counts["imported"]} clinic orders. Duplicate and incomplete rows were skipped.','success')
        summary=counts
    return render_template('import_clinic_orders.html',u=u,preview=preview[:200],summary=summary,warnings=warnings)


@app.route('/orders')
def orders():
    r=require_login()
    if r:return r
    u=current_user()
    q=provider_order_query(u)
    term=(request.args.get('q') or '').strip()
    status=(request.args.get('status') or '').strip()
    if term:
        like=f'%{term}%'
        q=q.filter(db.or_(Order.order_no.ilike(like),Order.patient_name.ilike(like),Order.patient_mrn.ilike(like),
                          Order.accession_no.ilike(like),Order.requester_name.ilike(like),Order.requester_organization.ilike(like)))
    all_counts=dict(db.session.query(Order.status,db.func.count(Order.id)).filter(Order.id.in_(provider_order_query(u).with_entities(Order.id))).group_by(Order.status).all())
    if status:
        q=q.filter(Order.status==status)
    rows=q.order_by(Order.id.desc()).all()
    return render_template('orders.html',u=u,orders=rows,term=term,status=status,status_counts=all_counts)


def create_order(selected, customer_user=None, link=None, source='portal'):
    order_no='ORD-'+utcnow().strftime('%Y%m%d%H%M%S')+'-'+secrets.token_hex(2).upper()
    confirmation=secrets.token_urlsafe(8).replace('-','').replace('_','')[:10].upper()
    clinic_id=(customer_user.clinic_id if customer_user else None) or (link.clinic_id if link else None)
    clinic=db.session.get(Clinic,clinic_id) if clinic_id else None
    o=Order(order_no=order_no,
            customer_user_id=customer_user.id if customer_user else None,
            share_link_id=link.id if link else None,
            clinic_id=clinic_id,
            requester_name=request.form.get('requester_name') or (customer_user.name if customer_user else ''),
            requester_email=request.form.get('requester_email') or (customer_user.email if customer_user else ''),
            requester_phone=request.form.get('requester_phone'),
            requester_organization=(clinic.name if clinic else '') or request.form.get('requester_organization') or (customer_user.organization if customer_user else '') or (link.organization_hint if link else ''),
            patient_name=request.form['patient_name'].strip(), patient_dob=request.form.get('patient_dob'), patient_sex=request.form.get('patient_sex'),
            patient_mrn=request.form.get('patient_mrn'), patient_phone=request.form.get('patient_phone'), patient_email=request.form.get('patient_email'),
            patient_address=request.form.get('patient_address'), patient_city=request.form.get('patient_city'), patient_state=request.form.get('patient_state'), patient_zip=request.form.get('patient_zip'),
            height_in=money(request.form.get('height_in')) or None, weight_lb=money(request.form.get('weight_lb')) or None,
            systolic_bp=int(request.form.get('systolic_bp')) if (request.form.get('systolic_bp') or '').isdigit() else None,
            diastolic_bp=int(request.form.get('diastolic_bp')) if (request.form.get('diastolic_bp') or '').isdigit() else None,
            stent_history=request.form.get('stent_history'), stent_date=request.form.get('stent_date'), cabg_history=request.form.get('cabg_history'), cabg_date=request.form.get('cabg_date'),
            intervention_notes=request.form.get('intervention_notes'), serum_creatinine_mg_dl=money(request.form.get('serum_creatinine_mg_dl')) or None,
            provider_name=request.form.get('provider_name'),
            status='Submitted', notes=request.form.get('notes'), confirmation_code=confirmation,
            payment_type=payment_type_from_form(), payer_name=request.form.get('payer_name'),
            insurance_member_id=request.form.get('insurance_member_id'), insurance_group_no=request.form.get('insurance_group_no'),
            free_reason=request.form.get('free_reason'), billing_status='Not Billed')
    update_order_calculated_demographics(o)
    db.session.add(o); db.session.flush()
    for tid in selected:
        db.session.add(OrderTest(order_id=o.id,test_id=int(tid)))
    if link:
        link.use_count += 1
    db.session.commit()
    audit('CREATE','order',o.id,f'{o.order_no}; source={source}', user_id=customer_user.id if customer_user else None)
    return o

@app.route('/orders/new', methods=['GET','POST'])
def new_order():
    r=require_login()
    if r:return r
    u=current_user()
    if u.role not in ('customer','staff','director','master'):
        abort(403)
    tests=Test.query.filter_by(active=True).order_by(Test.name).all()
    internal_order = u.role in ('staff','director','master')
    if request.method=='POST':
        selected=request.form.getlist('tests')
        if not selected:
            flash('Select at least one test.','danger')
            return render_template('new_order.html',u=u,tests=tests,provider_menu=provider_ordering_menu(tests),internal_order=internal_order)
        source='internal-laboratory-order' if internal_order else 'authenticated-provider'
        o=create_order(selected,customer_user=u,source=source)
        if internal_order:
            audit('INTERNAL_ORDER_ENTRY','order',o.id,f'Entered by {u.name} ({role_label(u.role)}); ordering provider={o.provider_name or "not specified"}',user_id=u.id)
        flash(f'Order {o.order_no} submitted.','success')
        return redirect(url_for('order_detail',order_id=o.id))
    return render_template('new_order.html',u=u,tests=tests,provider_menu=provider_ordering_menu(tests),internal_order=internal_order)

@app.route('/request/<token>', methods=['GET','POST'])
def public_request(token):
    link=ShareLink.query.filter_by(token=token).first()
    if not link_valid(link):
        return render_template('public_link_invalid.html',u=None), 410
    tests=available_tests_for_link(link)
    if request.method=='POST':
        selected=request.form.getlist('tests')
        allowed={str(t.id) for t in tests}
        if not selected or not set(selected).issubset(allowed):
            flash('Please select at least one available test.','danger')
            return render_template('public_request.html',u=None,link=link,tests=tests,provider_menu=provider_ordering_menu(tests))
        required=['requester_name','requester_email','patient_name','provider_name']
        if any(not request.form.get(x,'').strip() for x in required):
            flash('Please complete the required fields.','danger')
            return render_template('public_request.html',u=None,link=link,tests=tests,provider_menu=provider_ordering_menu(tests))
        o=create_order(selected,link=link,source='shared-link')
        return redirect(url_for('public_request_success',token=token,code=o.confirmation_code))
    return render_template('public_request.html',u=None,link=link,tests=tests,provider_menu=provider_ordering_menu(tests))

@app.route('/request/<token>/submitted/<code>')
def public_request_success(token,code):
    link=ShareLink.query.filter_by(token=token).first()
    o=Order.query.filter_by(confirmation_code=code,share_link_id=link.id if link else -1).first()
    if not o: abort(404)
    return render_template('public_request_success.html',u=None,link=link,order=o)

@app.route('/request/<token>/submitted/<code>/edit', methods=['GET','POST'])
def public_request_edit(token,code):
    link=ShareLink.query.filter_by(token=token).first()
    o=Order.query.filter_by(confirmation_code=code,share_link_id=link.id if link else -1).first()
    if not o: abort(404)
    # Existing submitted orders remain editable through their original strong share token even if
    # the reusable link later expires; no patient/result browsing is exposed by this route.
    if not link: abort(404)
    tests=available_tests_for_link(link)
    selected_ids={x.test_id for x in OrderTest.query.filter_by(order_id=o.id).all()}
    editable=order_provider_editable(o)
    if request.method=='POST':
        action=request.form.get('action')
        if not editable:
            flash('This request can no longer be edited online because the laboratory has received or started processing it. Contact Complete Omics for an amendment.','danger')
            return redirect(url_for('public_request_success',token=token,code=code))
        if action=='cancel_order':
            reason=(request.form.get('cancel_reason') or 'Cancelled by submitting provider before specimen receipt').strip()
            o.status='Cancelled'; db.session.commit(); audit('PUBLIC_PROVIDER_CANCEL','order',o.id,reason,user_id=None)
            flash('The request has been cancelled.','success')
            return redirect(url_for('public_request_success',token=token,code=code))
        try:
            apply_provider_order_corrections(o)
            allowed={t.id for t in tests}
            sync_order_tests(o,request.form.getlist('tests'),allowed_ids=allowed,actor_user_id=None,audit_prefix='PUBLIC_PROVIDER_CORRECTION')
            db.session.commit(); audit('PUBLIC_PROVIDER_CORRECTION','order',o.id,'External provider corrected submitted request',user_id=None)
            flash('Your corrections were saved.','success')
            return redirect(url_for('public_request_success',token=token,code=code))
        except ValueError as e:
            db.session.rollback(); flash(str(e),'danger')
            selected_ids={int(x) for x in request.form.getlist('tests') if x.isdigit()}
    return render_template('public_request_edit.html',u=None,link=link,order=o,tests=tests,provider_menu=provider_ordering_menu(tests),selected_ids=selected_ids,editable=editable)

@app.route('/request/<token>/submitted/<code>/requisition.pdf')
def public_requisition_pdf(token,code):
    link=ShareLink.query.filter_by(token=token).first()
    o=Order.query.filter_by(confirmation_code=code,share_link_id=link.id if link else -1).first()
    if not o: abort(404)
    ots=OrderTest.query.filter_by(order_id=o.id).all()
    tests=[db.session.get(Test,x.test_id) for x in ots]
    return make_requisition_pdf(o,tests)

@app.route('/share-links', methods=['GET','POST'])
def share_links():
    role_required('director')
    u=current_user()
    tests=Test.query.filter_by(active=True).order_by(Test.name).all()
    if request.method=='POST':
        label=request.form['label'].strip()
        days=int(request.form.get('expires_days') or 30)
        selected=request.form.getlist('tests')
        clinic_id=int(request.form.get('clinic_id')) if request.form.get('clinic_id') else None
        clinic=db.session.get(Clinic,clinic_id) if clinic_id else None
        link=ShareLink(token=secrets.token_urlsafe(32),label=label,organization_hint=(clinic.name if clinic else request.form.get('organization_hint')),clinic_id=(clinic.id if clinic else None),created_by=u.id,
                       expires_at=utcnow()+timedelta(days=max(1,min(days,365))),allowed_test_ids=','.join(selected))
        db.session.add(link);db.session.commit();audit('CREATE','share_link',link.id,label)
        flash('Secure request link created. Copy it and send it to the clinic/provider.','success')
        return redirect(url_for('share_links'))
    links=ShareLink.query.order_by(ShareLink.id.desc()).all()
    public_urls={x.id: canonical_public_url('public_request', token=x.token) for x in links}
    public_base=app.config.get('PUBLIC_BASE_URL')
    local_only=(not public_base and request.host.split(':')[0] in ('127.0.0.1','localhost'))
    return render_template('share_links.html',u=u,links=links,tests=tests,
                           clinics=Clinic.query.filter_by(active=True).order_by(Clinic.name).all(),
                           public_urls=public_urls, public_base=public_base, local_only=local_only)

@app.route('/share-links/<int:link_id>/toggle', methods=['POST'])
def toggle_share_link(link_id):
    role_required('director')
    link=db.session.get(ShareLink,link_id) or abort(404)
    link.active=not link.active;db.session.commit();audit('TOGGLE','share_link',link.id,f'active={link.active}')
    return redirect(url_for('share_links'))

def order_provider_editable(o):
    """Provider corrections are allowed only before accession/receipt/testing."""
    return bool(o and o.status == 'Submitted' and not o.accession_no and not o.sample_received_at)

def sync_order_tests(o, selected_ids, allowed_ids=None, actor_user_id=None, audit_prefix='PROVIDER_CORRECTION'):
    """Synchronize requested tests while preserving an audit record of additions/removals."""
    selected={int(x) for x in selected_ids if str(x).isdigit()}
    if allowed_ids is not None:
        allowed={int(x) for x in allowed_ids}
        if not selected.issubset(allowed):
            raise ValueError('One or more selected tests are not available for this request.')
    if not selected:
        raise ValueError('An active order must contain at least one test. Use Cancel Request to cancel the entire order.')
    existing=OrderTest.query.filter_by(order_id=o.id).all()
    existing_ids={x.test_id for x in existing}
    add_ids=selected-existing_ids
    remove_ids=existing_ids-selected
    # Provider corrections are only allowed before results exist, but enforce this again.
    for row in existing:
        if row.test_id in remove_ids and (row.result or row.result_status not in (None,'Pending')):
            raise ValueError('A test with laboratory results cannot be removed. Contact the laboratory director.')
    added_codes=[]; removed_codes=[]
    for tid in sorted(add_ids):
        t=db.session.get(Test,tid)
        if not t or not t.active: continue
        db.session.add(OrderTest(order_id=o.id,test_id=tid)); added_codes.append(t.code)
    for row in existing:
        if row.test_id in remove_ids:
            t=db.session.get(Test,row.test_id)
            removed_codes.append(t.code if t else str(row.test_id))
            db.session.delete(row)
    details=f'Added={",".join(added_codes) or "none"}; Removed={",".join(removed_codes) or "none"}'
    audit(audit_prefix,'order',o.id,details,user_id=actor_user_id)
    return added_codes,removed_codes

def apply_provider_order_corrections(o):
    fields=['requester_name','requester_email','requester_phone','provider_name','patient_name','patient_dob','patient_sex','patient_mrn','patient_phone','patient_email','patient_address','patient_city','patient_state','patient_zip','stent_history','stent_date','cabg_history','cabg_date','intervention_notes','notes']
    for f in fields:
        if f in request.form:
            val=(request.form.get(f) or '').strip()
            setattr(o,f,val or None)
    if request.form.get('height_in') is not None: o.height_in=money(request.form.get('height_in')) or None
    if request.form.get('weight_lb') is not None: o.weight_lb=money(request.form.get('weight_lb')) or None
    if request.form.get('systolic_bp') is not None: o.systolic_bp=int(request.form.get('systolic_bp')) if (request.form.get('systolic_bp') or '').isdigit() else None
    if request.form.get('diastolic_bp') is not None: o.diastolic_bp=int(request.form.get('diastolic_bp')) if (request.form.get('diastolic_bp') or '').isdigit() else None
    if request.form.get('serum_creatinine_mg_dl') is not None: o.serum_creatinine_mg_dl=money(request.form.get('serum_creatinine_mg_dl')) or None
    o.payment_type=payment_type_from_form(o.payment_type or 'Insurance')
    o.payer_name=(request.form.get('payer_name') or '').strip() or None
    o.insurance_member_id=(request.form.get('insurance_member_id') or '').strip() or None
    o.insurance_group_no=(request.form.get('insurance_group_no') or '').strip() or None
    o.free_reason=(request.form.get('free_reason') or '').strip() or None
    if o.payment_type=='Charity/Free': o.charity_approved=False
    update_order_calculated_demographics(o)

@app.route('/orders/<int:order_id>', methods=['GET','POST'])
def order_detail(order_id):
    r=require_login()
    if r:return r
    u=current_user(); o=db.session.get(Order,order_id) or abort(404)
    if u.role=='customer' and not ((u.clinic_id and o.clinic_id==u.clinic_id) or (not u.clinic_id and o.customer_user_id==u.id)): abort(403)
    if request.method=='GET': audit('PHI_VIEW','order',o.id,f'order={o.order_no}; role={u.role}',user_id=u.id)
    if request.method=='POST' and request.form.get('action')=='delete_mistaken_order':
        may_delete = order_provider_editable(o) and not Sample.query.filter_by(order_id=o.id).first() and not o.accession_no and o.status=='Submitted'
        if u.role=='customer' and o.customer_user_id and o.customer_user_id != u.id:
            may_delete=False
        if not may_delete:
            flash('This order can no longer be deleted because laboratory work has started or it is not your order. Use cancellation/amendment instead.','danger')
            return redirect(url_for('order_detail',order_id=o.id))
        order_id_value=o.id; order_no_value=o.order_no
        AutoVerificationEvent.query.filter_by(order_id=o.id).delete(synchronize_session=False)
        OrderTest.query.filter_by(order_id=o.id).delete(synchronize_session=False)
        audit('DELETE_DRAFT','order',order_id_value,f'{order_no_value}; created in error and removed before receipt',user_id=u.id)
        db.session.delete(o); db.session.commit()
        flash(f'Order {order_no_value} was deleted because it was entered in error before laboratory receipt.','success')
        return redirect(url_for('orders'))
    if request.method=='POST' and u.role=='customer' and request.form.get('action') in ('provider_correct','provider_cancel'):
        action=request.form.get('action')
        if not order_provider_editable(o):
            flash('This order can no longer be changed by the provider because the laboratory has received or started processing it. Please contact Complete Omics for an amendment.','danger')
            return redirect(url_for('order_detail',order_id=o.id))
        if action=='provider_cancel':
            reason=(request.form.get('cancel_reason') or 'Provider cancelled before specimen receipt').strip()
            o.status='Cancelled'; db.session.commit(); audit('PROVIDER_CANCEL','order',o.id,reason,user_id=u.id)
            flash('The order was cancelled. It remains in the audit history and will not proceed to testing.','success')
            return redirect(url_for('order_detail',order_id=o.id))
        try:
            apply_provider_order_corrections(o)
            sync_order_tests(o,request.form.getlist('tests'),actor_user_id=u.id)
            db.session.commit(); audit('PROVIDER_CORRECTION','order',o.id,'Provider updated order details',user_id=u.id)
            flash('Order corrections saved.','success')
        except ValueError as e:
            db.session.rollback(); flash(str(e),'danger')
        return redirect(url_for('order_detail',order_id=o.id))
    if request.method=='POST' and u.role=='customer' and request.form.get('action')=='payer_update':
        o.payment_type=payment_type_from_form(o.payment_type or 'Insurance')
        o.payer_name=(request.form.get('payer_name') or '').strip() or None
        o.insurance_member_id=(request.form.get('insurance_member_id') or '').strip() or None
        o.insurance_group_no=(request.form.get('insurance_group_no') or '').strip() or None
        o.free_reason=(request.form.get('free_reason') or '').strip() or None
        if o.payment_type=='Charity/Free':
            o.charity_approved=False
        db.session.commit();audit('PAYER_UPDATE','order',o.id,o.payment_type,user_id=u.id)
        flash('Payment option updated.','success')
        return redirect(url_for('order_detail',order_id=o.id))
    if request.method=='POST' and u.role in ('staff','director','master'):
        action=request.form.get('action')
        if action=='demographics_update':
            fields=['patient_phone','patient_email','patient_address','patient_city','patient_state','patient_zip','stent_history','stent_date','cabg_history','cabg_date','intervention_notes']
            for f in fields:setattr(o,f,(request.form.get(f) or '').strip() or None)
            o.patient_dob=(request.form.get('patient_dob') or o.patient_dob or '').strip() or None
            o.patient_sex=(request.form.get('patient_sex') or o.patient_sex or '').strip() or None
            o.height_in=money(request.form.get('height_in')) or None;o.weight_lb=money(request.form.get('weight_lb')) or None
            o.systolic_bp=int(request.form.get('systolic_bp')) if (request.form.get('systolic_bp') or '').isdigit() else None
            o.diastolic_bp=int(request.form.get('diastolic_bp')) if (request.form.get('diastolic_bp') or '').isdigit() else None
            o.serum_creatinine_mg_dl=money(request.form.get('serum_creatinine_mg_dl')) or None
            update_order_calculated_demographics(o);db.session.commit();audit('DEMOGRAPHICS_UPDATE','order',o.id,'Clinical demographics/intervention history updated')
            flash('Patient demographics and clinical history updated.','success')
        elif action=='billing_update':
            o.payment_type=payment_type_from_form(o.payment_type or 'Insurance')
            o.payer_name=(request.form.get('payer_name') or '').strip() or None
            o.insurance_member_id=(request.form.get('insurance_member_id') or '').strip() or None
            o.insurance_group_no=(request.form.get('insurance_group_no') or '').strip() or None
            o.claim_no=(request.form.get('claim_no') or '').strip() or None
            o.billing_status=(request.form.get('billing_status') or o.billing_status or 'Not Billed').strip()
            o.charge_amount=money(request.form.get('charge_amount'))
            o.expected_reimbursement=0.0 if o.payment_type=='Charity/Free' else money(request.form.get('expected_reimbursement'))
            o.amount_collected=0.0 if o.payment_type=='Charity/Free' else money(request.form.get('amount_collected'))
            o.adjustments=money(request.form.get('adjustments'))
            o.direct_lab_cost=money(request.form.get('direct_lab_cost'))
            o.other_cost=money(request.form.get('other_cost'))
            o.free_reason=(request.form.get('free_reason') or '').strip() or None
            if request.form.get('performed_by_user_id'):
                o.performed_by_user_id=int(request.form['performed_by_user_id'])
            if request.form.get('director_user_id') and is_director(u):
                o.director_user_id=int(request.form['director_user_id'])
            if o.payment_type=='Charity/Free':
                if is_director(u):
                    o.charity_approved=request.form.get('charity_approved')=='1'
            else:
                o.charity_approved=False
            db.session.commit();audit('BILLING_UPDATE','order',o.id,f'{o.payment_type}; {o.billing_status}')
            flash('Billing and financial details updated.','success')
        elif action=='receive':
            o.accession_no='CO-'+utcnow().strftime('%y%m%d')+'-'+str(o.id).zfill(5);o.sample_received_at=utcnow();o.status='Received'
            if not Sample.query.filter_by(order_id=o.id).first():
                sample_no='S-'+utcnow().strftime('%y%m%d')+'-'+str(o.id).zfill(5)
                first_ot=OrderTest.query.filter_by(order_id=o.id).first()
                first_test=db.session.get(Test,first_ot.test_id) if first_ot else None
                db.session.add(Sample(sample_no=sample_no,order_id=o.id,specimen_type=(first_test.specimen if first_test else 'Serum'),status='Received',received_at=utcnow()))
            db.session.commit();audit('RECEIVE','order',o.id,o.accession_no)
        elif action=='testing':
            o.status='Testing';db.session.commit();audit('STATUS','order',o.id,'Testing')
        elif action=='save_results':
            rows=OrderTest.query.filter_by(order_id=o.id).all()
            for rr in rows:
                t=db.session.get(Test,rr.test_id);val=request.form.get(f'result_{rr.id}','').strip();flag=''
                try:
                    num=float(val)
                    flag=toxicology_interpret(t.code,num) or apply_reference(o,t,rr,num)
                except ValueError: pass
                rr.result=val;rr.result_flag=flag;rr.result_status='Entered';rr.entered_by=u.id;rr.entered_at=utcnow()
                if t and t.code.upper() in ('CREAT','CREATININE','AU_CREAT','CREA','CRE'):
                    try:o.serum_creatinine_mg_dl=float(val);update_order_calculated_demographics(o)
                    except ValueError:pass
                AutoVerificationEvent.query.filter_by(order_test_id=rr.id).delete()
                try:
                    num=float(val); decision,checks=autoverification_checks(o,t,rr,num)
                    db.session.add(AutoVerificationEvent(order_id=o.id,order_test_id=rr.id,test_id=t.id,decision=decision,checks_json=json.dumps(checks)))
                except ValueError: pass
            calc_changed=run_calculations(o,u.id)
            o.status='Review';db.session.commit();audit('RESULTS_ENTERED','order',o.id,'Calculated: '+','.join(calc_changed))
        elif action=='approve' and is_director(u):
            holds=AutoVerificationEvent.query.filter_by(order_id=o.id,decision='Hold').all()
            override=(request.form.get('override_reason') or '').strip()
            if holds and not override:
                flash(f'{len(holds)} automated quality hold(s) require review. Enter a director override reason to release.','danger')
                return redirect(url_for('order_detail',order_id=o.id))
            for rr in OrderTest.query.filter_by(order_id=o.id).all():
                rr.result_status='Approved';rr.approved_by=u.id;rr.approved_at=utcnow()
            o.status='Released';db.session.commit();audit('APPROVE_RELEASE','order',o.id,('Director override: '+override) if override else 'Quality checks passed')
        return redirect(url_for('order_detail',order_id=o.id))
    rows=[]
    for ot in OrderTest.query.filter_by(order_id=o.id).all():
        rows.append((ot,db.session.get(Test,ot.test_id)))
    customer=db.session.get(User,o.customer_user_id) if o.customer_user_id else None
    av_events=AutoVerificationEvent.query.filter_by(order_id=o.id).order_by(AutoVerificationEvent.id.desc()).all()
    staff_users=User.query.filter(User.active==True,User.role.in_(['staff','director','master'])).order_by(User.name).all()
    directors=User.query.filter(User.active==True,User.role.in_(['director','master'])).order_by(User.name).all()
    fin=order_financials(o)
    correction_tests=Test.query.filter_by(active=True).order_by(Test.name).all() if u.role=='customer' and order_provider_editable(o) else []
    correction_provider_menu=provider_ordering_menu(correction_tests) if correction_tests else []
    selected_test_ids={ot.test_id for ot,_ in rows}
    return render_template('order_detail.html',u=u,order=o,rows=rows,customer=customer,av_events=av_events,staff_users=staff_users,directors=directors,fin=fin,correction_tests=correction_tests,correction_provider_menu=correction_provider_menu,selected_test_ids=selected_test_ids,provider_editable=order_provider_editable(o))

@app.route('/finance')
def finance_dashboard():
    u=role_required('director','master')
    today=utcnow().date()
    month_start=date(today.year,today.month,1)
    year_start=date(today.year,1,1)
    orders=Order.query.order_by(Order.created_at.desc()).all()
    def in_range(o,start):
        d=o.created_at.date() if hasattr(o.created_at,'date') else today
        return d>=start
    def aggregate(items):
        vals=[order_financials(x) for x in items]
        return {
            'orders':len(items),
            'revenue':sum(v['revenue'] for v in vals),
            'expected':sum(v['expected'] for v in vals),
            'cost':sum(v['cost'] for v in vals),
            'net_profit':sum(v['net_profit'] for v in vals),
            'expected_profit':sum(v['expected_profit'] for v in vals),
            'free_orders':sum(1 for x in items if x.payment_type=='Charity/Free')
        }
    month_orders=[o for o in orders if in_range(o,month_start)]
    ytd_orders=[o for o in orders if in_range(o,year_start)]
    monthly=[]
    for m in range(1,today.month+1):
        mo=[o for o in ytd_orders if o.created_at.month==m]
        row=aggregate(mo);row['month']=date(today.year,m,1).strftime('%b');monthly.append(row)
    recent=[(o,order_financials(o)) for o in orders[:100]]
    return render_template('finance.html',u=u,month=aggregate(month_orders),ytd=aggregate(ytd_orders),monthly=monthly,recent=recent)

@app.route('/finance/export.csv')
def finance_export():
    u=role_required('director','master')
    rows=Order.query.order_by(Order.created_at).all()
    output=io.StringIO();w=csv.writer(output)
    w.writerow(['Order','Date','Patient','Organization','Payment Type','Payer','Billing Status','Charge','Expected Reimbursement','Collected','Adjustments','Direct Lab Cost','Other Cost','Net Profit','Expected Profit'])
    for o in rows:
        f=order_financials(o)
        w.writerow([o.order_no,o.created_at.date().isoformat(),o.patient_name,o.requester_organization,o.payment_type,o.payer_name,o.billing_status,o.charge_amount,o.expected_reimbursement,o.amount_collected,o.adjustments,o.direct_lab_cost,o.other_cost,f['net_profit'],f['expected_profit']])
    return Response(output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment;filename=labos_financials.csv'})

@app.route('/tests', methods=['GET','POST'])
def test_catalog():
    role_required('staff','director');u=current_user()
    if request.method=='POST' and is_director(u):
        try:
            t=Test(code=request.form['code'].strip(),name=request.form['name'].strip(),specimen=request.form.get('specimen'),unit=request.form.get('unit'),
                   ref_low=float(request.form['ref_low']) if request.form.get('ref_low') else None,
                   ref_high=float(request.form['ref_high']) if request.form.get('ref_high') else None,method=request.form.get('method'),
                   loinc_code=(request.form.get('loinc_code') or '').strip() or None,
                   loinc_name=(request.form.get('loinc_name') or '').strip() or None,
                   loinc_version=(request.form.get('loinc_version') or LOINC_VERSION).strip() or LOINC_VERSION,
                   loinc_status=(request.form.get('loinc_status') or 'LOCAL / REVIEW').strip())
            db.session.add(t);db.session.commit();audit('CREATE','test',t.id,t.code);flash('Test added.','success')
        except Exception:
            db.session.rollback();flash('Could not add test. Check for duplicate code or invalid values.','danger')
    return render_template('tests.html',u=u,tests=Test.query.order_by(Test.name).all())

@app.route('/diagnostics-menu')
def diagnostics_menu():
    role_required('staff','director'); u=current_user()
    tests={t.code:t for t in Test.query.all()}
    grouped={}
    for item in DIAGNOSTIC_MENU:
        row=dict(item)
        t=tests.get(item['code'])
        row['active']=bool(t.active) if t else False
        row['test_id']=t.id if t else None
        row['loinc_code']=t.loinc_code if t else None
        row['loinc_status']=t.loinc_status if t else None
        grouped.setdefault(item['platform'],{}).setdefault(item['category'],[]).append(row)
    stats=[]
    for platform,cats in grouped.items():
        rows=[x for vals in cats.values() for x in vals]
        stats.append({'platform':platform,'count':len(rows),'active':sum(1 for x in rows if x['active'])})
    return render_template('diagnostics_menu.html',u=u,grouped=grouped,stats=stats,total=sum(x['count'] for x in stats),active=sum(x['active'] for x in stats))

@app.route('/diagnostics-menu/toggle/<int:test_id>',methods=['POST'])
def diagnostics_toggle(test_id):
    u=role_required('director')
    t=db.session.get(Test,test_id)
    if not t: abort(404)
    if t.code not in DIAGNOSTIC_META:
        flash('Only diagnostics-menu candidate assays can be toggled here.','danger')
        return redirect(url_for('diagnostics_menu'))
    t.active=not t.active
    db.session.commit()
    audit('DIAGNOSTIC_TEST_'+('ACTIVATED' if t.active else 'DEACTIVATED'),'test',t.id,t.code)
    flash(f"{t.name} {'activated for ordering' if t.active else 'deactivated'}.",'success')
    return redirect(url_for('diagnostics_menu'))

@app.route('/diagnostics-menu/export')
def diagnostics_export():
    role_required('staff','director')
    tests={t.code:t for t in Test.query.all()}
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(['Test Code','Test Name','Platform','Category','Specimen','Unit','LOINC','LOINC Name','LOINC Version','LOINC Status','Orderable/Active','Reference Interval Status'])
    for item in DIAGNOSTIC_MENU:
        t=tests.get(item['code'])
        ri_count=ReferenceInterval.query.filter_by(test_id=t.id,active=True).count() if t else 0
        w.writerow([item['code'],item['name'],item['platform'],item['category'],item['specimen'],item['unit'],
                    t.loinc_code if t else '',t.loinc_name if t else '',t.loinc_version if t else '',t.loinc_status if t else '',
                    'Yes' if (t and t.active) else 'No','Configured' if ri_count else 'Not configured'])
    return Response(out.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment;filename=Complete_Omics_Extended_Diagnostics_Menu.csv'})


@app.route('/loinc-mapping', methods=['GET','POST'])
def loinc_mapping():
    u=role_required('staff','director')
    if request.method=='POST':
        if not is_director(u): abort(403)
        t=db.session.get(Test, int(request.form.get('test_id') or 0)) or abort(404)
        t.loinc_code=(request.form.get('loinc_code') or '').strip() or None
        t.loinc_name=(request.form.get('loinc_name') or '').strip() or None
        t.loinc_version=(request.form.get('loinc_version') or LOINC_VERSION).strip() or LOINC_VERSION
        t.loinc_status=(request.form.get('loinc_status') or '').strip() or None
        t.loinc_notes=(request.form.get('loinc_notes') or '').strip() or None
        t.loinc_source=(request.form.get('loinc_source') or '').strip() or None
        db.session.commit()
        audit('UPDATE','test_loinc',t.id,f'{t.code}={t.loinc_code or "LOCAL"}; status={t.loinc_status or ""}')
        flash(f'LOINC mapping updated for {t.name}.','success')
        return redirect(url_for('loinc_mapping',q=request.args.get('q','')))
    rows=Test.query.order_by(Test.method,Test.name).all()
    return render_template('loinc_mapping.html',u=u,rows=rows,loinc_version=LOINC_VERSION)

@app.route('/loinc-mapping/export.csv')
def loinc_mapping_export():
    role_required('staff','director')
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(['Local Test Code','Test Name','Specimen','Unit','Method/Platform','LOINC','LOINC Long Common Name','LOINC Version','Mapping Status','Notes','Source','Exchange Eligible'])
    for t in Test.query.order_by(Test.method,Test.name).all():
        w.writerow([t.code,t.name,t.specimen,t.unit,t.method,t.loinc_code,t.loinc_name,t.loinc_version,t.loinc_status,t.loinc_notes,t.loinc_source,'Yes' if loinc_exchange_code(t) else 'No'])
    return Response(out.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment;filename=Complete_Omics_LOINC_Mapping.csv'})


@app.route('/toxicology')
def toxicology():
    role_required('staff','director')
    u=current_user()
    tests={t.code:t for t in Test.query.all()}
    menu=[]
    for item in DIAGNOSTIC_MENU:
        if item['platform']!='Complete Omics LC-MS/MS Toxicology':
            continue
        row=dict(item)
        t=tests.get(item['code'])
        spec=TOX_SPEC_BY_CODE.get(item['code'])
        row['active']=bool(t.active) if t else False
        row['test_id']=t.id if t else None
        row['spec']=spec
        menu.append(row)
    recent=ToxicologyBatchReview.query.order_by(ToxicologyBatchReview.id.desc()).limit(12).all()
    batches=Batch.query.order_by(Batch.id.desc()).limit(50).all()
    return render_template('toxicology.html',u=u,menu=menu,rules=TOX_BATCH_RULES,recent=recent,batches=batches)

@app.route('/toxicology/batch-review',methods=['POST'])
def toxicology_batch_review():
    u=role_required('staff','director')
    checks={k:bool(request.form.get(k)) for k in [
        'calibrators_ok','qc_ok','retention_time_ok','ion_ratio_ok','carryover_ok','internal_standards_ok','specimen_validity_ok'
    ]}
    decision='Accept' if all(checks.values()) else 'Hold'
    bid=request.form.get('batch_id')
    r=ToxicologyBatchReview(
        batch_id=int(bid) if bid and bid.isdigit() else None,
        run_name=(request.form.get('run_name') or 'LC-MS/MS Run').strip(),
        decision=decision,
        notes=request.form.get('notes'),
        reviewed_by=u.id,
        **checks
    )
    db.session.add(r)
    db.session.commit()
    audit('TOX_BATCH_REVIEW','toxicology_batch_review',r.id,f'decision={decision}')
    flash(f'Toxicology batch review saved: {decision}.','success' if decision=='Accept' else 'danger')
    return redirect(url_for('toxicology'))

@app.route('/toxicology/export.csv')
def toxicology_export():
    role_required('staff','director')
    tests={t.code:t for t in Test.query.all()}
    out=io.StringIO()
    w=csv.writer(out)
    w.writerow(['Test Code','Analyte','Category','Specimen','Internal Standard','LLOQ ng/mL','Reporting Cutoff ng/mL','ULOQ ng/mL','Orderable'])
    for item in DIAGNOSTIC_MENU:
        if item['platform']!='Complete Omics LC-MS/MS Toxicology':
            continue
        sp=TOX_SPEC_BY_CODE.get(item['code'],{})
        t=tests.get(item['code'])
        w.writerow([
            item['code'],item['name'],item['category'],item['specimen'],sp.get('internal_standard',''),
            sp.get('lloq',''),sp.get('cutoff',''),sp.get('uloq',''),'Yes' if (t and t.active) else 'No'
        ])
    return Response(out.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment;filename=Complete_Omics_Urine_Toxicology_Menu.csv'})

@app.route('/reference-intervals',methods=['GET','POST'])
def reference_intervals():
    role_required('staff','director');u=current_user()
    if request.method=='POST':
        role_required('director')
        f=request.files.get('file')
        if not f or not f.filename:
            flash('Choose an Excel or CSV reference-interval file.','danger');return redirect(url_for('reference_intervals'))
        try:
            records=[]
            if f.filename.lower().endswith('.csv'):
                text=io.StringIO(f.stream.read().decode('utf-8-sig'))
                records=list(csv.DictReader(text))
            else:
                from openpyxl import load_workbook
                book=load_workbook(f.stream,data_only=True,read_only=True)
                ws=book['Reference Intervals'] if 'Reference Intervals' in book.sheetnames else book.active
                rows=list(ws.iter_rows(values_only=True))
                headers=[str(x).strip() if x is not None else '' for x in rows[0]]
                records=[dict(zip(headers,row)) for row in rows[1:] if any(v is not None for v in row)]
            added=0;skipped=[]
            for rec in records:
                code=str(rec.get('Test Code') or '').strip()
                if not code: continue
                t=Test.query.filter_by(code=code).first()
                if not t:
                    skipped.append(code);continue
                def num(k):
                    v=rec.get(k)
                    if v is None or str(v).strip()=='': return None
                    return float(v)
                eff=rec.get('Effective Date')
                if isinstance(eff,datetime): eff=eff.date()
                elif isinstance(eff,date): pass
                elif eff:
                    try: eff=datetime.strptime(str(eff)[:10],'%Y-%m-%d').date()
                    except Exception: eff=None
                active=str(rec.get('Active') or 'No').strip().lower() in ('yes','true','1','active')
                ri=ReferenceInterval(test_id=t.id,specimen=str(rec.get('Specimen') or t.specimen or '').strip() or None,
                    method=str(rec.get('Method') or t.method or '').strip() or None,sex=str(rec.get('Sex') or 'Any').strip(),
                    age_min=num('Age Min'),age_max=num('Age Max'),age_unit=str(rec.get('Age Unit') or 'Years').strip(),
                    lower_limit=num('Lower Limit'),upper_limit=num('Upper Limit'),unit=str(rec.get('Unit') or t.unit or '').strip() or None,
                    text_reference=str(rec.get('Text Reference') or '').strip() or None,critical_low=num('Critical Low'),critical_high=num('Critical High'),
                    source=str(rec.get('Source / SOP') or '').strip() or None,effective_date=eff,version=str(rec.get('Version') or '').strip() or None,
                    active=active,notes=str(rec.get('Notes') or '').strip() or None)
                db.session.add(ri);added+=1
            db.session.commit();audit('IMPORT','reference_interval',None,f'rows={added}; skipped={sorted(set(skipped))}')
            flash(f'Imported {added} reference interval row(s).'+(f' Unknown test codes skipped: {", ".join(sorted(set(skipped)))}' if skipped else ''),'success')
        except Exception as e:
            db.session.rollback();flash(f'Import failed: {e}','danger')
        return redirect(url_for('reference_intervals'))
    rows=ReferenceInterval.query.order_by(ReferenceInterval.test_id,ReferenceInterval.id.desc()).all()
    tests={t.id:t for t in Test.query.all()}
    return render_template('reference_intervals.html',u=u,rows=rows,tests=tests)


@app.route('/reference-intervals/template.xlsx')
def reference_interval_template():
    role_required('staff','director')
    return send_file(os.path.join(BASE_DIR,'Complete_Omics_Reference_Intervals_Template.xlsx'),as_attachment=True,download_name='Complete_Omics_Reference_Intervals_Template.xlsx')

@app.route('/reference-intervals/template.csv')
def reference_interval_template_csv():
    role_required('staff','director')
    return send_file(os.path.join(BASE_DIR,'Complete_Omics_Reference_Intervals_Template.csv'),as_attachment=True,download_name='Complete_Omics_Reference_Intervals_Template.csv')

@app.route('/reference-intervals/<int:ri_id>/toggle',methods=['POST'])
def toggle_reference_interval(ri_id):
    role_required('director');ri=db.session.get(ReferenceInterval,ri_id) or abort(404);ri.active=not ri.active;db.session.commit();audit('TOGGLE','reference_interval',ri.id,f'active={ri.active}');return redirect(url_for('reference_intervals'))


@app.route('/reference-intervals/add',methods=['POST'])
def reference_interval_add():
    role_required('director')
    tid=int(request.form['test_id']);t=db.session.get(Test,tid) or abort(404)
    def optfloat(name):
        v=(request.form.get(name) or '').strip()
        try:return float(v) if v else None
        except ValueError:return None
    ri=ReferenceInterval(test_id=t.id,specimen=(request.form.get('specimen') or t.specimen or '').strip() or None,method=(request.form.get('method') or t.method or '').strip() or None,
        sex=(request.form.get('sex') or 'Any').strip(),age_min=optfloat('age_min'),age_max=optfloat('age_max'),age_unit=(request.form.get('age_unit') or 'Years').strip(),
        lower_limit=optfloat('lower_limit'),upper_limit=optfloat('upper_limit'),text_reference=(request.form.get('text_reference') or '').strip() or None,
        critical_low=optfloat('critical_low'),critical_high=optfloat('critical_high'),unit=(request.form.get('unit') or t.unit or '').strip() or None,
        source=(request.form.get('source') or '').strip() or None,version=(request.form.get('version') or '').strip() or None,active=request.form.get('active')=='1',notes=(request.form.get('notes') or '').strip() or None)
    db.session.add(ri);db.session.commit();audit('CREATE','reference_interval',ri.id,t.code);flash('Reference interval added.','success');return redirect(url_for('reference_intervals'))

@app.route('/reference-intervals/<int:ri_id>/edit',methods=['POST'])
def reference_interval_edit(ri_id):
    role_required('director');ri=db.session.get(ReferenceInterval,ri_id) or abort(404)
    def optfloat(name):
        v=(request.form.get(name) or '').strip()
        try:return float(v) if v else None
        except ValueError:return None
    for f in ['specimen','method','sex','age_unit','text_reference','unit','source','version','notes']:
        setattr(ri,f,(request.form.get(f) or '').strip() or None)
    for f in ['age_min','age_max','lower_limit','upper_limit','critical_low','critical_high']:setattr(ri,f,optfloat(f))
    ri.active=request.form.get('active')=='1';db.session.commit();audit('UPDATE','reference_interval',ri.id);flash('Reference interval updated.','success');return redirect(url_for('reference_intervals'))

@app.route('/reference-intervals/<int:ri_id>/delete',methods=['POST'])
def reference_interval_delete(ri_id):
    role_required('director');ri=db.session.get(ReferenceInterval,ri_id) or abort(404);db.session.delete(ri);db.session.commit();audit('DELETE','reference_interval',ri_id);flash('Reference interval deleted.','warning');return redirect(url_for('reference_intervals'))


@app.route('/api/card-scan',methods=['POST'])
def card_scan():
    r=require_login()
    if r:return jsonify({'error':'login required'}),401
    f=request.files.get('card')
    card_type=(request.form.get('card_type') or 'license').lower()
    if not f or not f.filename:return jsonify({'error':'Choose an image file.'}),400
    ext=os.path.splitext(f.filename)[1].lower()
    if ext not in ('.png','.jpg','.jpeg','.webp','.tif','.tiff'):
        return jsonify({'error':'Use a PNG, JPG, WEBP, or TIFF image.'}),400
    tmp=tempfile.NamedTemporaryFile(delete=False,suffix=ext);f.save(tmp.name);tmp.close()
    try:
        barcode_text=''
        barcode_error=''
        if card_type=='license':
            try:
                import zxingcpp
                from PIL import Image, ImageOps, ImageEnhance
                base=Image.open(tmp.name).convert('RGB')
                # PDF417 is normally on the BACK of a US driver license. Try several
                # orientations and enhanced/upscaled variants to tolerate phone photos.
                variants=[]
                for angle in (0,90,180,270):
                    im=base.rotate(angle,expand=True) if angle else base
                    variants.append(im)
                    try:
                        gray=ImageOps.autocontrast(ImageOps.grayscale(im))
                        variants.append(gray)
                        if max(im.size)<2600:
                            variants.append(im.resize((im.width*2,im.height*2)))
                    except Exception:
                        pass
                for im in variants:
                    try:
                        codes=zxingcpp.read_barcodes(im)
                        pdf=[c for c in codes if 'PDF417' in str(getattr(c,'format','')).upper()]
                        chosen=(pdf or codes)
                        if chosen:
                            barcode_text=str(chosen[0].text or '')
                            if barcode_text.strip():break
                    except Exception as e:
                        barcode_error=str(e)
            except Exception as e:
                barcode_error=str(e)

        text=''
        ocr_error=''
        try:
            import pytesseract
            from PIL import Image, ImageOps
            tess=configure_tesseract()
            if not tess:
                raise RuntimeError('Tesseract OCR executable was not found.')
            im=Image.open(tmp.name).convert('RGB')
            # Normal pass plus an autocontrast grayscale pass helps with laminated cards.
            text1=pytesseract.image_to_string(im,config='--psm 6')
            try:
                gray=ImageOps.autocontrast(ImageOps.grayscale(im))
                text2=pytesseract.image_to_string(gray,config='--psm 6')
            except Exception:
                text2=''
            text=(text1+'\n'+text2).strip()
        except Exception as e:
            ocr_error=str(e)
            if not barcode_text:
                msg=('Automatic card reading is not ready on this computer. '
                     'Run INSTALL_CARD_READER.bat once, then restart LabOS. '
                     'For a driver license, upload the BACK side for the most reliable PDF417 scan; '
                     'the front side requires OCR.')
                return jsonify({'error':msg,'detail':ocr_error,'barcode_detail':barcode_error}),503

        combined=(barcode_text+'\n'+text).strip()
        data={'raw_text':combined[:4000], 'scan_method':('PDF417 + OCR' if barcode_text and text else ('PDF417' if barcode_text else 'OCR'))}
        lines=[x.strip() for x in combined.splitlines() if x.strip()]
        if card_type=='license':
            joined='\n'.join(lines)
            def aamva(code):
                m=re.search(r'(?:^|\n)'+code+r'([^\n]+)',joined,re.I);return m.group(1).strip() if m else None
            last=aamva('DCS');first=aamva('DAC') or aamva('DCT');middle=aamva('DAD');dob=aamva('DBB')
            if first or last:data['patient_name']=' '.join(x for x in [first,middle,last] if x)
            if dob:
                digits=re.sub(r'\D','',dob)
                if len(digits)==8:
                    try:
                        first4=int(digits[:4]);current=utcnow().year
                        if 1900<=first4<=current:
                            yyyy,mm,dd=digits[:4],digits[4:6],digits[6:8]
                        else:
                            mm,dd,yyyy=digits[:2],digits[2:4],digits[4:8]
                        parsed=datetime.strptime(f'{yyyy}-{mm}-{dd}','%Y-%m-%d').date()
                        data['patient_dob']=parsed.isoformat()
                    except Exception:pass
            data['patient_address']=aamva('DAG');data['patient_city']=aamva('DAI');data['patient_state']=aamva('DAJ');data['patient_zip']=aamva('DAK')
            sex=aamva('DBC')
            if sex:data['patient_sex']='Male' if sex.strip()=='1' else ('Female' if sex.strip()=='2' else '')
            # Visual OCR fallback for front-side license photos.
            if 'patient_name' not in data:
                candidates=[x for x in lines if re.fullmatch(r'[A-Z][A-Z ,.-]{4,}',x)]
                if candidates:data['patient_name']=candidates[0].title()
            data['license_number']=aamva('DAQ')
        else:
            # Insurance cards vary widely: extract likely payer/member/group values for confirmation.
            for line in lines:
                low=line.lower()
                if 'member' in low or re.search(r'\bid\b',low):
                    m=re.search(r'(?:member\s*(?:id)?|id)\s*[:#]?\s*([A-Z0-9-]{4,})',line,re.I)
                    if m and 'insurance_member_id' not in data:data['insurance_member_id']=m.group(1)
                if 'group' in low:
                    m=re.search(r'group\s*(?:no|number|#)?\s*[:#]?\s*([A-Z0-9-]{2,})',line,re.I)
                    if m:data['insurance_group_no']=m.group(1)
            if lines:data['payer_name']=lines[0][:120]
        if ocr_error and barcode_text:
            data['notice']='Driver-license barcode was read successfully. OCR is not installed, so front-side text was not used.'
        return jsonify(data)
    finally:
        try:os.unlink(tmp.name)
        except Exception:pass

@app.route('/admin/branding/logo')
def branding_logo():
    role_required('director','master');b=get_branding();path=b.logo_path if b.logo_path and os.path.exists(b.logo_path) else DEFAULT_LOGO
    return send_file(path,mimetype='image/png')

@app.route('/admin/branding',methods=['GET','POST'])
def branding_settings():
    u=role_required('director','master');b=get_branding()
    if request.method=='POST':
        f=request.files.get('letterhead')
        if f and f.filename:
            if not f.filename.lower().endswith('.docx'):
                flash('Upload a Word .docx letterhead file.','danger');return redirect(url_for('branding_settings'))
            path=os.path.join(BRANDING_DIR,'Complete_Omics_Letterhead.docx');f.save(path)
            try:
                vals=extract_docx_branding(path);b.source_docx=path
                for k in ['logo_path','address1','city_state_zip','clia','npi','website']:
                    if vals.get(k):setattr(b,k,vals[k])
            except Exception as e:flash(f'Letterhead uploaded, but automatic extraction failed: {e}','warning')
        for k in ['lab_name','accreditation','address1','city_state_zip','clia','npi','website']:
            if k in request.form:setattr(b,k,(request.form.get(k) or '').strip() or None)
        b.updated_at=utcnow();db.session.commit();audit('BRANDING_UPDATE','branding_setting',b.id);flash('Report branding updated.','success');return redirect(url_for('branding_settings'))
    return render_template('branding.html',u=u,b=b)

@app.route('/instrument-import',methods=['GET','POST'])
def instrument_import():
    role_required('staff','director');u=current_user();preview=[]
    if request.method=='POST':
        f=request.files.get('file')
        if not f or not f.filename:
            flash('Choose a CSV or XLSX file.','danger');return redirect(url_for('instrument_import'))
        try:
            if f.filename.lower().endswith('.csv'):
                records=list(csv.DictReader(io.StringIO(f.stream.read().decode('utf-8-sig'))))
            else:
                from openpyxl import load_workbook
                book=load_workbook(f.stream,data_only=True,read_only=True);ws=book.active;raw=list(ws.iter_rows(values_only=True));heads=[str(x).strip() for x in raw[0]];records=[dict(zip(heads,row)) for row in raw[1:] if any(v is not None for v in row)]
            updated=0;errors=[];touched=set()
            for rec in records:
                accession=str(rec.get('accession_no') or rec.get('Accession') or '').strip();code=str(rec.get('test_code') or rec.get('Test Code') or '').strip();result=rec.get('result') if rec.get('result') is not None else rec.get('Result')
                o=Order.query.filter_by(accession_no=accession).first();t=Test.query.filter_by(code=code).first()
                if not o or not t: errors.append(f'{accession}/{code}');continue
                ot=OrderTest.query.filter_by(order_id=o.id,test_id=t.id).first()
                if not ot: errors.append(f'{accession}/{code} not ordered');continue
                val=str(result).strip();flag=''
                try: flag=apply_reference(o,t,ot,float(val))
                except Exception: pass
                ot.result=val;ot.result_flag=flag;ot.result_status='Imported';ot.entered_by=u.id;ot.entered_at=utcnow();updated+=1;touched.add(o.id)
            for oid in touched:
                o=db.session.get(Order,oid);run_calculations(o,u.id);o.status='Review'
            db.session.commit();audit('IMPORT','instrument_results',None,f'updated={updated}; errors={len(errors)}')
            flash(f'Imported {updated} result(s).'+(f' {len(errors)} row(s) could not be matched.' if errors else ''),'success')
        except Exception as e:
            db.session.rollback();flash(f'Instrument import failed: {e}','danger')
        return redirect(url_for('instrument_import'))
    return render_template('instrument_import.html',u=u)

@app.route('/instrument-import/template.csv')
def instrument_import_template():
    role_required('staff','director')
    return Response('accession_no,test_code,result\nCO-260921-00001,TSH,2.10\n',mimetype='text/csv',headers={'Content-Disposition':'attachment;filename=instrument_result_import_template.csv'})

@app.route('/api/fhir/diagnostic-report/<int:order_id>')
def fhir_diagnostic_report(order_id):
    role_required('staff','director')
    o=db.session.get(Order,order_id) or abort(404)
    contained=[]
    result_refs=[]
    for ot in OrderTest.query.filter_by(order_id=o.id).all():
        t=db.session.get(Test,ot.test_id)
        obs_id=f'obs-{ot.id}'
        ref_text=ot.ref_text_used or f'{ot.ref_low_used if ot.ref_low_used is not None else ""}-{ot.ref_high_used if ot.ref_high_used is not None else ""} {ot.ref_unit_used or t.unit or ""}'
        obs={
            'resourceType':'Observation',
            'id':obs_id,
            'status':'final' if o.status=='Released' else 'preliminary',
            'code':{'text':t.name,'coding':fhir_test_codings(t)},
            'subject':{'display':o.patient_name},
            'valueString':ot.result or '',
            'referenceRange':[{'text':ref_text}] if ref_text.strip() else []
        }
        if ot.result_flag:
            obs['interpretation']=[{'text':ot.result_flag}]
        contained.append(obs)
        result_refs.append({'reference':f'#{obs_id}','display':t.name})
    return {
        'resourceType':'DiagnosticReport',
        'id':str(o.id),
        'status':'final' if o.status=='Released' else 'preliminary',
        'code':{'text':'Complete Omics Laboratory Report'},
        'subject':{'display':o.patient_name},
        'identifier':[{'system':'urn:complete-omics:accession','value':o.accession_no or o.order_no}],
        'contained':contained,
        'result':result_refs
    }

@app.route('/api/hl7/oru/<int:order_id>')
def hl7_oru(order_id):
    """Generate an HL7 v2.5.1 ORU^R01.

    OBX-3 carries Complete Omics local coding and, for LOINC mappings marked READY,
    the approved LOINC alternate code with coding system LN. If exactly one test is
    ordered, OBR-4 uses the same dual-coded identifier; otherwise OBR-4 remains a
    Complete Omics local laboratory-report/panel code.
    """
    role_required('staff','director')
    o=db.session.get(Order,order_id) or abort(404)
    order_tests=OrderTest.query.filter_by(order_id=o.id).all()
    ts=utcnow().strftime('%Y%m%d%H%M%S')
    control_id=f'CO-{o.id}-{ts}'
    obr4='COMPLETEOMICS^Laboratory Report^99COI'
    if len(order_tests)==1:
        single_test=db.session.get(Test,order_tests[0].test_id)
        if single_test:
            obr4=hl7_test_cwe(single_test)
    patient_name=hl7_escape(o.patient_name or '')
    mrn=hl7_escape(o.patient_mrn or '')
    accession=hl7_escape(o.accession_no or o.order_no or '')
    lines=[
        f'MSH|^~\\&|LABOS|COMPLETEOMICS|||{ts}||ORU^R01|{control_id}|P|2.5.1',
        f'PID|||{mrn}||{patient_name}||{(o.patient_dob or "").replace("-","")}|{(o.patient_sex or "")[:1].upper()}',
        f'OBR|1|||{obr4}||||||||||||||{accession}'
    ]
    for i,ot in enumerate(order_tests,1):
        t=db.session.get(Test,ot.test_id)
        if not t:
            continue
        ref=ot.ref_text_used or f'{ot.ref_low_used if ot.ref_low_used is not None else ""}-{ot.ref_high_used if ot.ref_high_used is not None else ""}'
        value=hl7_escape(ot.result or '')
        unit=hl7_escape(ot.ref_unit_used or t.unit or '')
        ref=hl7_escape(ref)
        flag=hl7_escape(ot.result_flag or '')
        obx3=hl7_test_cwe(t)
        lines.append(f'OBX|{i}|ST|{obx3}||{value}|{unit}|{ref}|{flag}|||F')
    audit('HL7_ORU_EXPORT','order',o.id,f'ORU^R01 v2.5.1; tests={len(order_tests)}; LOINC alternate coding applied when READY')
    return Response('\r'.join(lines)+'\r',mimetype='text/plain; charset=utf-8')

@app.route('/compliance',methods=['GET','POST'])
def compliance_center():
    u=role_required('director','master')
    if request.method=='POST':
        action=request.form.get('action')
        if action=='add_record':
            rec=ComplianceRecord(record_type=(request.form.get('record_type') or 'Assessment')[:60], title=(request.form.get('title') or '').strip(), owner=(request.form.get('owner') or '').strip(), status=(request.form.get('status') or 'Open')[:60], due_date=request.form.get('due_date'), completed_date=request.form.get('completed_date'), severity=(request.form.get('severity') or '')[:30], evidence_ref=(request.form.get('evidence_ref') or '').strip(), notes=(request.form.get('notes') or '').strip(), created_by=u.id, updated_at=utcnow())
            if not rec.title: flash('Title is required.','danger')
            else:
                db.session.add(rec); db.session.commit(); audit('COMPLIANCE_RECORD_CREATE','compliance_record',rec.id,f'{rec.record_type}: {rec.title}'); flash('Compliance record added.','success')
        elif action=='settings':
            for key in ('security_officer','privacy_officer','risk_analysis_date','risk_review_due','incident_contact','baa_review_date','backup_test_date','vulnerability_scan_date'):
                set_compliance_setting(key,request.form.get(key,''),u.id)
            audit('COMPLIANCE_SETTINGS_UPDATE','compliance_setting',None,'Security/compliance profile updated'); flash('Compliance profile updated.','success')
        return redirect(url_for('compliance_center'))
    ok,count,bad=audit_chain_status()
    privileged=User.query.filter(User.active==True,User.role.in_(['director','master'])).all()
    mfa_pct=round((sum(1 for x in privileged if x.mfa_enabled)/len(privileged)*100),1) if privileged else 100.0
    posture={
        'https_configured': bool(app.config.get('PUBLIC_BASE_URL','').lower().startswith('https://')),
        'secure_cookie': bool(app.config.get('SESSION_COOKIE_SECURE')),
        'privileged_mfa_pct': mfa_pct,
        'audit_chain_ok': ok, 'audit_rows':count, 'audit_bad_id':bad,
        'idle_timeout':app.config['IDLE_TIMEOUT_MINUTES'], 'lockout_limit':app.config['LOGIN_FAILURE_LIMIT'],
        'audit_retention_years':app.config['AUDIT_RETENTION_YEARS']
    }
    settings={k:compliance_setting(k,'') for k in ('security_officer','privacy_officer','risk_analysis_date','risk_review_due','incident_contact','baa_review_date','backup_test_date','vulnerability_scan_date')}
    records=ComplianceRecord.query.order_by(ComplianceRecord.id.desc()).limit(250).all()
    counts={x:ComplianceRecord.query.filter_by(record_type=x).count() for x in ('Risk','Incident','Vendor/BAA','Training','Policy','Assessment')}
    return render_template('compliance.html',u=u,posture=posture,settings=settings,records=records,counts=counts)

@app.route('/compliance/record/<int:record_id>/status',methods=['POST'])
def compliance_record_status(record_id):
    u=role_required('director','master'); rec=db.session.get(ComplianceRecord,record_id) or abort(404)
    rec.status=(request.form.get('status') or rec.status)[:60]; rec.completed_date=request.form.get('completed_date') or rec.completed_date; rec.updated_at=utcnow(); db.session.commit(); audit('COMPLIANCE_RECORD_UPDATE','compliance_record',rec.id,f'status={rec.status}'); return redirect(url_for('compliance_center'))

@app.route('/interoperability',methods=['GET','POST'])
def interoperability_center():
    u=role_required('director','master')
    if request.method=='POST':
        action=request.form.get('action')
        if action=='settings':
            for key in ('dxf_participant_status','dsa_signed_date','qhio_name','qhio_contact','participant_directory_status','national_network','hitrust_status','hitrust_expiry','data_residency','privacy_policy_review_date','person_matching_status','adt_status','fhir_endpoint'):
                set_compliance_setting(key,request.form.get(key,''),u.id)
            audit('DXF_PROFILE_UPDATE','compliance_setting',None,'DxF/QHIO readiness profile updated'); flash('DxF/QHIO profile updated.','success')
        elif action=='transaction':
            tx=ExchangeTransaction(transaction_id=(request.form.get('transaction_id') or secrets.token_hex(12)).strip(),direction=request.form.get('direction','Outbound'),framework=request.form.get('framework'),message_type=request.form.get('message_type'),counterparty=request.form.get('counterparty'),patient_reference=request.form.get('patient_reference'),status=request.form.get('status','Logged'),details=request.form.get('details'),created_by=u.id)
            db.session.add(tx); db.session.commit(); audit('EXCHANGE_TRANSACTION_LOG','exchange_transaction',tx.id,f'{tx.framework}; {tx.message_type}; {tx.status}'); flash('Exchange transaction logged.','success')
        return redirect(url_for('interoperability_center'))
    keys=('dxf_participant_status','dsa_signed_date','qhio_name','qhio_contact','participant_directory_status','national_network','hitrust_status','hitrust_expiry','data_residency','privacy_policy_review_date','person_matching_status','adt_status','fhir_endpoint')
    settings={k:compliance_setting(k,'') for k in keys}
    txs=ExchangeTransaction.query.order_by(ExchangeTransaction.id.desc()).limit(200).all()
    return render_template('interoperability.html',u=u,settings=settings,transactions=txs)

@app.route('/audit/export.csv')
def audit_export():
    role_required('director','master'); output=io.StringIO(); w=csv.writer(output)
    w.writerow(['ID','UTC Time','User ID','Action','Entity','Entity ID','Details','Previous Hash','Record Hash'])
    for a in Audit.query.order_by(Audit.id.asc()).all(): w.writerow([a.id,a.created_at,a.user_id,a.action,a.entity,a.entity_id,a.details,a.prev_hash,a.record_hash])
    audit('AUDIT_EXPORT','audit',None,'Audit CSV exported')
    return Response(output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment;filename=labos_audit_export.csv'})

@app.route('/audit/verify')
def audit_verify():
    role_required('director','master'); ok,count,bad=audit_chain_status(); audit('AUDIT_CHAIN_VERIFY','audit',None,f'ok={ok}; rows={count}; first_bad={bad}')
    flash((f'Audit hash chain verified across {count} records.' if ok else f'Audit hash chain verification failed near record {bad}.'), 'success' if ok else 'danger')
    return redirect(url_for('audit_log'))

@app.route('/audit')
def audit_log():
    role_required('director');u=current_user()
    rows=Audit.query.order_by(Audit.id.desc()).limit(500).all()
    users={x.id:x for x in User.query.all()}
    return render_template('audit.html',u=u,rows=rows,users=users)

@app.route('/export/orders.csv')
def export_orders():
    r=require_login()
    if r:return r
    u=current_user();rows=provider_order_query(u).order_by(Order.id).all()
    output=io.StringIO();w=csv.writer(output);w.writerow(['Order No','Accession','Patient','DOB','Sex','MRN','Provider','Requester','Organization','Payment Type','Payer','Billing Status','Status','Created','Received'])
    for x in rows:w.writerow([x.order_no,x.accession_no,x.patient_name,x.patient_dob,x.patient_sex,x.patient_mrn,x.provider_name,x.requester_email,x.requester_organization,x.payment_type,x.payer_name,x.billing_status,x.status,fmt_dt(x.created_at),fmt_dt(x.sample_received_at)])
    return Response(output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment;filename=orders.csv'})


def make_requisition_pdf(o,tests):
    bio=io.BytesIO();c=canvas.Canvas(bio,pagesize=letter);W,H=letter;b=get_branding();y=draw_letterhead(c,b,W,H)
    c.setFont('Helvetica-Bold',15);c.drawString(.6*inch,y,'Laboratory Test Requisition');y-=.3*inch
    items=[('Order',o.order_no),('Confirmation',o.confirmation_code),('Patient',o.patient_name),('DOB',o.patient_dob or ''),('Sex',o.patient_sex or ''),('MRN / Patient ID',o.patient_mrn or ''),('Ordering provider',o.provider_name or ''),('Organization',o.requester_organization or ''),('Submitted',fmt_dt(o.created_at))]
    for k,v in items:
        c.setFont('Helvetica-Bold',8.5);c.drawString(.6*inch,y,k+':');c.setFont('Helvetica',8.5);c.drawString(1.85*inch,y,str(v)[:92]);y-=.18*inch
    y-=.06*inch;c.line(.6*inch,y,7.9*inch,y);y-=.24*inch;c.setFont('Helvetica-Bold',9.5);c.drawString(.6*inch,y,'Clinical information');y-=.2*inch;c.setFont('Helvetica',8.3)
    clin=[f'BP: {o.systolic_bp or ""}/{o.diastolic_bp or ""} mmHg',f'Weight: {o.weight_lb or ""} lb',f'Height: {o.height_in or ""} in',f'BMI: {o.bmi if o.bmi is not None else ""}',f'Stent: {o.stent_history or "Not documented"} {o.stent_date or ""}',f'CABG: {o.cabg_history or "Not documented"} {o.cabg_date or ""}']
    c.drawString(.7*inch,y,'   |   '.join(clin[:4]));y-=.18*inch;c.drawString(.7*inch,y,'   |   '.join(clin[4:]));y-=.26*inch
    c.setFont('Helvetica-Bold',9.5);c.drawString(.6*inch,y,'Requested tests');y-=.2*inch;c.setFont('Helvetica',8.5)
    for t in tests:
        if y<.85*inch:c.showPage();y=draw_letterhead(c,b,W,H)
        c.drawString(.8*inch,y,f'- {t.name} ({t.specimen or "specimen not configured"}) - {t.method or "method not configured"}');y-=.18*inch
    c.save();bio.seek(0);return send_file(bio,mimetype='application/pdf',as_attachment=True,download_name=f'{o.order_no}_requisition.pdf')

@app.route('/orders/<int:order_id>/report.pdf')
def report_pdf(order_id):
    r=require_login()
    if r:return r
    u=current_user();o=db.session.get(Order,order_id) or abort(404)
    if u.role=='customer' and (not ((u.clinic_id and o.clinic_id==u.clinic_id) or (not u.clinic_id and o.customer_user_id==u.id)) or o.status!='Released'):abort(403)
    rows=[(ot,db.session.get(Test,ot.test_id)) for ot in OrderTest.query.filter_by(order_id=o.id).all()]
    bio=io.BytesIO();c=canvas.Canvas(bio,pagesize=letter);W,H=letter;b=get_branding();y=draw_letterhead(c,b,W,H)
    c.setFont('Helvetica-Bold',15);c.drawString(.6*inch,y,'Laboratory Report');c.setFont('Helvetica',8);c.drawRightString(7.9*inch,y,'Final report' if o.status=='Released' else 'Preliminary');y-=.28*inch
    c.setFont('Helvetica-Bold',9);c.drawString(.6*inch,y,f'Patient: {o.patient_name}');c.drawString(4.15*inch,y,f'Order: {o.order_no}');y-=.18*inch
    c.setFont('Helvetica',8.3);c.drawString(.6*inch,y,f'DOB: {o.patient_dob or ""}    Sex: {o.patient_sex or ""}    MRN: {o.patient_mrn or ""}');c.drawString(4.15*inch,y,f'Accession: {o.accession_no or ""}');y-=.18*inch
    c.drawString(.6*inch,y,f'Provider: {o.provider_name or ""}');c.drawString(4.15*inch,y,f'Received: {fmt_dt(o.sample_received_at)}');y-=.22*inch
    # clinical data strip
    c.setFont('Helvetica-Bold',8);c.drawString(.6*inch,y,'Clinical data:');c.setFont('Helvetica',8)
    vals=[]
    if o.systolic_bp or o.diastolic_bp:vals.append(f'BP {o.systolic_bp or ""}/{o.diastolic_bp or ""} mmHg')
    if o.weight_lb:vals.append(f'Weight {o.weight_lb:g} lb')
    if o.bmi is not None:vals.append(f'BMI {o.bmi:.1f}')
    if o.stent_history:vals.append(f'Stent {o.stent_history} {o.stent_date or ""}')
    if o.cabg_history:vals.append(f'CABG {o.cabg_history} {o.cabg_date or ""}')
    if o.egfr_ckd_epi_2021 is not None:vals.append(f'eGFR {o.egfr_ckd_epi_2021:.1f} mL/min/1.73 m2')
    c.drawString(1.45*inch,y,' | '.join(vals)[:115] if vals else 'Not provided');y-=.24*inch
    c.line(.6*inch,y,7.9*inch,y);y-=.22*inch;c.setFont('Helvetica-Bold',8.2);c.drawString(.6*inch,y,'Test');c.drawString(3.15*inch,y,'Result');c.drawString(4.35*inch,y,'Reference Interval');c.drawString(6.1*inch,y,'Method');y-=.18*inch
    c.setFont('Helvetica',8.2)
    for ot,t in rows:
        if y<1.05*inch:
            c.showPage();y=draw_letterhead(c,b,W,H);c.setFont('Helvetica-Bold',8.2);c.drawString(.6*inch,y,'Test');c.drawString(3.15*inch,y,'Result');c.drawString(4.35*inch,y,'Reference Interval');c.drawString(6.1*inch,y,'Method');y-=.18*inch;c.setFont('Helvetica',8.2)
        ref=ot.ref_text_used or ''
        if not ref and (ot.ref_low_used is not None or ot.ref_high_used is not None):ref=f'{ot.ref_low_used if ot.ref_low_used is not None else ""}-{ot.ref_high_used if ot.ref_high_used is not None else ""} {ot.ref_unit_used or t.unit or ""}'
        if not ref and (t.ref_low is not None or t.ref_high is not None):ref=f'{t.ref_low if t.ref_low is not None else ""}-{t.ref_high if t.ref_high is not None else ""} {t.unit or ""}'
        tox_text=toxicology_report_text(t.code,ot.result,ot.result_flag);res=((tox_text if tox_text is not None else (ot.result or ''))+((' '+ot.result_flag) if ot.result_flag and ot.result_flag not in ('NEG','POS') else '')+((' '+t.unit) if t.unit and (tox_text is None or tox_text!='Negative') else ''))
        c.drawString(.6*inch,y,t.name[:38]);c.drawString(3.15*inch,y,res[:25]);c.drawString(4.35*inch,y,ref[:29]);c.drawString(6.1*inch,y,(t.method or '')[:28]);y-=.19*inch
    if o.serum_creatinine_mg_dl is not None and o.egfr_ckd_epi_2021 is not None:
        y-=.08*inch;c.setFont('Helvetica-Bold',8);c.drawString(.6*inch,y,'Calculated eGFR (CKD-EPI 2021, race-free):');c.setFont('Helvetica',8);c.drawString(3.25*inch,y,f'{o.egfr_ckd_epi_2021:.1f} mL/min/1.73 m2 from creatinine {o.serum_creatinine_mg_dl:g} mg/dL. Adult equation; age and sex required.');y-=.18*inch
    comment=toxicology_specimen_comment(o)
    if comment:
        c.setFont('Helvetica-Bold',8);c.drawString(.6*inch,y,'Toxicology comment:');y-=.16*inch;c.setFont('Helvetica',8);c.drawString(.75*inch,y,comment[:110]);y-=.18*inch
    c.line(.6*inch,y,7.9*inch,y);y-=.2*inch;c.setFont('Helvetica',7.5);c.drawString(.6*inch,y,f'Status: {o.status}   Generated: {fmt_dt(utcnow())}.')
    c.save();bio.seek(0);return send_file(bio,mimetype='application/pdf',as_attachment=True,download_name=f'{o.order_no}_report.pdf')


def policy_enabled(code):
    p=QCPolicy.query.filter_by(code=code).first()
    return bool(p and p.enabled)

def westgard_flag(value, mean, sd, history=None):
    """Configurable QC helper. History is newest-first QCResult rows for the same control."""
    if sd is None or sd <= 0:
        return 0.0, 'NO_SD', 'Review'
    z=(value-mean)/sd
    hist=[h.z_score for h in (history or []) if h.z_score is not None]
    seq=[z]+hist
    flags=[]; reject=False; warning=False
    if policy_enabled('WG_13S') and abs(z) >= 3:
        flags.append('1_3s'); reject=True
    if policy_enabled('WG_22S') and len(seq)>=2 and all(abs(x)>=2 for x in seq[:2]) and seq[0]*seq[1]>0:
        flags.append('2_2s'); reject=True
    if policy_enabled('WG_R4S') and len(seq)>=2 and seq[0]*seq[1]<0 and abs(seq[0]-seq[1])>=4:
        flags.append('R_4s'); reject=True
    if policy_enabled('WG_41S') and len(seq)>=4:
        q=seq[:4]
        if all(x>1 for x in q) or all(x<-1 for x in q): flags.append('4_1s'); reject=True
    if policy_enabled('WG_10X') and len(seq)>=10:
        q=seq[:10]
        if all(x>0 for x in q) or all(x<0 for x in q): flags.append('10x'); reject=True
    if not reject and policy_enabled('WG_12S') and abs(z)>=2:
        flags.append('1_2s'); warning=True
    status='Reject' if reject else ('Warning' if warning else 'Accept')
    return round(z,3), ', '.join(flags) if flags else 'Within limits', status

def previous_patient_numeric_result(order, test_id):
    if not order.patient_mrn: return None
    prior=(db.session.query(OrderTest,Order)
           .join(Order,Order.id==OrderTest.order_id)
           .filter(Order.patient_mrn==order.patient_mrn,Order.status=='Released',Order.id!=order.id,OrderTest.test_id==test_id)
           .order_by(Order.id.desc()).first())
    if not prior: return None
    try:return float(prior[0].result)
    except (TypeError,ValueError):return None

def autoverification_checks(order, test, order_test, numeric_value):
    checks=[]; hold=False
    if policy_enabled('CRITICAL') and order_test.result_flag in ('CL','CH'):
        checks.append({'check':'Critical value','status':'HOLD','detail':order_test.result_flag}); hold=True
    if policy_enabled('QC_BLOCK'):
        qd=QCDefinition.query.filter_by(test_id=test.id,active=True).first()
        if qd:
            qr=QCResult.query.filter_by(qc_definition_id=qd.id).order_by(QCResult.id.desc()).first()
            if qr and qr.status=='Reject': checks.append({'check':'Latest QC','status':'HOLD','detail':qr.rule_flag}); hold=True
            elif qr: checks.append({'check':'Latest QC','status':'PASS','detail':qr.status})
            else: checks.append({'check':'Latest QC','status':'REVIEW','detail':'No QC result recorded'})
    if policy_enabled('DELTA'):
        p=QCPolicy.query.filter_by(code='DELTA').first(); threshold=50.0
        try: threshold=float((json.loads(p.config_json or '{}')).get('percent',50))
        except Exception: pass
        prev=previous_patient_numeric_result(order,test.id)
        if prev is not None and prev != 0:
            delta=abs((numeric_value-prev)/prev)*100
            if delta>threshold: checks.append({'check':'Delta check','status':'HOLD','detail':f'{delta:.1f}% > {threshold:.1f}%'}); hold=True
            else: checks.append({'check':'Delta check','status':'PASS','detail':f'{delta:.1f}%'} )
    return ('Hold' if hold else 'Pass'), checks


@app.route('/samples')
def samples():
    role_required('staff','director');u=current_user()
    rows=Sample.query.order_by(Sample.id.desc()).all()
    orders_map={o.id:o for o in Order.query.all()}
    return render_template('samples.html',u=u,samples=rows,orders_map=orders_map)

@app.route('/samples/<int:sample_id>/label.pdf')
def sample_label(sample_id):
    role_required('staff','director');samp=db.session.get(Sample,sample_id) or abort(404);o=db.session.get(Order,samp.order_id)
    bio=io.BytesIO();c=canvas.Canvas(bio,pagesize=(4*inch,2*inch))
    c.setFont('Helvetica-Bold',10);c.drawString(.2*inch,1.7*inch,'Complete Omics Inc.')
    c.setFont('Helvetica',8);c.drawString(.2*inch,1.48*inch,f'Sample: {samp.sample_no}')
    c.drawString(.2*inch,1.28*inch,f'Patient: {o.patient_name[:28]}')
    c.drawString(.2*inch,1.08*inch,f'Accession: {o.accession_no or "Pending"}')
    barcode=code128.Code128(samp.sample_no,barHeight=.45*inch,barWidth=.65)
    barcode.drawOn(c,.2*inch,.25*inch)
    c.save();bio.seek(0)
    return send_file(bio,mimetype='application/pdf',as_attachment=True,download_name=f'{samp.sample_no}_barcode.pdf')

@app.route('/batches',methods=['GET','POST'])
def batches():
    role_required('staff','director');u=current_user()
    if request.method=='POST':
        b=Batch(batch_no='B-'+utcnow().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(1).upper(),name=request.form['name'].strip(),method=request.form.get('method'),instrument=request.form.get('instrument'),created_by=u.id,notes=request.form.get('notes'))
        db.session.add(b);db.session.commit();audit('CREATE','batch',b.id,b.batch_no);return redirect(url_for('batch_detail',batch_id=b.id))
    return render_template('batches.html',u=u,batches=Batch.query.order_by(Batch.id.desc()).all())

@app.route('/batches/<int:batch_id>',methods=['GET','POST'])
def batch_detail(batch_id):
    role_required('staff','director');u=current_user();b=db.session.get(Batch,batch_id) or abort(404)
    if request.method=='POST':
        action=request.form.get('action')
        if action=='delete_batch':
            linked = {
                'samples': BatchSample.query.filter_by(batch_id=b.id).count(),
                'worksheets': Worksheet.query.filter_by(batch_id=b.id).count(),
                'plates': PlateMap.query.filter_by(batch_id=b.id).count(),
                'qc': QCResult.query.filter_by(batch_id=b.id).count(),
                'tox_reviews': ToxicologyBatchReview.query.filter_by(batch_id=b.id).count(),
            }
            if b.status != 'Open' or any(linked.values()):
                flash('This batch cannot be deleted because laboratory work is already attached to it. Remove a mistaken batch before samples, worksheets, QC, plates, or run review are added.','danger')
                return redirect(url_for('batch_detail',batch_id=b.id))
            batch_id_value=b.id; batch_no_value=b.batch_no
            audit('DELETE_DRAFT','batch',batch_id_value,f'{batch_no_value}; created in error',user_id=u.id)
            db.session.delete(b); db.session.commit()
            flash(f'Batch {batch_no_value} was deleted because it had no laboratory work attached.','success')
            return redirect(url_for('batches'))
        if action=='add_sample':
            sid=int(request.form['sample_id'])
            if not BatchSample.query.filter_by(batch_id=b.id,sample_id=sid).first(): db.session.add(BatchSample(batch_id=b.id,sample_id=sid,position=request.form.get('position')))
        elif action=='status':
            b.status=request.form.get('status','Open'); b.run_at=utcnow() if b.status=='Completed' else b.run_at
        db.session.commit();audit('UPDATE','batch',b.id,action);return redirect(url_for('batch_detail',batch_id=b.id))
    links=BatchSample.query.filter_by(batch_id=b.id).all();assigned=[]
    for x in links:
        samp=db.session.get(Sample,x.sample_id);assigned.append((x,samp,db.session.get(Order,samp.order_id) if samp else None))
    available=Sample.query.order_by(Sample.id.desc()).all()
    return render_template('batch_detail.html',u=u,batch=b,assigned=assigned,available=available)

@app.route('/worksheets',methods=['GET','POST'])
def worksheets():
    role_required('staff','director');u=current_user()
    if request.method=='POST':
        w=Worksheet(title=request.form['title'].strip(),batch_id=int(request.form['batch_id']) if request.form.get('batch_id') else None,created_by=u.id,notes=request.form.get('notes'))
        db.session.add(w);db.session.commit();audit('CREATE','worksheet',w.id,w.title);return redirect(url_for('worksheet_detail',worksheet_id=w.id))
    return render_template('worksheets.html',u=u,worksheets=Worksheet.query.order_by(Worksheet.id.desc()).all(),batches=Batch.query.order_by(Batch.id.desc()).all())

@app.route('/worksheets/<int:worksheet_id>',methods=['GET','POST'])
def worksheet_detail(worksheet_id):
    role_required('staff','director');u=current_user();w=db.session.get(Worksheet,worksheet_id) or abort(404)
    if request.method=='POST':
        action=request.form.get('action')
        if action=='delete_worksheet':
            if w.status != 'Draft':
                flash('Only a Draft worksheet can be deleted. Approved worksheets remain part of the laboratory record.','danger')
                return redirect(url_for('worksheet_detail',worksheet_id=w.id))
            worksheet_id_value=w.id; title_value=w.title
            WorksheetEntry.query.filter_by(worksheet_id=w.id).delete(synchronize_session=False)
            audit('DELETE_DRAFT','worksheet',worksheet_id_value,f'{title_value}; created in error',user_id=u.id)
            db.session.delete(w); db.session.commit()
            flash(f'Worksheet “{title_value}” was deleted.','success')
            return redirect(url_for('worksheets'))
        if action=='add_entry': db.session.add(WorksheetEntry(worksheet_id=w.id,row_label=request.form['row_label'],value=request.form.get('value'),unit=request.form.get('unit'),entered_by=u.id,entered_at=utcnow()))
        elif action=='approve' and is_director(u): w.status='Approved';w.approved_by=u.id;w.approved_at=utcnow()
        db.session.commit();audit('UPDATE','worksheet',w.id,action);return redirect(url_for('worksheet_detail',worksheet_id=w.id))
    return render_template('worksheet_detail.html',u=u,worksheet=w,entries=WorksheetEntry.query.filter_by(worksheet_id=w.id).all())

@app.route('/plates',methods=['GET','POST'])
def plates():
    role_required('staff','director');u=current_user()
    if request.method=='POST':
        p=PlateMap(name=request.form['name'].strip(),batch_id=int(request.form['batch_id']) if request.form.get('batch_id') else None,plate_format=96,created_by=u.id)
        db.session.add(p);db.session.commit();audit('CREATE','plate_map',p.id,p.name);return redirect(url_for('plate_detail',plate_id=p.id))
    return render_template('plates.html',u=u,plates=PlateMap.query.order_by(PlateMap.id.desc()).all(),batches=Batch.query.order_by(Batch.id.desc()).all())

@app.route('/plates/<int:plate_id>',methods=['GET','POST'])
def plate_detail(plate_id):
    role_required('staff','director');u=current_user();p=db.session.get(PlateMap,plate_id) or abort(404)
    rows='ABCDEFGH'; cols=range(1,13)
    if request.method=='POST':
        well=(request.form.get('well') or '').strip().upper()
        if not re.fullmatch(r'[A-H](?:[1-9]|1[0-2])',well): abort(400)
        pw=PlateWell.query.filter_by(plate_id=p.id,well=well).first()
        if request.form.get('action')=='erase':
            if pw:
                deleted_id=pw.id;db.session.delete(pw);db.session.commit();audit('ERASE','plate_well',deleted_id,f'plate={p.id}; well={well}')
            flash(f'{well} cleared.','success')
        else:
            sample_id=request.form.get('sample_id')
            if sample_id and not db.session.get(Sample,int(sample_id)): abort(400)
            if not pw: pw=PlateWell(plate_id=p.id,well=well);db.session.add(pw)
            pw.well_type=request.form.get('well_type','Sample');pw.label=(request.form.get('label') or '').strip()[:160]
            pw.concentration=(request.form.get('concentration') or '').strip()[:80]
            pw.sample_id=int(sample_id) if sample_id else None
            db.session.commit();audit('UPDATE','plate_well',pw.id,f'plate={p.id}; well={well}')
            flash(f'{well} saved.','success')
        return redirect(url_for('plate_detail',plate_id=p.id,well=well))
    wells={x.well:x for x in PlateWell.query.filter_by(plate_id=p.id).all()}
    well_data={k:{'type':v.well_type,'sample_id':v.sample_id,'label':v.label,'concentration':v.concentration} for k,v in wells.items()}
    selected_well=request.args.get('well','A1')
    if not re.fullmatch(r'[A-H](?:[1-9]|1[0-2])',selected_well): selected_well='A1'
    return render_template('plate_detail.html',u=u,plate=p,rows=rows,cols=cols,wells=wells,well_data=well_data,selected_well=selected_well,samples=Sample.query.order_by(Sample.id.desc()).limit(200).all())

@app.route('/qc',methods=['GET','POST'])
def qc():
    role_required('staff','director');u=current_user()
    if request.method=='POST':
        action=request.form.get('action')
        if action=='definition' and is_director(u):
            q=QCDefinition(name=request.form['name'],test_id=int(request.form['test_id']),level=request.form['level'],target_mean=float(request.form['target_mean']),target_sd=float(request.form['target_sd']),lot=request.form.get('lot'))
            db.session.add(q);db.session.commit();audit('CREATE','qc_definition',q.id,q.name)
        elif action=='result':
            qd=db.session.get(QCDefinition,int(request.form['qc_definition_id'])) or abort(404);value=float(request.form['value'])
            history=QCResult.query.filter_by(qc_definition_id=qd.id).order_by(QCResult.id.desc()).limit(12).all()
            z,flag,status=westgard_flag(value,qd.target_mean,qd.target_sd,history)
            qr=QCResult(qc_definition_id=qd.id,batch_id=int(request.form['batch_id']) if request.form.get('batch_id') else None,value=value,z_score=z,rule_flag=flag,status=status,entered_by=u.id)
            db.session.add(qr);db.session.commit();audit('CREATE','qc_result',qr.id,f'{flag}; {status}')
        return redirect(url_for('qc'))
    defs=QCDefinition.query.filter_by(active=True).order_by(QCDefinition.name).all();results=QCResult.query.order_by(QCResult.id.desc()).limit(100).all()
    tests={t.id:t for t in Test.query.all()};defs_map={d.id:d for d in defs}
    return render_template('qc.html',u=u,defs=defs,results=results,tests=tests,defs_map=defs_map,batches=Batch.query.order_by(Batch.id.desc()).limit(50).all())

@app.route('/qc/<int:definition_id>/chart')
def qc_chart(definition_id):
    role_required('staff','director');u=current_user();qd=db.session.get(QCDefinition,definition_id) or abort(404)
    results=QCResult.query.filter_by(qc_definition_id=qd.id).order_by(QCResult.id.asc()).limit(60).all()
    pts=[];n=len(results)
    for i,r in enumerate(results):
        x=60 if n<=1 else 60+i*(820/(n-1)); z=max(-4,min(4,r.z_score or 0)); y=190-z*42
        pts.append((round(x,1),round(y,1),r))
    return render_template('qc_chart.html',u=u,qd=qd,results=results,points=pts)

@app.route('/qc/review/<int:result_id>',methods=['POST'])
def qc_review(result_id):
    role_required('staff','director');u=current_user();qr=db.session.get(QCResult,result_id) or abort(404)
    decision=request.form.get('decision','Reviewed');notes=(request.form.get('notes') or '').strip();ca=(request.form.get('corrective_action') or '').strip()
    rev=QCReview(qc_result_id=qr.id,decision=decision,notes=notes,corrective_action=ca,reviewed_by=u.id)
    db.session.add(rev);db.session.commit();audit('QC_REVIEW','qc_result',qr.id,f'{decision}; {notes}; {ca}')
    flash('QC review recorded.','success');return redirect(url_for('qc'))

@app.route('/quality-policies',methods=['GET','POST'])
def quality_policies():
    role_required('staff','director');u=current_user()
    if request.method=='POST' and is_director(u):
        p=db.session.get(QCPolicy,int(request.form['policy_id'])) or abort(404)
        p.enabled=request.form.get('enabled')=='on';p.severity=request.form.get('severity') or p.severity
        if p.code=='DELTA':
            try:p.config_json=json.dumps({'percent':float(request.form.get('delta_percent') or 50)})
            except ValueError:pass
        db.session.commit();audit('UPDATE','qc_policy',p.id,f'enabled={p.enabled}; severity={p.severity}')
        flash('Quality policy updated.','success');return redirect(url_for('quality_policies'))
    policies=QCPolicy.query.order_by(QCPolicy.code).all()
    for p in policies:
        p.delta_percent=50
        if p.code=='DELTA':
            try:p.delta_percent=float((json.loads(p.config_json or '{}')).get('percent',50))
            except Exception:pass
    return render_template('quality_policies.html',u=u,policies=policies)

@app.route('/qc/lot-comparison',methods=['GET','POST'])
def qc_lot_comparison():
    role_required('staff','director');u=current_user()
    if request.method=='POST':
        old=[float(x.strip()) for x in request.form['old_values'].split(',') if x.strip()]
        new=[float(x.strip()) for x in request.form['new_values'].split(',') if x.strip()]
        pairs=min(len(old),len(new)); old=old[:pairs];new=new[:pairs]
        if pairs<2: flash('Enter at least two paired values for each lot.','danger');return redirect(url_for('qc_lot_comparison'))
        mo=sum(old)/pairs;mn=sum(new)/pairs;bias=((mn-mo)/mo*100) if mo else None;limit=float(request.form.get('acceptance_limit') or 10)
        status='Accept' if bias is not None and abs(bias)<=limit else 'Review'
        rec=QCLotComparison(test_id=int(request.form['test_id']),old_lot=request.form['old_lot'],new_lot=request.form['new_lot'],pairs=pairs,mean_old=mo,mean_new=mn,bias_percent=bias,acceptance_limit=limit,status=status,notes=request.form.get('notes'),created_by=u.id)
        db.session.add(rec);db.session.commit();audit('CREATE','qc_lot_comparison',rec.id,f'bias={bias}; status={status}')
        return redirect(url_for('qc_lot_comparison'))
    return render_template('qc_lot_comparison.html',u=u,tests=Test.query.filter_by(active=True).order_by(Test.name).all(),rows=QCLotComparison.query.order_by(QCLotComparison.id.desc()).limit(50).all())

@app.route('/inventory',methods=['GET','POST'])
def inventory():
    role_required('staff','director');u=current_user()
    if request.method=='POST':
        lot=InventoryLot(item_name=request.form['item_name'],category=request.form.get('category'),supplier=request.form.get('supplier'),catalog_no=request.form.get('catalog_no'),lot_no=request.form.get('lot_no'),quantity=float(request.form.get('quantity') or 0),unit=request.form.get('unit'),received_date=request.form.get('received_date'),expiration_date=request.form.get('expiration_date'),storage_location=request.form.get('storage_location'))
        db.session.add(lot);db.session.commit();audit('CREATE','inventory_lot',lot.id,lot.item_name);return redirect(url_for('inventory'))
    return render_template('inventory.html',u=u,lots=InventoryLot.query.order_by(InventoryLot.id.desc()).all())

@app.route('/calculations',methods=['GET','POST'])
def calculations():
    role_required('staff','director');u=current_user()
    if request.method=='POST' and is_director(u):
        rule=CalculationRule(name=request.form['name'],output_code=request.form['output_code'],expression=request.form['expression'],description=request.form.get('description'))
        db.session.add(rule);db.session.commit();audit('CREATE','calculation_rule',rule.id,rule.output_code);return redirect(url_for('calculations'))
    return render_template('calculations.html',u=u,rules=CalculationRule.query.order_by(CalculationRule.id.desc()).all())

@app.route('/export/inventory.csv')
def export_inventory():
    role_required('staff','director');rows=InventoryLot.query.order_by(InventoryLot.id).all();output=io.StringIO();w=csv.writer(output)
    w.writerow(['Item','Category','Supplier','Catalog','Lot','Quantity','Unit','Received','Expires','Location','Status'])
    for x in rows:w.writerow([x.item_name,x.category,x.supplier,x.catalog_no,x.lot_no,x.quantity,x.unit,x.received_date,x.expiration_date,x.storage_location,x.status])
    return Response(output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment;filename=inventory.csv'})


with app.app_context():
    db.create_all();ensure_v93_user_schema();ensure_v94_multiclinic_schema();ensure_v96_billing_schema();ensure_v100_final_schema();ensure_v110_security_schema();ensure_v114_loinc_schema();seed()

if __name__=='__main__':
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')),debug=os.environ.get('FLASK_DEBUG')=='1')
