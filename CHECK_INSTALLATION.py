import importlib, os, shutil, sys
required = {
    'flask':'Flask',
    'flask_sqlalchemy':'Flask-SQLAlchemy',
    'sqlalchemy':'SQLAlchemy',
    'reportlab':'reportlab',
    'openpyxl':'openpyxl',
    'PIL':'Pillow',
    'pytesseract':'pytesseract',
    'docx':'python-docx',
    'zxingcpp':'zxing-cpp',
    'pyotp':'pyotp',
}
production = {'gunicorn':'gunicorn', 'psycopg':'psycopg'}
failed=[]
print('Complete Omics LabOS 11.1.5 installation check')
print('='*52)
for mod,pkg in required.items():
    try:
        importlib.import_module(mod); print(f'[OK] {pkg}')
    except Exception as e:
        failed.append(pkg); print(f'[MISSING] {pkg}: {e}')
print('\nProduction/cloud components:')
for mod,pkg in production.items():
    try:
        importlib.import_module(mod); print(f'[OK] {pkg}')
    except Exception as e:
        print(f'[INFO] {pkg} not installed in this interpreter: {e}')
print('\nExternal OCR engine:')
print('[OK] Tesseract found at '+shutil.which('tesseract') if shutil.which('tesseract') else '[INFO] Tesseract executable not found in PATH; Windows installer may still locate it in Program Files.')
print('\nProduction environment:')
for k in ['LIS_SECRET_KEY','PUBLIC_BASE_URL','DATABASE_URL','COOKIE_SECURE','REQUIRE_PRIVILEGED_MFA']:
    v=os.getenv(k)
    if k in ('LIS_SECRET_KEY','DATABASE_URL'):
        shown='configured' if v else 'not set'
    else:
        shown=v or 'not set'
    print(f'[{"OK" if v else "INFO"}] {k}: {shown}')
if failed:
    print('\nOne or more required packages are missing. Run the normal START script or:')
    print(f'  {sys.executable} -m pip install -r requirements-local.txt')
    sys.exit(1)
print('\nCore Python dependencies are available.')
