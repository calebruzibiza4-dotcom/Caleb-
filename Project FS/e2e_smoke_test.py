import requests
import time

base = 'http://127.0.0.1:5000'
s = requests.Session()

def create_customer():
    data = {
        'name': 'E2E Test User',
        'email': 'e2e_user@example.com',
        'phone': '0123456789',
        'address': '123 Test Lane',
        'password': 'password123',
        'is_business': ''
    }
    r = s.post(base + '/customers/new', data=data, allow_redirects=True)
    print('POST /customers/new ->', r.status_code)
    return r

def customer_login():
    data = {'email': 'e2e_user@example.com', 'password': 'password123'}
    r = s.post(base + '/customer/login', data=data, allow_redirects=True)
    print('POST /customer/login ->', r.status_code)
    return r

def create_kb():
    data = {'title': 'E2E Article', 'content': 'This is an E2E Article used for testing diagnose. Fix steps: reboot.', 'tags': 'e2e,test'}
    r = s.post(base + '/kb/new', data=data, allow_redirects=True)
    print('POST /kb/new ->', r.status_code)
    return r

def diagnose():
    data = {'symptoms': 'device not booting reboot test'}
    r = s.post(base + '/kb/diagnose', data=data, allow_redirects=True)
    print('POST /kb/diagnose ->', r.status_code)
    if 'E2E Article' in r.text or 'reboot' in r.text:
        print('DIAGNOSE: likely matched article')
    else:
        print('DIAGNOSE: no match found')
    return r

if __name__ == '__main__':
    # Run the sequence and write a deterministic log for inspection
    time.sleep(1)
    log_path = 'e2e_log.txt'
    try:
        with open(log_path, 'w', encoding='utf-8') as lf:
            lf.write('Starting E2E smoke test\n')
            r = create_customer()
            lf.write(f'create_customer: status={r.status_code}\n')
            r = customer_login()
            lf.write(f'customer_login: status={r.status_code}\n')
            r = create_kb()
            lf.write(f'create_kb: status={r.status_code}\n')
            r = diagnose()
            lf.write(f'diagnose: status={r.status_code}\n')
            lf.write('Finished E2E smoke test\n')
    except Exception as ex:
        import traceback
        with open('e2e_log.txt', 'a', encoding='utf-8') as lf:
            lf.write('E2E test crashed with exception:\n')
            lf.write('\n'.join(traceback.format_exception(type(ex), ex, ex.__traceback__)))
        raise
