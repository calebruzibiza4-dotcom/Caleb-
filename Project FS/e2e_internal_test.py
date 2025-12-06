from app import app, db, Customer, KnowledgeBaseArticle

# Run a quick internal test using Flask test client (no external network required)
with app.app_context():
    db.create_all()
    # create a test customer
    if not Customer.query.filter_by(email='itest@example.com').first():
        c = Customer(name='Internal Test', email='itest@example.com')
        c.set_password('itestpass')
        db.session.add(c)
        db.session.commit()

    # ensure a KB article exists
    if not KnowledgeBaseArticle.query.filter_by(title='Reboot Fix').first():
        a = KnowledgeBaseArticle(title='Reboot Fix', content='If device will not boot, try rebooting and check power.', tags='boot,reboot')
        db.session.add(a)
        db.session.commit()

from flask import session

# Use test_request_context to avoid relying on test_client (werkzeug version issues)
with app.test_request_context('/kb/diagnose', method='POST', data={'symptoms': 'my laptop will not boot and shows black screen'}):
    # set customer session
    session['customer_id'] = Customer.query.filter_by(email='itest@example.com').first().id
    # call the view function directly
    rv = app.view_functions['kb_diagnose']()
    # The view may return a Response or rendered string
    if hasattr(rv, 'get_data'):
        text = rv.get_data(as_text=True)
        print('Returned Response, length=', len(text))
    else:
        text = rv
        print('Returned string length=', len(text))
    found = '<h4>Suggestions' in text
    print('Contains Suggestions section:', found)
    print(text[:800])