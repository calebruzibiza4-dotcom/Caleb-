from app import app, db, Customer

# Internal signup test using request context
with app.app_context():
    db.create_all()

# First signup attempt (new email)
with app.test_request_context('/signup', method='POST', data={'name':'Signup Test','email':'signup_test@example.com','password':'s3cret'}):
    resp = app.view_functions['signup']()
    # After view, check DB
    c = Customer.query.filter_by(email='signup_test@example.com').first()
    print('Created customer:', bool(c), 'verified=', getattr(c,'verified', None))

# Second signup attempt (duplicate email)
with app.test_request_context('/signup', method='POST', data={'name':'Signup Test2','email':'signup_test@example.com','password':'otherpass'}):
    resp = app.view_functions['signup']()
    # Should not create another
    customers = Customer.query.filter_by(email='signup_test@example.com').all()
    print('Number of customers with same email:', len(customers))
