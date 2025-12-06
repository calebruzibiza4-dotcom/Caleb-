import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask import session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
import time
from sqlalchemy import inspect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Resolve base directory first and provide an explicit instance path to Flask.
# This avoids Flask trying to auto-discover package paths (which can call
# pkgutil.get_loader) on some newer Python runtimes where that lookup fails.
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, instance_path=os.path.join(BASE_DIR, 'instance'), instance_relative_config=False)
app.config['SECRET_KEY'] = 'dev-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'instance', 'repairshop.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(50))
    address = db.Column(db.String(255))
    is_business = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # optional password for customer account (hashed)
    password_hash = db.Column(db.String(255))
    # whether the account was verified/approved by staff
    verified = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

class SparePart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    cost = db.Column(db.Float, default=0.0)

class SupportRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'))
    scheduled_for = db.Column(db.DateTime)
    status = db.Column(db.String(50), default='open')
    estimated_cost = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    priority = db.Column(db.Integer, default=3)
    location = db.Column(db.String(255))
    time_taken_hours = db.Column(db.Float)
    customer = db.relationship('Customer', backref='requests')
    # customer feedback/rating (1-5)
    rating = db.Column(db.Integer)
    customer_feedback = db.Column(db.Text)

class KnowledgeBaseArticle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text)
    tags = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Simple rule-based suggestion mapping for common computer problems.
SUGGESTION_RULES = {
    'slow': [
        'Restart the computer to clear temporary issues.',
        'Check for heavy background processes in Task Manager and close unnecessary apps.',
        'Ensure there is at least 10% free disk space on your system drive.'
    ],
    'battery': [
        'Reduce screen brightness and turn off unused radios (Bluetooth/Wi-Fi) to save battery.',
        'If battery drains extremely fast, consider replacing the battery or calibrating it.'
    ],
    'not boot': [
        'Check that the power cable is connected and the battery has charge.',
        'Try booting into safe mode or BIOS to verify hardware is detected.'
    ],
    'blue screen': [
        'Take note of the stop code and look up the specific error.',
        'Try booting in safe mode and uninstall recently added drivers or updates.'
    ],
    'overheat': [
        'Ensure vents are not blocked and the cooling fan is working.',
        'Use compressed air to gently remove dust from vents and fans.'
    ],
    'wifi': [
        'Restart the router and the computer.',
        'Check Wi-Fi drivers and try reconnecting to the network.'
    ],
    'virus': [
        'Run a full system scan with an up-to-date antivirus program.',
        'Disconnect from the internet if malware is suspected and seek professional help.'
    ],
    'password': [
        'Use the password reset feature if available or contact support to verify account ownership.',
    ],
    'screen': [
        'Check display cable connections and test with an external monitor if possible.',
        'Update or roll back the display driver.'
    ],
    'not switching on': [
        'first check that its properly plugged into a working power outlet, and try a different power cable. If that does not work, disconnect all external devices, perform a full power cycle by holding the power button for 15-30 seconds, and then try to start it again. For desktops, inspect internal cables and components like the RAM and GPU, while for laptops, check the battery and charger. '
    ],
}


# Simple user model for staff access
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_staff = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Simple helper to create DB (called explicitly on startup)
def create_tables():
    os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)
    # create DB within app context
    with app.app_context():
        inspector = inspect(db.engine)
        # Attempt to create any missing tables without destructive drops.
        db.create_all()
        # If an obvious schema mismatch is detected, create a backup and record an audit entry.
        try:
            mismatch = False
            if inspector.has_table('support_request'):
                cols = [c['name'] for c in inspector.get_columns('support_request')]
                if 'customer_id' not in cols or 'rating' not in cols:
                    mismatch = True
            if inspector.has_table('customer'):
                cust_cols = [c['name'] for c in inspector.get_columns('customer')]
                if 'verified' not in cust_cols:
                    mismatch = True
            if inspector.has_table('user'):
                user_cols = [c['name'] for c in inspector.get_columns('user')]
                if 'username' not in user_cols or 'password_hash' not in user_cols:
                    mismatch = True

            if mismatch:
                # Make a JSON backup of current DB content before any further action
                try:
                    from json import dumps
                    with app.app_context():
                        customers = [dict(id=c.id, name=c.name, email=c.email, phone=c.phone, address=c.address, is_business=c.is_business) for c in Customer.query.all()]
                        requests_ = [dict(id=r.id, title=r.title, description=r.description, customer_id=r.customer_id, scheduled_for=r.scheduled_for.isoformat() if r.scheduled_for else None, status=r.status) for r in SupportRequest.query.all()]
                        parts = [dict(id=p.id, sku=p.sku, name=p.name, quantity=p.quantity, cost=p.cost) for p in SparePart.query.all()]
                        kb = [dict(id=a.id, title=a.title, content=a.content, tags=a.tags) for a in KnowledgeBaseArticle.query.all()]
                        payload = {'customers': customers, 'requests': requests_, 'parts': parts, 'kb': kb}
                    timestamp = int(time.time())
                    backup_path = os.path.join(BASE_DIR, 'instance', f'pre_migration_backup_{timestamp}.json')
                    with open(backup_path, 'w', encoding='utf-8') as f:
                        f.write(dumps(payload, indent=2, ensure_ascii=False))
                    # record an audit entry
                    try:
                        a = Audit(user_id=None, action='pre_migration_backup', details=f'Created backup at {backup_path}')
                        db.session.add(a)
                        db.session.commit()
                    except Exception:
                        pass
                except Exception:
                    pass
                # Don't auto-drop. Notify developer via stdout and leave DB intact.
                print('Schema mismatch detected. Backed up data to', backup_path)
                print('To apply schema changes run migrations or manually inspect the DB.')
        except Exception:
            # If inspection fails, still ensure tables exist
            db.create_all()
        # create a default staff user for development if none exists
        try:
            if not User.query.first():
                u = User(username='admin')
                u.set_password('admin')
                db.session.add(u)
                db.session.commit()
        except Exception:
            # ignore if table doesn't exist yet or other race conditions
            pass

# Setup login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    recent = SupportRequest.query.order_by(SupportRequest.created_at.desc()).limit(5).all()
    return render_template('index.html', recent=recent)

# Customers
@app.route('/customers')
def customers():
    q = request.args.get('q', '')
    if q:
        items = Customer.query.filter(Customer.name.ilike(f"%{q}%"))
    else:
        items = Customer.query.order_by(Customer.created_at.desc())
    return render_template('customers.html', customers=items, q=q)

@app.route('/customers/new', methods=['GET', 'POST'])
def new_customer():
    if request.method == 'POST':
        data = request.form
        c = Customer(
            name=data.get('name'),
            email=data.get('email'),
            phone=data.get('phone'),
            address=data.get('address'),
            is_business=bool(data.get('is_business')),
            verified=True
        )
        pwd = data.get('password')
        if pwd:
            c.set_password(pwd)
        db.session.add(c)
        db.session.commit()
        flash('Customer created', 'success')
        return redirect(url_for('customers'))
    return render_template('customer_form.html', customer=None)

@app.route('/customers/<int:id>/edit', methods=['GET', 'POST'])
def edit_customer(id):
    c = Customer.query.get_or_404(id)
    if request.method == 'POST':
        data = request.form
        c.name = data.get('name')
        c.email = data.get('email')
        c.phone = data.get('phone')
        c.address = data.get('address')
        c.is_business = bool(data.get('is_business'))
        pwd = data.get('password')
        if pwd:
            c.set_password(pwd)
        db.session.commit()
        flash('Customer updated', 'success')
        return redirect(url_for('customers'))
    return render_template('customer_form.html', customer=c)


@app.route('/customers/<int:id>/approve', methods=['POST'])
@login_required
def approve_customer(id):
    # Only staff can approve accounts
    if not getattr(current_user, 'is_staff', False):
        flash('Not authorized', 'danger')
        return redirect(url_for('customers'))
    c = Customer.query.get_or_404(id)
    if c.verified:
        flash('Customer already verified', 'info')
    else:
        c.verified = True
        db.session.commit()
        flash(f'Customer {c.name} has been verified.', 'success')
        try:
            db.session.add(Audit(user_id=current_user.id if current_user.is_authenticated else None, action='customer_approve', details=f'customer_id={c.id},email={c.email}'))
            db.session.commit()
        except Exception:
            db.session.rollback()
    return redirect(url_for('customers'))

# Support requests
@app.route('/requests')
def requests_list():
    items = SupportRequest.query.order_by(SupportRequest.priority.asc(), SupportRequest.scheduled_for.asc().nullsfirst()).all()
    return render_template('requests.html', requests=items)

@app.route('/requests/new', methods=['GET', 'POST'])
def new_request():
    customers = Customer.query.order_by(Customer.name).all()
    if request.method == 'POST':
        data = request.form
        scheduled = data.get('scheduled_for')
        scheduled_dt = datetime.fromisoformat(scheduled) if scheduled else None
        r = SupportRequest(
            title=data.get('title'),
            description=data.get('description'),
            customer_id=int(data.get('customer_id')) if data.get('customer_id') else None,
            scheduled_for=scheduled_dt,
            estimated_cost=float(data.get('estimated_cost') or 0),
            priority=int(data.get('priority') or 3),
            location=data.get('location')
        )
        db.session.add(r)
        db.session.commit()
        flash('Support request created', 'success')
        return redirect(url_for('requests_list'))
    return render_template('request_form.html', customers=customers)


# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in', 'success')
            next_page = request.args.get('next') or url_for('dashboard')
            return redirect(next_page)
        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('index'))


# Staff user management
@app.route('/staff')
@login_required
def staff_list():
    if not getattr(current_user, 'is_staff', False):
        flash('Not authorized', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.order_by(User.username).all()
    return render_template('staff_list.html', users=users)


@app.route('/staff/new', methods=['GET', 'POST'])
@login_required
def staff_new():
    if not getattr(current_user, 'is_staff', False):
        flash('Not authorized', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_staff = bool(request.form.get('is_staff'))
        if not username or not password:
            flash('Username and password required', 'warning')
            return render_template('staff_form.html', user=None)
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'warning')
            return render_template('staff_form.html', user=None)
        u = User(username=username, is_staff=is_staff)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash('Staff user created', 'success')
        try:
            db.session.add(Audit(user_id=current_user.id if current_user.is_authenticated else None, action='staff_create', details=f'username={u.username}'))
            db.session.commit()
        except Exception:
            db.session.rollback()
        return redirect(url_for('staff_list'))
    return render_template('staff_form.html', user=None)


@app.route('/staff/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def staff_edit(id):
    if not getattr(current_user, 'is_staff', False):
        flash('Not authorized', 'danger')
        return redirect(url_for('dashboard'))
    u = User.query.get_or_404(id)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_staff = bool(request.form.get('is_staff'))
        if username:
            u.username = username
        u.is_staff = is_staff
        if password:
            u.set_password(password)
        db.session.commit()
        flash('Staff user updated', 'success')
        try:
            db.session.add(Audit(user_id=current_user.id if current_user.is_authenticated else None, action='staff_edit', details=f'id={u.id},username={u.username}'))
            db.session.commit()
        except Exception:
            db.session.rollback()
        return redirect(url_for('staff_list'))
    return render_template('staff_form.html', user=u)


@app.route('/staff/<int:id>/delete', methods=['POST'])
@login_required
def staff_delete(id):
    if not getattr(current_user, 'is_staff', False):
        flash('Not authorized', 'danger')
        return redirect(url_for('dashboard'))
    u = User.query.get_or_404(id)
    if u.id == current_user.id:
        flash('You cannot delete your own account while logged in', 'warning')
        return redirect(url_for('staff_list'))
    db.session.delete(u)
    db.session.commit()
    flash('Staff user deleted', 'info')
    try:
        db.session.add(Audit(user_id=current_user.id if current_user.is_authenticated else None, action='staff_delete', details=f'id={u.id},username={u.username}'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    return redirect(url_for('staff_list'))

# Spare parts
@app.route('/parts')
def parts():
    q = request.args.get('q', '')
    if q:
        items = SparePart.query.filter((SparePart.name.ilike(f"%{q}%")) | (SparePart.sku.ilike(f"%{q}%")))
    else:
        items = SparePart.query.order_by(SparePart.name)
    return render_template('parts.html', parts=items, q=q)

@app.route('/parts/new', methods=['GET', 'POST'])
def new_part():
    if request.method == 'POST':
        data = request.form
        p = SparePart(sku=data.get('sku'), name=data.get('name'), quantity=int(data.get('quantity') or 0), cost=float(data.get('cost') or 0))
        db.session.add(p)
        db.session.commit()
        flash('Part added', 'success')
        return redirect(url_for('parts'))
    return render_template('part_form.html', part=None)

@app.route('/parts/<int:id>/edit', methods=['GET', 'POST'])
def edit_part(id):
    p = SparePart.query.get_or_404(id)
    if request.method == 'POST':
        data = request.form
        p.sku = data.get('sku')
        p.name = data.get('name')
        p.quantity = int(data.get('quantity') or 0)
        p.cost = float(data.get('cost') or 0)
        db.session.commit()
        flash('Part updated', 'success')
        return redirect(url_for('parts'))
    return render_template('part_form.html', part=p)

# Knowledge base
@app.route('/kb')
def kb_list():
    q = request.args.get('q', '')
    if q:
        items = KnowledgeBaseArticle.query.filter((KnowledgeBaseArticle.title.ilike(f"%{q}%")) | (KnowledgeBaseArticle.tags.ilike(f"%{q}%")))
    else:
        items = KnowledgeBaseArticle.query.order_by(KnowledgeBaseArticle.created_at.desc())
    return render_template('kb.html', articles=items, q=q)


@app.route('/kb/diagnose', methods=['GET', 'POST'])
def kb_diagnose():
    # Only allow customers to use the diagnose tool
    if not session.get('customer_id'):
        flash('Please log in as a customer to use the diagnose tool.', 'warning')
        return redirect(url_for('customer_login'))

    results = []
    suggestions = []
    query = ''
    if request.method == 'POST':
        query = request.form.get('symptoms', '').strip()
        if query:
            # basic keyword scoring across title/content/tags
            terms = [t.lower() for t in query.split() if len(t) > 2]
            articles = KnowledgeBaseArticle.query.all()
            scored = []
            for a in articles:
                score = 0
                text = ' '.join([a.title or '', a.content or '', a.tags or '']).lower()
                for t in terms:
                    score += text.count(t) * (3 if t in (a.tags or '').lower() else 1)
                if score > 0:
                    # extract a short snippet where term appears
                    idx = min([text.find(t) for t in terms if text.find(t) >= 0] or [0])
                    snippet = (a.content or '')[max(0, idx-80):idx+160]
                    scored.append((score, a, snippet))
            scored.sort(key=lambda x: x[0], reverse=True)
            results = [{'score': s, 'article': art, 'snippet': sn} for s, art, sn in scored]
            # Build suggestions from simple rule-matching
            qlow = query.lower()
            matched = set()
            for key, hints in SUGGESTION_RULES.items():
                if key in qlow:
                    matched.add(key)
                    for h in hints:
                        suggestions.append({'term': key, 'suggestion': h})

            # Also suggest relevant KB articles as next steps
            for r in results:
                suggestions.append({'term': 'kb', 'suggestion': f"See article: {r['article'].title}", 'article_id': r['article'].id})
            # If no suggestions and no results, provide general guidance
            if not suggestions:
                suggestions.append({'term': 'general', 'suggestion': 'Try restarting your device and describing the exact error messages or behaviors.'})
    return render_template('kb_diagnose.html', results=results, query=query, suggestions=suggestions)


@app.route('/kb/<int:id>')
def kb_view(id):
    a = KnowledgeBaseArticle.query.get_or_404(id)
    return render_template('kb_view.html', article=a)

@app.route('/kb/new', methods=['GET', 'POST'])
def kb_new():
    if request.method == 'POST':
        data = request.form
        a = KnowledgeBaseArticle(title=data.get('title'), content=data.get('content'), tags=data.get('tags'))
        db.session.add(a)
        db.session.commit()
        flash('Article added', 'success')
        return redirect(url_for('kb_list'))
    return render_template('kb_form.html')

# Dashboard & simple analytics
@app.route('/dashboard')
def dashboard():
    try:
        # Common issues (order by actual counted column)
        issue_count = db.func.count(SupportRequest.id)
        issues = db.session.query(SupportRequest.title, issue_count.label('count'))\
            .group_by(SupportRequest.title).order_by(issue_count.desc()).limit(5).all()

        # Avg time
        avg_time = db.session.query(db.func.avg(SupportRequest.time_taken_hours)).scalar() or 0

        # Satisfaction (placeholder)
        total = db.session.query(db.func.count(SupportRequest.id)).scalar() or 0
        done = db.session.query(db.func.count(SupportRequest.id)).filter(SupportRequest.status == 'done').scalar() or 0

        parts_low = SparePart.query.filter(SparePart.quantity < 5).all()

        job_count = db.func.count(SupportRequest.id)
        business_jobs = db.session.query(Customer.address, job_count.label('count'))\
            .join(SupportRequest, Customer.id == SupportRequest.customer_id)\
            .group_by(Customer.address).order_by(job_count.desc()).limit(5).all()

        # rating distribution (group by rating)
        rating_rows = db.session.query(SupportRequest.rating, db.func.count(SupportRequest.id)).group_by(SupportRequest.rating).all()
        rating_counts = {row[0]: row[1] for row in rating_rows if row[0] is not None}

    except Exception as e:
        # Log/flash a helpful message but avoid 500 errors on the dashboard
        flash(f'Dashboard data error: {str(e)}', 'danger')
        issues = []
        avg_time = 0
        total = 0
        done = 0
        parts_low = []
        business_jobs = []

    # normalize ratings to 1-5
    ratings = {i: int(rating_counts.get(i, 0)) for i in range(1, 6)}
    return render_template('dashboard.html', issues=issues, avg_time=round(avg_time, 2), total=total, done=done, parts_low=parts_low, business_jobs=business_jobs, ratings=ratings)


# Development-only: Reset the entire database schema and data.
@app.route('/reset', methods=['POST'])
@login_required
def reset_db():
    token = request.form.get('token')
    stored = session.get('reset_token')
    exp = session.get('reset_token_exp', 0)
    now = time.time()
    if not token or not stored or token != stored or now > exp:
        flash('Invalid or expired reset token. Use the preview page to generate a fresh token.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        with app.app_context():
            # create a backup first
            try:
                from json import dumps
                customers = [dict(id=c.id, name=c.name, email=c.email) for c in Customer.query.all()]
                payload = {'customers': customers}
                ts = int(time.time())
                path = os.path.join(BASE_DIR, 'instance', f'reset_backup_{ts}.json')
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(dumps(payload, indent=2, ensure_ascii=False))
                try:
                    db.session.add(Audit(user_id=current_user.id if current_user.is_authenticated else None, action='pre_reset_backup', details=path))
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            except Exception:
                pass
            db.drop_all()
            db.create_all()
        # clear token after successful reset
        session.pop('reset_token', None)
        session.pop('reset_token_exp', None)
        flash('Database has been reset (development only).', 'success')
    except Exception as e:
        flash(f'Failed to reset database: {e}', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/reset', methods=['GET'])
@login_required
def reset_preview():
    # Only in debug mode
    if not app.debug:
        flash('Reset preview disabled in production mode', 'warning')
        return redirect(url_for('dashboard'))

    # generate a short-lived token and store in session
    token = uuid.uuid4().hex
    session['reset_token'] = token
    # token valid for 5 minutes
    session['reset_token_exp'] = time.time() + 300

    # gather counts for dry-run preview
    with app.app_context():
        cust_count = db.session.query(db.func.count(Customer.id)).scalar() or 0
        req_count = db.session.query(db.func.count(SupportRequest.id)).scalar() or 0
        part_count = db.session.query(db.func.count(SparePart.id)).scalar() or 0
        kb_count = db.session.query(db.func.count(KnowledgeBaseArticle.id)).scalar() or 0

    return render_template('reset_preview.html', token=token, cust_count=cust_count, req_count=req_count, part_count=part_count, kb_count=kb_count)

# API endpoints for minimal integrations
@app.route('/api/customers')
def api_customers():
    customers = Customer.query.limit(100).all()
    return jsonify([{'id':c.id,'name':c.name,'email':c.email} for c in customers])


@app.route('/export')
@login_required
def export_backup():
    # Export current DB data as JSON for dry-run backup before reset
    with app.app_context():
        customers = [
            {'id': c.id, 'name': c.name, 'email': c.email, 'phone': c.phone, 'address': c.address, 'is_business': c.is_business}
            for c in Customer.query.all()
        ]
        requests_ = [
            {'id': r.id, 'title': r.title, 'description': r.description, 'customer_id': r.customer_id, 'scheduled_for': r.scheduled_for.isoformat() if r.scheduled_for else None, 'status': r.status, 'estimated_cost': r.estimated_cost}
            for r in SupportRequest.query.all()
        ]
        parts = [
            {'id': p.id, 'sku': p.sku, 'name': p.name, 'quantity': p.quantity, 'cost': p.cost}
            for p in SparePart.query.all()
        ]
        kb = [
            {'id': a.id, 'title': a.title, 'content': a.content, 'tags': a.tags}
            for a in KnowledgeBaseArticle.query.all()
        ]
    data = {'customers': customers, 'requests': requests_, 'parts': parts, 'kb': kb}
    import json
    payload = json.dumps(data, indent=2)
    from flask import Response
    resp = Response(payload, mimetype='application/json')
    resp.headers['Content-Disposition'] = 'attachment; filename=backup.json'
    try:
        db.session.add(Audit(user_id=current_user.id if current_user.is_authenticated else None, action='export_backup', details='exported backup'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    return resp


# Customer authentication (simple session-based)
def customer_login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('customer_id'):
            flash('Please log in as customer to continue', 'warning')
            return redirect(url_for('customer_login'))
        return f(*args, **kwargs)
    return wrapped


@app.route('/customer/login', methods=['GET', 'POST'])
def customer_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        c = Customer.query.filter(Customer.email == email).first()
        # If customer exists but no password set, prompt them to create one
        if c and (not c.password_hash):
            flash('No password set for this account. Please set a password before logging in.', 'warning')
            return redirect(url_for('customer_set_password'))

        if c and c.check_password(password):
            session['customer_id'] = c.id
            flash('Customer logged in', 'success')
            return redirect(url_for('customer_dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('customer_login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.form
        # require password at signup for a better UX
        pwd = data.get('password')
        if not pwd:
            flash('Please choose a password when signing up.', 'warning')
            return render_template('signup.html')
        # check for duplicate email
        existing = None
        if data.get('email'):
            existing = Customer.query.filter(Customer.email == data.get('email')).first()
        if existing:
            flash('An account with that email already exists. Please log in or use a different email.', 'warning')
            return redirect(url_for('customer_login'))
        c = Customer(
            name=data.get('name'),
            email=data.get('email'),
            phone=data.get('phone'),
            address=data.get('address'),
            is_business=False,
            verified=False
        )
        c.set_password(pwd)
        db.session.add(c)
        db.session.commit()
        flash('Account request submitted. A staff member will verify it shortly.', 'success')
        # audit log
        try:
            db.session.add(Audit(user_id=None, action='customer_signup', details=f'Email: {c.email}'))
            db.session.commit()
        except Exception:
            db.session.rollback()
        return redirect(url_for('customer_login'))
    return render_template('signup.html')


@app.route('/customer/set_password', methods=['GET', 'POST'])
def customer_set_password():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        c = Customer.query.filter(Customer.email == email).first()
        if not c:
            flash('No account found for that email address.', 'danger')
            return redirect(url_for('customer_set_password'))
        # Only allow setting password if none exists; staff can update via admin UI
        if c.password_hash:
            flash('A password is already set for this account. Use the login form or contact support.', 'warning')
            return redirect(url_for('customer_login'))
        c.set_password(password)
        db.session.commit()
        flash('Password set. You can now log in.', 'success')
        return redirect(url_for('customer_login'))
    return render_template('customer_set_password.html')


@app.route('/customer/logout')
def customer_logout():
    session.pop('customer_id', None)
    flash('Customer logged out', 'info')
    return redirect(url_for('index'))


@app.route('/customer/dashboard')
@customer_login_required
def customer_dashboard():
    cid = session.get('customer_id')
    c = Customer.query.get(cid)
    reqs = SupportRequest.query.filter_by(customer_id=cid).order_by(SupportRequest.created_at.desc()).all()
    return render_template('customer_dashboard.html', customer=c, requests=reqs)


@app.route('/customer/requests/<int:req_id>/rate', methods=['POST'])
@customer_login_required
def customer_rate(req_id):
    cid = session.get('customer_id')
    r = SupportRequest.query.get_or_404(req_id)
    if r.customer_id != cid:
        flash('Not authorized', 'danger')
        return redirect(url_for('customer_dashboard'))
    rating = int(request.form.get('rating') or 0)
    feedback = request.form.get('feedback')
    if rating < 1 or rating > 5:
        flash('Rating must be between 1 and 5', 'warning')
        return redirect(url_for('customer_dashboard'))
    r.rating = rating
    r.customer_feedback = feedback
    db.session.commit()
    flash('Thank you for your feedback', 'success')
    return redirect(url_for('customer_dashboard'))

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)
