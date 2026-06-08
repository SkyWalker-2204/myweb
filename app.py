from flask import Flask, request, jsonify, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import uuid
import secrets

app = Flask(__name__, static_folder='.', static_url_path='')
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mehndi.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

CORS(app, supports_credentials=True)
db = SQLAlchemy(app)

# ─────────────────────────────── MODELS ───────────────────────────────

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='admin')

class Booking(db.Model):
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.String(20), unique=True, nullable=False)
    customer_name = db.Column(db.String(120), nullable=False)
    mobile = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120))
    event_type = db.Column(db.String(80), nullable=False)
    event_date = db.Column(db.String(20), nullable=False)
    event_time = db.Column(db.String(20))
    address = db.Column(db.Text)
    city = db.Column(db.String(80))
    package_name = db.Column(db.String(80))
    people_count = db.Column(db.Integer, default=1)
    notes = db.Column(db.Text)
    booking_status = db.Column(db.String(30), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Gallery(db.Model):
    __tablename__ = 'gallery'
    id = db.Column(db.Integer, primary_key=True)
    image_url = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    title = db.Column(db.String(150))

class Testimonial(db.Model):
    __tablename__ = 'testimonials'
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(120), nullable=False)
    review = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, default=5)

# ─────────────────────────────── HELPERS ──────────────────────────────

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def sanitize(val, max_len=255):
    if val is None:
        return ''
    return str(val).strip()[:max_len]

def generate_booking_id():
    return 'MHD' + datetime.utcnow().strftime('%y%m%d') + str(uuid.uuid4())[:4].upper()

# ─────────────────────────────── ROUTES ───────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# ── Booking ──────────────────────────────────────────────────────────

@app.route('/book', methods=['POST'])
def book():
    data = request.get_json(silent=True) or request.form
    required = ['customer_name', 'mobile', 'event_type', 'event_date']
    for field in required:
        if not data.get(field):
            return jsonify({'success': False, 'error': f'{field} is required'}), 400

    mobile = sanitize(data.get('mobile'))
    if len(mobile) < 10:
        return jsonify({'success': False, 'error': 'Valid mobile number required'}), 400

    booking = Booking(
        booking_id=generate_booking_id(),
        customer_name=sanitize(data.get('customer_name'), 120),
        mobile=mobile,
        email=sanitize(data.get('email'), 120),
        event_type=sanitize(data.get('event_type'), 80),
        event_date=sanitize(data.get('event_date'), 20),
        event_time=sanitize(data.get('event_time'), 20),
        address=sanitize(data.get('address'), 500),
        city=sanitize(data.get('city'), 80),
        package_name=sanitize(data.get('package_name'), 80),
        people_count=int(data.get('people_count', 1)),
        notes=sanitize(data.get('notes'), 500),
    )
    db.session.add(booking)
    db.session.commit()
    return jsonify({'success': True, 'booking_id': booking.booking_id})

# ── Auth ─────────────────────────────────────────────────────────────

@app.route('/login', methods=['POST'])
def admin_login():
    data = request.get_json(silent=True) or request.form
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        session['admin_logged_in'] = True
        session['admin_username'] = user.username
        return jsonify({'success': True, 'username': user.username})
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def admin_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/auth/status', methods=['GET'])
def auth_status():
    if session.get('admin_logged_in'):
        return jsonify({'logged_in': True, 'username': session.get('admin_username')})
    return jsonify({'logged_in': False})

# ── Admin Bookings ──────────────────────────────────────────────────

@app.route('/admin/bookings', methods=['GET'])
@login_required
def get_admin_bookings():
    search = request.args.get('q', '')
    query = Booking.query
    if search:
        query = query.filter(
            db.or_(
                Booking.customer_name.contains(search),
                Booking.mobile.contains(search),
                Booking.booking_id.contains(search)
            )
        )
    bookings = query.order_by(Booking.event_date.desc()).all()
    return jsonify([{
        'id': b.id,
        'booking_id': b.booking_id,
        'customer_name': b.customer_name,
        'mobile': b.mobile,
        'email': b.email,
        'event_type': b.event_type,
        'event_date': b.event_date,
        'event_time': b.event_time,
        'address': b.address,
        'city': b.city,
        'package_name': b.package_name,
        'people_count': b.people_count,
        'notes': b.notes,
        'booking_status': b.booking_status,
        'created_at': b.created_at.isoformat() if b.created_at else ''
    } for b in bookings])

@app.route('/admin/bookings/stats', methods=['GET'])
@login_required
def get_booking_stats():
    total = Booking.query.count()
    pending = Booking.query.filter_by(booking_status='Pending').count()
    confirmed = Booking.query.filter_by(booking_status='Confirmed').count()
    completed = Booking.query.filter_by(booking_status='Completed').count()
    today = datetime.utcnow().date()
    upcoming = Booking.query.filter(Booking.event_date >= str(today)).count()
    return jsonify({
        'total': total,
        'pending': pending,
        'confirmed': confirmed,
        'completed': completed,
        'upcoming': upcoming,
    })

@app.route('/admin/booking/<int:bid>', methods=['PUT'])
@login_required
def update_booking(bid):
    booking = Booking.query.get_or_404(bid)
    data = request.get_json(silent=True) or request.form
    allowed_statuses = ['Pending', 'Confirmed', 'Completed', 'Cancelled']
    if 'booking_status' in data and data['booking_status'] in allowed_statuses:
        booking.booking_status = data['booking_status']
    if 'notes' in data:
        booking.notes = sanitize(data['notes'], 500)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/booking/<int:bid>', methods=['DELETE'])
@login_required
def delete_booking(bid):
    booking = Booking.query.get_or_404(bid)
    db.session.delete(booking)
    db.session.commit()
    return jsonify({'success': True})

# ── Gallery (Admin only can add) ─────────────────────────────────────

@app.route('/gallery', methods=['GET'])
def get_gallery():
    cat = request.args.get('category')
    query = Gallery.query
    if cat:
        query = query.filter_by(category=cat)
    items = query.all()
    return jsonify([{'id': g.id, 'image_url': g.image_url, 'category': g.category, 'title': g.title} for g in items])

@app.route('/gallery', methods=['POST'])
@login_required
def add_gallery():
    data = request.get_json(silent=True) or request.form
    if not data.get('image_url') or not data.get('category'):
        return jsonify({'success': False, 'error': 'image_url and category required'}), 400
    item = Gallery(
        image_url=sanitize(data['image_url'], 500),
        category=sanitize(data['category'], 80),
        title=sanitize(data.get('title', ''), 150),
    )
    db.session.add(item)
    db.session.commit()
    return jsonify({'success': True, 'id': item.id}), 201

@app.route('/gallery/<int:gid>', methods=['DELETE'])
@login_required
def delete_gallery(gid):
    item = Gallery.query.get_or_404(gid)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'success': True})

# ── Testimonials ──────────────────────────────────────────────────────

@app.route('/testimonials', methods=['GET'])
def get_testimonials():
    items = Testimonial.query.all()
    return jsonify([{'id': t.id, 'customer_name': t.customer_name, 'review': t.review, 'rating': t.rating} for t in items])

@app.route('/testimonial', methods=['POST'])
def add_testimonial():
    data = request.get_json(silent=True) or request.form
    if not data.get('customer_name') or not data.get('review'):
        return jsonify({'success': False, 'error': 'Name and review required'}), 400
    try:
        rating = max(1, min(5, int(data.get('rating', 5))))
    except (ValueError, TypeError):
        rating = 5
    t = Testimonial(
        customer_name=sanitize(data['customer_name'], 120),
        review=sanitize(data['review'], 1000),
        rating=rating,
    )
    db.session.add(t)
    db.session.commit()
    return jsonify({'success': True, 'id': t.id}), 201

@app.route('/testimonial/<int:tid>', methods=['DELETE'])
@login_required
def delete_testimonial(tid):
    t = Testimonial.query.get_or_404(tid)
    db.session.delete(t)
    db.session.commit()
    return jsonify({'success': True})

# ─────────────────────────────── SEED DB ──────────────────────────────

def seed_db():
    # Create admin user
    if not User.query.filter_by(username='sabiya').first():
        db.session.add(User(
            username='sabiya',
            password_hash=generate_password_hash('sabiya123'),
            role='admin',
        ))
    
    # Add default admin if not exists
    if not User.query.filter_by(username='admin').first():
        db.session.add(User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            role='admin',
        ))

    if Testimonial.query.count() == 0:
        testimonials = [
            ('Priya Sharma', 'Absolutely stunning bridal mehndi! Every guest was mesmerised. Sabiya\'s artistry is unmatched. I felt like a queen on my wedding day!', 5),
            ('Anjali Mehta', 'Booked for my engagement and the Arabic pattern was breathtaking. Very professional, on time!', 5),
            ('Neha Patel', 'The festival mehndi package was so affordable yet the quality was top-notch. Highly recommended!', 5),
        ]
        for name, review, rating in testimonials:
            db.session.add(Testimonial(customer_name=name, review=review, rating=rating))

    if Gallery.query.count() == 0:
        gallery_items = [
            ('https://images.unsplash.com/photo-1600857062241-98a9f0f9e4f4?w=600', 'Bridal', 'Royal Bridal Full Hand'),
            ('https://images.unsplash.com/photo-1583292650898-7d22cd27ca6f?w=600', 'Bridal', 'Intricate Bridal Feet'),
            ('https://images.unsplash.com/photo-1571019614242-c5c5dee9f50b?w=600', 'Arabic', 'Floral Arabic Design'),
            ('https://images.unsplash.com/photo-1559827260-dc66d52bef19?w=600', 'Engagement', 'Elegant Engagement Mehndi'),
            ('https://images.unsplash.com/photo-1607827448299-a099b845f076?w=600', 'Festival', 'Diwali Special Design'),
        ]
        for url, cat, title in gallery_items:
            db.session.add(Gallery(image_url=url, category=cat, title=title))

    db.session.commit()

# ─────────────────────────────── MAIN ─────────────────────────────────

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_db()
    print('\n✨ Sabiya\'s Mehndi Art Website running!')
    print('   Open: http://localhost:5000')
    print('   Admin Login: http://localhost:5000 → Click Admin')
    print('   Username: sabiya | Password: sabiya123')
    print('   Alternative: admin | admin123\n')
    app.run(debug=True, port=5000)