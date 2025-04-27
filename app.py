from flask import Flask, request, jsonify, make_response, send_from_directory
from flask_cors import CORS
import sqlite3
import jwt
import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"])
app.config['SECRET_KEY'] = 'hotel_management_secret_key'

# Upload folder configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database connection
def get_db_connection():
    conn = sqlite3.connect('hotel.db')
    conn.row_factory = sqlite3.Row
    return conn

# Create tables if they don't exist
def initialize_db():
    conn = get_db_connection()
    
    # Users table
    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'guest'
    )
    ''')
    
    # Rooms table with image column
    conn.execute('''
    CREATE TABLE IF NOT EXISTS rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_number TEXT UNIQUE NOT NULL,
        room_type TEXT NOT NULL,
        price_per_night REAL NOT NULL,
        occupied BOOLEAN NOT NULL DEFAULT 0,
        image_filename TEXT
    )
    ''')
    
    # Reservations table with payment status
    conn.execute('''
    CREATE TABLE IF NOT EXISTS reservations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        room_id INTEGER NOT NULL,
        check_in_date TEXT NOT NULL,
        check_out_date TEXT NOT NULL,
        total_price REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'confirmed',
        payment_status TEXT NOT NULL DEFAULT 'pending',
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (room_id) REFERENCES rooms (id)
    )
    ''')
    
    # Check if we need to add default rooms
    cursor = conn.execute('SELECT COUNT(*) FROM rooms')
    if cursor.fetchone()[0] == 0:
        # Insert some default rooms
        rooms_data = [
            ('101', 'Standard', 100.0, 0, None),
            ('102', 'Standard', 100.0, 0, None),
            ('201', 'Deluxe', 200.0, 0, None),
            ('202', 'Deluxe', 200.0, 0, None),
            ('301', 'Suite', 300.0, 0, None),
        ]
        
        conn.executemany(
            'INSERT INTO rooms (room_number, room_type, price_per_night, occupied, image_filename) VALUES (?, ?, ?, ?, ?)',
            rooms_data
        )
        
    # Check if we need to add default admin user
    cursor = conn.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
    if cursor.fetchone()[0] == 0:
        # Create default admin with password 'admin'
        hashed_password = generate_password_hash('admin')
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                     ('admin', hashed_password, 'admin'))
    
    conn.commit()
    conn.close()

# Initialize the database on startup
initialize_db()

# JWT token validation decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if token is in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            conn = get_db_connection()
            current_user = conn.execute('SELECT * FROM users WHERE id = ?', (data['user_id'],)).fetchone()
            conn.close()
            
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
                
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

# Admin role required decorator
def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user['role'] != 'admin':
            return jsonify({'message': 'Admin privileges required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Authentication endpoints
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password are required!'}), 400
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (data['username'],)).fetchone()
    conn.close()
    
    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({'message': 'Invalid username or password!'}), 401
    
    # Create JWT token
    token = jwt.encode({
        'user_id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'])
    
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    })

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password are required!'}), 400
    
    hashed_password = generate_password_hash(data['password'])
    
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                   (data['username'], hashed_password, 'guest'))
        conn.commit()
        
        # Get the newly created user
        user = conn.execute('SELECT * FROM users WHERE username = ?', (data['username'],)).fetchone()
        
        # Create JWT token
        token = jwt.encode({
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            'message': 'User registered successfully!',
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            }
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username already exists!'}), 409
    finally:
        conn.close()

# Room endpoints
@app.route('/rooms', methods=['GET'])
def get_rooms():
    conn = get_db_connection()
    rooms = conn.execute('SELECT * FROM rooms').fetchall()
    conn.close()
    
    return jsonify([{
        'id': room['id'],
        'room_number': room['room_number'],
        'room_type': room['room_type'],
        'price_per_night': room['price_per_night'],
        'occupied': bool(room['occupied']),
        'image_filename': room['image_filename']
    } for room in rooms])

@app.route('/rooms/<int:room_id>', methods=['GET'])
def get_room(room_id):
    conn = get_db_connection()
    room = conn.execute('SELECT * FROM rooms WHERE id = ?', (room_id,)).fetchone()
    conn.close()
    
    if not room:
        return jsonify({'message': 'Room not found!'}), 404
    
    return jsonify({
        'id': room['id'],
        'room_number': room['room_number'],
        'room_type': room['room_type'],
        'price_per_night': room['price_per_night'],
        'occupied': bool(room['occupied']),
        'image_filename': room['image_filename']
    })

@app.route('/rooms', methods=['POST'])
@token_required
@admin_required
def create_room(current_user):
    data = request.json
    
    if not data or not data.get('room_number') or not data.get('room_type') or not data.get('price_per_night'):
        return jsonify({'message': 'Room details are incomplete!'}), 400
    
    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT INTO rooms (room_number, room_type, price_per_night) VALUES (?, ?, ?)',
            (data['room_number'], data['room_type'], data['price_per_night'])
        )
        conn.commit()
        
        # Get the newly created room
        room_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        room = conn.execute('SELECT * FROM rooms WHERE id = ?', (room_id,)).fetchone()
        
        return jsonify({
            'message': 'Room created successfully!',
            'room': {
                'id': room['id'],
                'room_number': room['room_number'],
                'room_type': room['room_type'],
                'price_per_night': room['price_per_night'],
                'occupied': bool(room['occupied']),
                'image_filename': room['image_filename']
            }
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Room number already exists!'}), 409
    finally:
        conn.close()

@app.route('/rooms/<int:room_id>', methods=['PUT'])
@token_required
@admin_required
def update_room(current_user, room_id):
    data = request.json
    
    if not data:
        return jsonify({'message': 'No data provided!'}), 400
    
    update_fields = []
    values = []
    
    if 'room_number' in data:
        update_fields.append('room_number = ?')
        values.append(data['room_number'])
    
    if 'room_type' in data:
        update_fields.append('room_type = ?')
        values.append(data['room_type'])
    
    if 'price_per_night' in data:
        update_fields.append('price_per_night = ?')
        values.append(data['price_per_night'])
    
    if 'occupied' in data:
        update_fields.append('occupied = ?')
        values.append(1 if data['occupied'] else 0)
    
    if not update_fields:
        return jsonify({'message': 'No valid fields to update!'}), 400
    
    values.append(room_id)
    
    conn = get_db_connection()
    try:
        conn.execute(
            f'UPDATE rooms SET {", ".join(update_fields)} WHERE id = ?',
            values
        )
        conn.commit()
        
        room = conn.execute('SELECT * FROM rooms WHERE id = ?', (room_id,)).fetchone()
        
        if not room:
            return jsonify({'message': 'Room not found!'}), 404
        
        return jsonify({
            'message': 'Room updated successfully!',
            'room': {
                'id': room['id'],
                'room_number': room['room_number'],
                'room_type': room['room_type'],
                'price_per_night': room['price_per_night'],
                'occupied': bool(room['occupied']),
                'image_filename': room['image_filename']
            }
        })
        
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Room number already exists!'}), 409
    finally:
        conn.close()

@app.route('/rooms/<int:room_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_room(current_user, room_id):
    conn = get_db_connection()
    
    # Check if room exists
    room = conn.execute('SELECT * FROM rooms WHERE id = ?', (room_id,)).fetchone()
    
    if not room:
        conn.close()
        return jsonify({'message': 'Room not found!'}), 404
    
    # Check if room has reservations
    reservations = conn.execute('SELECT * FROM reservations WHERE room_id = ?', (room_id,)).fetchall()
    
    if reservations:
        conn.close()
        return jsonify({'message': 'Cannot delete room with reservations!'}), 400
    
    # Delete room
    conn.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Room deleted successfully!'})

# Room image upload endpoint
@app.route('/rooms/<int:room_id>/image', methods=['POST'])
@token_required
@admin_required
def upload_room_image(current_user, room_id):
    if 'image' not in request.files:
        return jsonify({'message': 'No image file provided!'}), 400
    
    file = request.files['image']
    
    if file.filename == '':
        return jsonify({'message': 'No image selected!'}), 400
    
    if file and allowed_file(file.filename):
        # Create a unique filename with room_id prefix
        filename = f"room_{room_id}_{secure_filename(file.filename)}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the file
        file.save(file_path)
        
        # Update the room record with the image filename
        conn = get_db_connection()
        
        # Check if room exists
        room = conn.execute('SELECT * FROM rooms WHERE id = ?', (room_id,)).fetchone()
        
        if not room:
            conn.close()
            return jsonify({'message': 'Room not found!'}), 404
        
        # Update the room with the new image filename
        conn.execute('UPDATE rooms SET image_filename = ? WHERE id = ?', (filename, room_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Image uploaded successfully!',
            'image_filename': filename
        })
    
    return jsonify({'message': 'Invalid file type! Allowed types: png, jpg, jpeg'}), 400

# Serve room images
@app.route('/uploads/<filename>')
def serve_room_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Reservation endpoints
@app.route('/reservations', methods=['GET'])
@token_required
def get_reservations(current_user):
    conn = get_db_connection()
    
    # Different queries based on user role
    if current_user['role'] == 'admin':
        query = '''
        SELECT r.*, u.username, rm.room_number, rm.room_type, rm.price_per_night
        FROM reservations r
        JOIN users u ON r.user_id = u.id
        JOIN rooms rm ON r.room_id = rm.id
        ORDER BY r.check_in_date DESC
        '''
        reservations = conn.execute(query).fetchall()
    else:
        query = '''
        SELECT r.*, u.username, rm.room_number, rm.room_type, rm.price_per_night
        FROM reservations r
        JOIN users u ON r.user_id = u.id
        JOIN rooms rm ON r.room_id = rm.id
        WHERE r.user_id = ?
        ORDER BY r.check_in_date DESC
        '''
        reservations = conn.execute(query, (current_user['id'],)).fetchall()
    
    conn.close()
    
    return jsonify([{
        'id': res['id'],
        'user_id': res['user_id'],
        'username': res['username'],
        'room_id': res['room_id'],
        'room_number': res['room_number'],
        'room_type': res['room_type'],
        'check_in_date': res['check_in_date'],
        'check_out_date': res['check_out_date'],
        'total_price': res['total_price'],
        'status': res['status'],
        'payment_status': res['payment_status']
    } for res in reservations])

@app.route('/reservations', methods=['POST'])
@token_required
def create_reservation(current_user):
    data = request.json
    
    if not data or not data.get('room_id') or not data.get('check_in_date') or not data.get('check_out_date'):
        return jsonify({'message': 'Reservation details are incomplete!'}), 400
    
    conn = get_db_connection()
    
    # Check if room exists and is available
    room = conn.execute('SELECT * FROM rooms WHERE id = ? AND occupied = 0', (data['room_id'],)).fetchone()
    
    if not room:
        conn.close()
        return jsonify({'message': 'Room not found or already occupied!'}), 400
    
    # Calculate total price
    try:
        check_in = datetime.datetime.strptime(data['check_in_date'], '%Y-%m-%d')
        check_out = datetime.datetime.strptime(data['check_out_date'], '%Y-%m-%d')
        
        if check_in >= check_out:
            conn.close()
            return jsonify({'message': 'Check-out date must be after check-in date!'}), 400
        
        # Calculate number of nights
        nights = (check_out - check_in).days
        total_price = nights * room['price_per_night']
        
        # Insert reservation
        cursor = conn.execute(
            '''INSERT INTO reservations 
               (user_id, room_id, check_in_date, check_out_date, total_price) 
               VALUES (?, ?, ?, ?, ?)''',
            (current_user['id'], data['room_id'], data['check_in_date'], data['check_out_date'], total_price)
        )
        
        # Update room status to occupied
        conn.execute('UPDATE rooms SET occupied = 1 WHERE id = ?', (data['room_id'],))
        
        conn.commit()
        
        # Get the newly created reservation with room details
        reservation_id = cursor.lastrowid
        query = '''
        SELECT r.*, u.username, rm.room_number, rm.room_type, rm.price_per_night
        FROM reservations r
        JOIN users u ON r.user_id = u.id
        JOIN rooms rm ON r.room_id = rm.id
        WHERE r.id = ?
        '''
        reservation = conn.execute(query, (reservation_id,)).fetchone()
        
        result = {
            'message': 'Reservation created successfully!',
            'reservation': {
                'id': reservation['id'],
                'user_id': reservation['user_id'],
                'username': reservation['username'],
                'room_id': reservation['room_id'],
                'room_number': reservation['room_number'],
                'room_type': reservation['room_type'],
                'check_in_date': reservation['check_in_date'],
                'check_out_date': reservation['check_out_date'],
                'total_price': reservation['total_price'],
                'status': reservation['status'],
                'payment_status': reservation['payment_status']
            }
        }
        
        conn.close()
        return jsonify(result), 201
        
    except Exception as e:
        conn.close()
        return jsonify({'message': f'Error creating reservation: {str(e)}'}), 500

@app.route('/reservations/<int:reservation_id>/cancel', methods=['POST'])
@token_required
def cancel_reservation(current_user, reservation_id):
    conn = get_db_connection()
    
    # Check if reservation exists and belongs to user (or user is admin)
    if current_user['role'] == 'admin':
        reservation = conn.execute('SELECT * FROM reservations WHERE id = ?', (reservation_id,)).fetchone()
    else:
        reservation = conn.execute(
            'SELECT * FROM reservations WHERE id = ? AND user_id = ?', 
            (reservation_id, current_user['id'])
        ).fetchone()
    
    if not reservation:
        conn.close()
        return jsonify({'message': 'Reservation not found or access denied!'}), 404
    
    # Update reservation status
    conn.execute('UPDATE reservations SET status = "cancelled" WHERE id = ?', (reservation_id,))
    
    # Update room status to available
    conn.execute('UPDATE rooms SET occupied = 0 WHERE id = ?', (reservation['room_id'],))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Reservation cancelled successfully!'})

@app.route('/reservations/<int:reservation_id>/payment', methods=['POST'])
@token_required
def process_payment(current_user, reservation_id):
    conn = get_db_connection()
    
    # Check if reservation exists and belongs to user (or user is admin)
    if current_user['role'] == 'admin':
        reservation = conn.execute('SELECT * FROM reservations WHERE id = ?', (reservation_id,)).fetchone()
    else:
        reservation = conn.execute(
            'SELECT * FROM reservations WHERE id = ? AND user_id = ?', 
            (reservation_id, current_user['id'])
        ).fetchone()
    
    if not reservation:
        conn.close()
        return jsonify({'message': 'Reservation not found or access denied!'}), 404
    
    # Check if payment is already processed
    if reservation['payment_status'] == 'paid':
        conn.close()
        return jsonify({'message': 'Payment already processed!'}), 400
    
    # Update payment status
    conn.execute('UPDATE reservations SET payment_status = "paid" WHERE id = ?', (reservation_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Payment processed successfully!'})

# Admin user management endpoints
@app.route('/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user):
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, role FROM users').fetchall()
    conn.close()
    
    return jsonify([{
        'id': user['id'],
        'username': user['username'],
        'role': user['role']
    } for user in users])

@app.route('/users/<int:user_id>', methods=['PUT'])
@token_required
@admin_required
def update_user(current_user, user_id):
    data = request.json
    
    if not data:
        return jsonify({'message': 'No data provided!'}), 400
    
    # Prevent changing own role
    if user_id == current_user['id'] and 'role' in data and data['role'] != 'admin':
        return jsonify({'message': 'Cannot change your own admin role!'}), 403
    
    update_fields = []
    values = []
    
    if 'username' in data:
        update_fields.append('username = ?')
        values.append(data['username'])
    
    if 'role' in data:
        if data['role'] not in ['admin', 'guest']:
            return jsonify({'message': 'Invalid role! Must be admin or guest.'}), 400
        update_fields.append('role = ?')
        values.append(data['role'])
    
    if 'password' in data:
        update_fields.append('password = ?')
        values.append(generate_password_hash(data['password']))
    
    if not update_fields:
        return jsonify({'message': 'No valid fields to update!'}), 400
    
    values.append(user_id)
    
    conn = get_db_connection()
    try:
        conn.execute(
            f'UPDATE users SET {", ".join(update_fields)} WHERE id = ?',
            values
        )
        conn.commit()
        
        user = conn.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,)).fetchone()
        
        if not user:
            return jsonify({'message': 'User not found!'}), 404
        
        return jsonify({
            'message': 'User updated successfully!',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            }
        })
        
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username already exists!'}), 409
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True) 