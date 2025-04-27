from fastapi.middleware.cors import CORSMiddleware  # Import CORS middleware
from jwt_handler import create_access_token
from jwt_handler import create_access_token, verify_token
from fastapi import FastAPI, HTTPException, Depends, status, Header
from pydantic import BaseModel
from fastapi.security import HTTPBearer
from fastapi import Depends, HTTPException, status
import asyncio

import sqlite3
import bcrypt
from datetime import datetime
import uuid

app = FastAPI()

origins = ["*", "http://localhost:5174"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Database connection
def get_db():
    conn = sqlite3.connect('hotel.db')
    conn.row_factory = sqlite3.Row
    return conn

# Models
class UserRegister(BaseModel):
    email: str
    password: str
    full_name: str
    role: str
    contact_number: str

class RoomCreate(BaseModel):
    room_number: str
    room_type: str
    price: float
    capacity: int
    amenities: str
    image_url: str | None = None  # Added image_url field, optional

class ReservationCreate(BaseModel):
    user_id: int
    room_id: int
    check_in_date: str
    check_out_date: str

class PaymentCreate(BaseModel):
    reservation_id: int
    amount: float
    payment_method: str
    transaction_id: str

class UserMeResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    contact_number: str

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    contact_number: str
    # created_at: datetime

class UserLogin(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse  # Use existing UserResponse model

class RoomStatusUpdate(BaseModel):
    status: str

bearer_scheme = HTTPBearer()

# Middleware to verify JWT token
async def get_current_user(token: str = Depends(bearer_scheme)):
    print("Received Token:", token.credentials)
    payload = verify_token(token.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


# Authentication APIs
@app.post("/api/auth/register")
def register(user: UserRegister):
    conn = get_db()
    cursor = conn.cursor()
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute(
        "INSERT INTO Users (email, password, full_name, role, contact_number) VALUES (?, ?, ?, ?, ?)",
        (user.email, hashed_password, user.full_name, user.role, user.contact_number)
    )
    conn.commit()
    conn.close()
    return {"message": "User registered successfully"}



@app.post("/api/auth/login", response_model=LoginResponse)
def login(user: UserLogin):
    conn = get_db()
    cursor = conn.cursor()
    db_user = cursor.execute("SELECT * FROM Users WHERE email = ?", (user.email,)).fetchone()
    conn.close()

    if not db_user or not bcrypt.checkpw(user.password.encode('utf-8'), db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # # Convert SQLite datetime string to datetime object
    # created_at_str = db_user["created_at"]
    # created_at = datetime.strptime(created_at_str, "%Y-%m-%d %H:%M:%S")  # Handle SQLite format

    access_token = create_access_token(data={"sub": db_user["email"], "id": db_user["id"], "role": db_user["role"]})
    
    user_data = {
        "id": db_user["id"],
        "email": db_user["email"],
        "full_name": db_user["full_name"],
        "role": db_user["role"],
        "contact_number": db_user["contact_number"],
        # "created_at": created_at,  # Use converted datetime
    }

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_data
    }



@app.get("/api/auth/me", response_model=UserMeResponse)
def get_user_profile(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    user = cursor.execute(
        "SELECT id, email, full_name, role, contact_number FROM Users WHERE id = ?",
        (current_user["id"],)
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user_dict = dict(user)  # Convert Row to dictionary
    return UserMeResponse(**user_dict)


# Room Management APIs
# Admin-only endpoints
@app.post("/api/rooms")
def create_room(room: RoomCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can create rooms")
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO Rooms (room_number, room_type, price, capacity, amenities, status, image_url) VALUES (?, ?, ?, ?, ?, 'available', ?)",
            (room.room_number, room.room_type, room.price, room.capacity, room.amenities, room.image_url)
        )
        conn.commit()
        return {"message": "Room created successfully"}
    except sqlite3.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"Room number '{room.room_number}' already exists")
    except Exception as e:
        conn.rollback()
        print(f"Error creating room: {e}")
        raise HTTPException(status_code=500, detail="Failed to create room")
    finally:
        conn.close()



@app.get("/api/rooms")
def get_rooms():
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        rooms = cursor.execute("SELECT * FROM Rooms").fetchall()
        # Convert Row objects to dictionaries for JSON serialization
        result = [dict(room) for room in rooms]
        conn.close()
        return {"rooms": result}
    except Exception as e:
        print(f"Error getting rooms: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve rooms")
    finally:
        if conn:
            conn.close()


@app.get("/api/rooms/{room_id}")
def get_room(room_id: int):
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        room = cursor.execute("SELECT * FROM Rooms WHERE id = ?", (room_id,)).fetchone()
        
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")
        
        # Convert SQLite Row object to dictionary
        return {"room": dict(room)}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting room: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve room details")
    finally:
        conn.close()



@app.put("/api/rooms/{room_id}/status")
def update_room_status(
    room_id: int, 
    status_update: RoomStatusUpdate,  # Accept status in the request body
    current_user: dict = Depends(get_current_user)
):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can update room status")
    
    if status_update.status not in ["available", "occupied"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be 'available' or 'occupied'")
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE Rooms SET status = ? WHERE id = ?",
        (status_update.status, room_id)
    )
    conn.commit()
    conn.close()
    
    return {"message": "Room status updated successfully"}

@app.post("/api/reservations")
def create_reservation(reservation: ReservationCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get room price and calculate total price
        room = cursor.execute("SELECT price, status FROM Rooms WHERE id = ?", (reservation.room_id,)).fetchone()
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")

        if room["status"] != "available":
            raise HTTPException(status_code=400, detail="Room is not available for booking")

        # Calculate number of days
        try:
            check_in = datetime.strptime(reservation.check_in_date, "%Y-%m-%d")
            check_out = datetime.strptime(reservation.check_out_date, "%Y-%m-%d")
            if check_out <= check_in:
                 raise HTTPException(status_code=400, detail="Check-out date must be after check-in date")
            days = (check_out - check_in).days
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

        total_price = room["price"] * days

        # Create reservation with payment_status='pending'
        cursor.execute(
            """INSERT INTO Reservations 
            (user_id, room_id, check_in_date, check_out_date, total_price, status, payment_status) 
            VALUES (?, ?, ?, ?, ?, 'confirmed', 'pending')""",
            (current_user["id"], reservation.room_id, reservation.check_in_date, 
             reservation.check_out_date, total_price)
        )
        
        # Update room status to "occupied"
        cursor.execute(
            "UPDATE Rooms SET status = 'occupied' WHERE id = ?",
            (reservation.room_id,)
        )
        
        conn.commit()
        
        return {"message": "Reservation created successfully, pending payment"}
    except HTTPException as e:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log the error
        print(f"Error creating reservation: {e}")
        conn.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


# User-specific endpoints
@app.get("/api/reservations")
def get_reservations(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        if current_user["role"] == "admin":
            # Admin can see all reservations with user details
            query = """
                SELECT r.*, u.full_name as user_name, u.contact_number as user_phone, m.room_number 
                FROM Reservations r
                JOIN Users u ON r.user_id = u.id
                JOIN Rooms m ON r.room_id = m.id
                ORDER BY r.created_at DESC
            """
            reservations = cursor.execute(query).fetchall()
        else:
            # Regular users only see their own reservations
            query = """
                SELECT r.*, m.room_number 
                FROM Reservations r
                JOIN Rooms m ON r.room_id = m.id
                WHERE user_id = ?
                ORDER BY r.created_at DESC
            """
            reservations = cursor.execute(query, (current_user["id"],)).fetchall()
        
        # Convert SQLite Row objects to dictionaries for proper JSON serialization
        result = [dict(reservation) for reservation in reservations]
        
        return {"reservations": result}
    except Exception as e:
        print(f"Error fetching reservations: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve reservations")
    finally:
        conn.close()



@app.delete("/api/reservations/{reservation_id}")
def cancel_reservation(reservation_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Check if admin, if yes, allow cancellation of any reservation
        if current_user["role"] == "admin":
            reservation = cursor.execute(
                "SELECT * FROM Reservations WHERE id = ?", (reservation_id,)
            ).fetchone()
        else:
            # Regular users can only cancel their own reservations
            reservation = cursor.execute(
                "SELECT * FROM Reservations WHERE id = ? AND user_id = ?", 
                (reservation_id, current_user["id"])
            ).fetchone()
            
        if not reservation:
            raise HTTPException(status_code=404, detail="Reservation not found or you don't have permission")
            
        cursor.execute("UPDATE Reservations SET status = 'cancelled' WHERE id = ?", (reservation_id,))
        
        # Update room availability
        cursor.execute("UPDATE Rooms SET status = 'available' WHERE id = ?", (reservation["room_id"],))
        
        conn.commit()
        
        return {"message": "Reservation cancelled successfully"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error cancelling reservation: {e}")
        conn.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()



# Payment APIs
@app.post("/api/reservations/{reservation_id}/pay")
def pay_reservation(reservation_id: int, current_user: dict = Depends(get_current_user)):
    """
    Process payment for a reservation and update its payment_status to 'completed'
    """
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Find the reservation and verify it belongs to the current user (or user is admin)
        if current_user["role"] == "admin":
            reservation = cursor.execute(
                "SELECT * FROM Reservations WHERE id = ?", (reservation_id,)
            ).fetchone()
        else:
            reservation = cursor.execute(
                "SELECT * FROM Reservations WHERE id = ? AND user_id = ?", 
                (reservation_id, current_user["id"])
            ).fetchone()
            
        if not reservation:
            raise HTTPException(status_code=404, detail="Reservation not found or you don't have permission")
            
        if reservation["status"] == "cancelled":
            raise HTTPException(status_code=400, detail="Cannot pay for a cancelled reservation")
            
        if reservation["payment_status"] == "completed":
            raise HTTPException(status_code=400, detail="Payment already completed")
            
        # Generate a transaction ID - typically would come from payment processor
        transaction_id = str(uuid.uuid4())
        
        # Update reservation payment status
        cursor.execute(
            "UPDATE Reservations SET payment_status = 'completed' WHERE id = ?", 
            (reservation_id,)
        )
        
        # Create payment record
        cursor.execute(
            """INSERT INTO Payments 
            (reservation_id, amount, payment_method, transaction_id, status) 
            VALUES (?, ?, ?, ?, 'completed')""",
            (reservation_id, reservation["total_price"], "card", transaction_id)
        )
        
        conn.commit()
        return {
            "message": "Payment processed successfully", 
            "transaction_id": transaction_id,
            "amount": reservation["total_price"],
            "status": "completed"
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error processing payment: {e}")
        conn.rollback()
        raise HTTPException(status_code=500, detail="Failed to process payment")
    finally:
        conn.close()

@app.post("/api/payments")
def process_payment(payment: PaymentCreate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO Payments (reservation_id, amount, payment_method, transaction_id, status) VALUES (?, ?, ?, ?, 'completed')",
        (payment.reservation_id, payment.amount, payment.payment_method, payment.transaction_id)
    )
    conn.commit()
    conn.close()
    return {"message": "Payment processed successfully"}

@app.get("/api/payments")
def get_payments(reservation_id: int):
    conn = get_db()
    cursor = conn.cursor()
    payments = cursor.execute(
        "SELECT * FROM Payments WHERE reservation_id = ?", (reservation_id,)
    ).fetchall()
    conn.close()
    return {"payments": payments}

# Reviews system
@app.post("/api/reviews")
def create_review(review_data: dict, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO Reviews (user_id, room_id, rating, comment) VALUES (?, ?, ?, ?)",
        (current_user["id"], review_data["room_id"], review_data["rating"], review_data["comment"])  # assumes Reviews table exists
    )
    conn.commit()
    conn.close()
    return {"message": "Review submitted successfully"}

@app.get("/api/rooms/{room_id}/reviews")
def get_room_reviews(room_id: int):
    conn = get_db()
    cursor = conn.cursor()
    reviews = cursor.execute(
        """SELECT r.*, u.full_name as user_name FROM Reviews r
        JOIN Users u ON r.user_id = u.id
        WHERE r.room_id = ?""",
        (room_id,)
    ).fetchall()
    conn.close()
    return {"reviews": reviews}

@app.get("/api/admin/reports/bookings")
def get_booking_report(date_from: str, date_to: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    conn = get_db()
    cursor = conn.cursor()
    bookings = cursor.execute(
        """SELECT r.*, u.full_name, u.contact_number, rm.room_number, rm.room_type
        FROM Reservations r
        JOIN Users u ON r.user_id = u.id
        JOIN Rooms rm ON r.room_id = rm.id
        WHERE r.check_in_date >= ? AND r.check_out_date <= ?""",
        (date_from, date_to)
    ).fetchall()
    conn.close()
    return {"bookings": bookings}

# Run the app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)