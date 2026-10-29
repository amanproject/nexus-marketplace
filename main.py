import os
from dotenv import load_dotenv

# Load the hidden .env file
load_dotenv()

from fastapi import Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import smtplib
import random
from email.message import EmailMessage

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from sqlmodel import Field, Session, SQLModel, create_engine, select

from passlib.context import CryptContext

# --- THE EMAIL ENGINE ---
# Pull the secrets from the hidden .env file!
SECRET_KEY = os.getenv("SECRET_KEY")
MY_EMAIL = os.getenv("MY_EMAIL")
MY_APP_PASSWORD = os.getenv("MY_APP_PASSWORD")
ALGORITHM = "HS256"

def send_otp_email(receiver_email: str, otp_code: str):
    msg = EmailMessage()
    msg.set_content(f"Welcome to the Store!\n\nYour secret verification code is: {otp_code}\n\nDo not share this with anyone.")
    msg['Subject'] = 'Your Store Verification Code'
    msg['From'] = MY_EMAIL
    msg['To'] = receiver_email

    # Connect to Google's secure servers and fire the email
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(MY_EMAIL, MY_APP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"Success: OTP sent to {receiver_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")
        print("*" * 50)
        print(f"DEVELOPER FALLBACK - OTP FOR {receiver_email} IS: {otp_code}")
        print("*" * 50)

# Set up the Bcrypt hashing engine
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Tool 1: Takes a plain text password and scrambles it
def get_password_hash(password):
    return pwd_context.hash(password)

# Tool 2: Checks if a typed password matches a scrambled one
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

import jwt
from datetime import datetime, timedelta, timezone


security = HTTPBearer()

# The Security Guard Function
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        # Try to read the badge using our secret key
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid badge")
        return {"username": username, "role": role}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Badge has expired (Time to log in again)")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Fake or tampered badge detected!")
    
# The Badge Printer Function
def create_access_token(data: dict):
    to_encode = data.copy()
    # The badge automatically destroys itself after 2 hours for security
    expire = datetime.now(timezone.utc) + timedelta(hours=2)
    to_encode.update({"exp": expire})
    
    # Cryptographically seal the badge using your SECRET_KEY
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

class Product(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    name: str
    price: int
    owner: str  #who owns this product
    mrp: int             
    discount_price: int  
    stock_quantity: int

class User(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    username: str
    email: str                 # NEW: We need to know where to send the email!
    password: str
    role: str = "buyer" 
    is_verified: bool = False  # NEW: Accounts are locked by default
    otp_code: str = ""         # NEW: Memory slot to store their 6-digit code

class LoginRequest(SQLModel):
    username: str
    password: str

# Pull the Neon Cloud Database URL from the hidden .env vault
DATABASE_URL = os.getenv("DATABASE_URL")

# Build the cloud engine.
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SQLModel.metadata.create_all(engine)

app = FastAPI()

# Initialize the Circuit Breaker tracking IP addresses
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/")
def home():
    return FileResponse("index.html")

@app.get("/products")
def get_products():
    with Session(engine) as session:
        return session.exec(select(Product)).all()

@app.post("/products")
def create_product(product: Product, current_user: dict = Depends(get_current_user)):
    # 1. Check if the user's badge says they are a seller
    if current_user["role"] != "seller":
        raise HTTPException(status_code=403, detail="Access Denied: Only sellers can list products.")
        
    with Session(engine) as session:
        # 2. OVERRIDE: Ignore what the HTML sent. Force the owner to be the verified name on the badge!
        product.owner = current_user["username"] 
        
        session.add(product)
        session.commit()
        return {"message": "Product created securely!"}

@app.delete("/products/{product_id}")
def delete_product(product_id: int):
    with Session(engine) as session:
        product = session.get(Product, product_id)
        if product:
            session.delete(product)
            session.commit()
        return {"message": "Product deleted!"}

# A small class to receive OTP verification requests
class OTPRequest(SQLModel):
    username: str
    otp: str

@app.post("/users")
@limiter.limit("3/minute")  # SHIELD: Max 3 emails/registrations per minute
def create_user(request: Request, user: User):
    with Session(engine) as session:

        # --- THE NEW FIX: Block Duplicate Usernames ---
        statement = select(User).where(User.username == user.username)
        existing_user = session.exec(statement).first()
        
        if existing_user:
            return {"error": "Username already taken! Please choose another one."}
        # ----------------------------------------------

        email_statement = select(User).where(User.email == user.email)
        existing_email = session.exec(email_statement).first()
        if existing_email:
            return {"error": "Email is already registered! Please log in or use a different email."}

        # 1. Generate a random 6-digit number
        generated_otp = str(random.randint(100000, 999999))
        user.otp_code = generated_otp
        
        # 2. Scramble the password
        user.password = get_password_hash(user.password)
        
        # 3. Save to database
        session.add(user)
        session.commit()
        
        # 4. Fire the email engine!
        send_otp_email(user.email, generated_otp)
        
        return {"message": f"Account created! Please check {user.email} for your OTP."}

@app.post("/verify")
def verify_account(request: OTPRequest):
    with Session(engine) as session:
        statement = select(User).where(User.username == request.username)
        user = session.exec(statement).first()
        
        # If the user exists and the OTP matches perfectly:
        if user and user.otp_code == request.otp:
            user.is_verified = True
            user.otp_code = ""  # Destroy the OTP after it is used
            session.add(user)
            session.commit()
            return {"message": "Verification successful! You can now log in."}
            
        return {"error": "Invalid username or OTP."}

@app.post("/login")
@limiter.limit("5/minute")  # SHIELD: Max 5 password guesses per minute
def login_user(request: Request, payload: LoginRequest): 
    with Session(engine) as session:
        # NOTICE: We changed 'request.username' to 'payload.username' here
        statement = select(User).where(User.username == payload.username)
        user_in_db = session.exec(statement).first() 

        # NOTICE: We changed 'request.password' to 'payload.password' here
        if user_in_db and verify_password(payload.password, user_in_db.password):
            
            # THE NEW LOCK: Block them if they haven't verified their email!
            if not user_in_db.is_verified:
                return {"error": "Account locked. Please verify your email OTP first."}
            
            # (The rest of your JWT printing logic stays exactly the same)
            badge_data = {"sub": user_in_db.username, "role": user_in_db.role}
            digital_badge = create_access_token(data=badge_data)
            
            # Hand the badge back to the web browser
            return {
                "message": "Login successful", 
                "access_token": digital_badge, 
                "role": user_in_db.role
            }
        else:
            return {"error": "Invalid username or password"}

@app.get("/users")
def get_users():
    with Session(engine) as session:
        statement = select(User)
        users = session.exec(statement).all()
        
        # We manually package the data to include the email, 
        # but strictly EXCLUDE passwords and OTPs for security!
        safe_users = []
        for u in users:
            safe_users.append({
                "id": u.id,
                "username": u.username,
                "email": u.email,      # THE FIX: Now Python sends the email!
                "role": u.role
            })
            
        return safe_users

@app.delete("/users/{user_id}")
def delete_user(user_id: int):
    with Session(engine) as session:
        user = session.get(User, user_id)
        if user:
            session.delete(user)
            session.commit()
        return {"message": "User deleted"}

# 1. A tiny class to receive the manual stock changes from the seller
class StockUpdate(SQLModel):
    new_stock: int

# 2. SELLER POWER: Let sellers manually fix defective/damaged inventory
@app.put("/products/{product_id}/stock")
def update_stock(product_id: int, request: StockUpdate):
    with Session(engine) as session:
        product = session.get(Product, product_id)
        if product:
            product.stock_quantity = request.new_stock
            session.commit()
            return {"message": "Stock updated successfully"}
        return {"error": "Product not found"}

# 3. CHECKOUT POWER: Receive a list of bought items and reduce their stock by 1
@app.post("/checkout")
def process_checkout(product_ids: list[int]):
    with Session(engine) as session:
        for pid in product_ids:
            product = session.get(Product, pid)
            # Ensure the product exists and actually has stock left before deducting
            if product and product.stock_quantity > 0:
                product.stock_quantity -= 1
                session.add(product)
        session.commit()
        return {"message": "Inventory deducted"}