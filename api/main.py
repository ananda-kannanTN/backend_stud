from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import mysql.connector
from starlette.middleware.cors import CORSMiddleware
import jwt
from datetime import datetime, timedelta
from mangum import Mangum

# ---------- App Setup ----------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ---------- JWT Config ----------
SECRET_KEY = "secretkey"   # 🔑 change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5

# security
security = HTTPBearer()

# ---------- Token Utils ----------
def create_token(email: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    return verify_token(credentials.credentials)

# ---------- Database Connection ----------
def get_db_connection():
    return mysql.connector.connect(
        host="srv1834.hstgr.io",
        user="u651328475_batch_11",
        password="Batch_11",
        database="u651328475_batch_11",
    )

# ---------- Pydantic Models ----------
class LoginRequest(BaseModel):
    email: str
    password: str

class OTPRequest(BaseModel):
    email: str
    code: str

class ResetPasswordRequest(BaseModel):
    email: str
    new_password: str

class Register(BaseModel):
    reg: int
    name: str
    degree: str
    specilization: str
    address: str
    phone_no: str

# ---------- Root Endpoint ----------
@app.get("/")
def home():
    return {"message": "Backend running successfully 🚀"}

# ---------- Auth APIs ----------
@app.post("/login")
def login_user(data: LoginRequest):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM ak_admin WHERE email=%s AND password=%s", (data.email, data.password))
    user = cursor.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(user["email"])
    return {"access_token": token, "token_type": "bearer"}

PRIVATE_CODE = "leo"

@app.post("/send-otp")
def send_otp(data: OTPRequest):
    if data.code != PRIVATE_CODE:
        raise HTTPException(status_code=400, detail="Invalid Code. OTP not sent!")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM ak_admin WHERE email=%s", (data.email,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=404, detail="Email not registered!")

    return {"success": True, "message": "OTP Verified. Proceed to Reset Password"}

@app.post("/reset-password")
def reset_password(data: ResetPasswordRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ak_admin WHERE email=%s", (data.email,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Email not registered!")

    cursor.execute("UPDATE ak_admin SET password=%s WHERE email=%s", (data.new_password, data.email))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Password changed successfully"}

# ---------- Student CRUD APIs ----------
@app.get("/stud_data")
def get_all_users(token: str = Depends(auth)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM ak_student")
    result = cursor.fetchall()
    conn.close()
    return result

@app.post("/insert_data")
def register_user(user: Register, token: str = Depends(auth)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO ak_student (reg, name, degree, specilization, address, phone_no) VALUES (%s,%s,%s,%s,%s,%s)",
        (user.reg, user.name, user.degree, user.specilization, user.address, user.phone_no)
    )
    conn.commit()
    conn.close()
    return {"status": "success", "message": "User registered successfully"}

@app.delete("/del/{reg_id}")
def delete_user(reg_id: int, token: str = Depends(auth)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ak_student WHERE reg=%s", (reg_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    cursor.execute("DELETE FROM ak_student WHERE reg=%s", (reg_id,))
    conn.commit()
    conn.close()
    return {"message": f"User with reg {reg_id} deleted successfully"}

@app.put("/update/{reg_id}")
def update_user(reg_id: int, user: Register, token: str = Depends(auth)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ak_student WHERE reg=%s", (reg_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    cursor.execute(
        "UPDATE ak_student SET name=%s, degree=%s, specilization=%s, address=%s, phone_no=%s WHERE reg=%s",
        (user.name, user.degree, user.specilization, user.address, user.phone_no, reg_id)
    )
    conn.commit()
    conn.close()
    return {"status": "success", "message": "User updated successfully"}

# ---------- For Vercel ----------
handler = Mangum(app)
