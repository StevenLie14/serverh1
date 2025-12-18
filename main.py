from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, UploadFile, File, Form
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
import bcrypt
import jwt
import enum

from dotenv import load_dotenv
import os
import shutil
import uuid

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:password@localhost/bilibili")
PORT = int(os.getenv("PORT", "8000"))
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="Bilibili Anime API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Enums
class UserRole(str, enum.Enum):
    admin = "admin"
    user = "user"

class AnimeStatus(str, enum.Enum):
    completed = "Completed"
    ongoing = "Ongoing"
    upcoming = "Upcoming"

# SQLAlchemy Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.admin)
    created_at = Column(DateTime, default=datetime.utcnow)

class AnimeContent(Base):
    __tablename__ = "anime_content"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    image_url = Column(String(500))
    status = Column(Enum(AnimeStatus), default=AnimeStatus.upcoming)
    episodes = Column(Integer, nullable=True)
    duration = Column(Integer, nullable=True)  # in minutes
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic Models
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class AnimeCreate(BaseModel):
    title: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    status: AnimeStatus = AnimeStatus.upcoming
    episodes: Optional[int] = None
    duration: Optional[int] = None

class AnimeResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    image_url: Optional[str]
    status: str
    episodes: Optional[int]
    duration: Optional[int]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Standard API response wrapper
def make_response(code: int, message: str, data):
    return {"code": code, "message": message, "data": data}


# Serializers for SQLAlchemy models
def serialize_user(user: User):
    if not user:
        return None
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


def serialize_anime(anime: AnimeContent):
    if not anime:
        return None
    return {
        "id": anime.id,
        "title": anime.title,
        "description": anime.description,
        "image_url": anime.image_url,
        "status": anime.status.value if hasattr(anime.status, 'value') else str(anime.status),
        "episodes": anime.episodes,
        "duration": anime.duration,
        "created_at": anime.created_at.isoformat() if anime.created_at else None,
        "updated_at": anime.updated_at.isoformat() if anime.updated_at else None,
    }


# Exception handlers to return standardized responses
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content=make_response(exc.status_code, exc.detail, None))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content=make_response(422, "Validation error", exc.errors()))

# Password hashing
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# JWT token functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user


# New: read token from cookie for cookie-based auth
def get_token_from_cookie(request: Request) -> str:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


def get_current_user_from_cookie(token: str = Depends(get_token_from_cookie), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

def get_admin_user(current_user: User = Depends(get_current_user_from_cookie)):
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Only admins can perform this action")
    return current_user

# API Endpoints
@app.get("/")
def read_root():
    return JSONResponse(status_code=200, content=make_response(200, "Welcome to Bilibili Anime API", {"welcome": "Bilibili Anime API"}))

@app.post("/register")
def register(user: UserRegister, db: Session = Depends(get_db)):
    # Check if user exists
    db_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    
    if db_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Create new user
    hashed_pw = hash_password(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        password=hashed_pw
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return JSONResponse(status_code=201, content=make_response(201, "User registered successfully", serialize_user(new_user)))

@app.post("/login")
def login(
    email: str = Form(..., description="User email for login"),
    password: str = Form(..., description="User password"),
    db: Session = Depends(get_db)
):
    # Authenticate using email
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.id})
    content = make_response(200, "Login successful", {"access_token": access_token, "token_type": "bearer"})
    resp = JSONResponse(status_code=200, content=content)
    # set cookie on the response we actually return
    resp.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return resp

@app.get("/users/me")
def get_current_user_info(current_user: User = Depends(get_current_user_from_cookie)):
    return JSONResponse(status_code=200, content=make_response(200, "Current user retrieved", serialize_user(current_user)))


@app.post("/logout")
def logout():
    resp = JSONResponse(status_code=200, content=make_response(200, "Logged out", None))
    resp.delete_cookie("access_token")
    return resp

@app.get("/anime")
def get_all_anime(db: Session = Depends(get_db)):
    anime_list = db.query(AnimeContent).order_by(AnimeContent.created_at.desc()).all()
    return JSONResponse(status_code=200, content=make_response(200, "Anime list retrieved", [serialize_anime(a) for a in anime_list]))

@app.get("/anime/{anime_id}")
def get_anime(anime_id: int, db: Session = Depends(get_db)):
    anime = db.query(AnimeContent).filter(AnimeContent.id == anime_id).first()
    if not anime:
        raise HTTPException(status_code=404, detail="Anime not found")
    return JSONResponse(status_code=200, content=make_response(200, "Anime retrieved", serialize_anime(anime)))

@app.post("/anime")
def create_anime(
    title: str = Form(...),
    description: Optional[str] = Form(None),
    image: UploadFile = File(None),
    status: AnimeStatus = Form(AnimeStatus.upcoming),
    episodes: Optional[int] = Form(None),
    duration: Optional[int] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    image_url = None
    if image is not None:
        upload_dir = os.path.join(os.path.dirname(__file__), "static", "images")
        os.makedirs(upload_dir, exist_ok=True)
        filename = f"{uuid.uuid4().hex}_{image.filename}"
        file_path = os.path.join(upload_dir, filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        image_url = f"/static/images/{filename}"

    new_anime = AnimeContent(
        title=title,
        description=description,
        image_url=image_url,
        status=status,
        episodes=episodes,
        duration=duration,
    )
    db.add(new_anime)
    db.commit()
    db.refresh(new_anime)
    return JSONResponse(status_code=201, content=make_response(201, "Anime created", serialize_anime(new_anime)))

@app.put("/anime/{anime_id}")
def update_anime(
    anime_id: int,
    anime: AnimeCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    db_anime = db.query(AnimeContent).filter(AnimeContent.id == anime_id).first()
    if not db_anime:
        raise HTTPException(status_code=404, detail="Anime not found")
    
    for key, value in anime.dict().items():
        setattr(db_anime, key, value)
    
    db_anime.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_anime)
    return JSONResponse(status_code=200, content=make_response(200, "Anime updated", serialize_anime(db_anime)))

@app.delete("/anime/{anime_id}")
def delete_anime(
    anime_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    anime = db.query(AnimeContent).filter(AnimeContent.id == anime_id).first()
    if not anime:
        raise HTTPException(status_code=404, detail="Anime not found")
    
    db.delete(anime)
    db.commit()
    return JSONResponse(status_code=200, content=make_response(200, "Anime deleted successfully", None))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)