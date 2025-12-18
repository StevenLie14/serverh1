from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
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
    return {"message": "Welcome to Bilibili Anime API"}

@app.post("/register", response_model=UserResponse)
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
    
    return new_user

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db), response: Response = None):
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user.id})
    if response is not None:
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            samesite="lax",
            secure=False,
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user_from_cookie)):
    return current_user


@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logged out"}

@app.get("/anime", response_model=List[AnimeResponse])
def get_all_anime(db: Session = Depends(get_db)):
    anime_list = db.query(AnimeContent).order_by(AnimeContent.created_at.desc()).all()
    return anime_list

@app.get("/anime/{anime_id}", response_model=AnimeResponse)
def get_anime(anime_id: int, db: Session = Depends(get_db)):
    anime = db.query(AnimeContent).filter(AnimeContent.id == anime_id).first()
    if not anime:
        raise HTTPException(status_code=404, detail="Anime not found")
    return anime

@app.post("/anime", response_model=AnimeResponse)
def create_anime(
    anime: AnimeCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    new_anime = AnimeContent(**anime.dict())
    db.add(new_anime)
    db.commit()
    db.refresh(new_anime)
    return new_anime

@app.put("/anime/{anime_id}", response_model=AnimeResponse)
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
    return db_anime

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
    return {"message": "Anime deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)