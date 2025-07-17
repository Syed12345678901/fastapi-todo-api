from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordRequestForm
from database import get_db

from fastapi.security import OAuth2PasswordBearer
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.openapi.models import OAuthFlowPassword
from fastapi.security import OAuth2
from fastapi.openapi.utils import get_openapi
from auth import get_current_user, hash_password, verify_password, create_access_token



from database import SessionLocal, engine, Base
from models import User as DBUser  # Task model commented for now
# from models import Task as DBTask

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# ────────────────────────────────────────────────
# Database Dependency - in Database.py??
# ────────────────────────────────────────────────
# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# ────────────────────────────────────────────────
# Pydantic Schemas
# ────────────────────────────────────────────────

# Task Schemas (commented out until Task model is added back)
class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    completed: bool = False
    due_date: Optional[datetime] = None

class TaskResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    completed: bool
    due_date: Optional[datetime]
    created_at: datetime

    class Config:
        orm_mode = True

# User Schemas
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str

    class Config:
        orm_mode = True

# ────────────────────────────────────────────────
# Password Utilities - pasted the same in auth.py
# ────────────────────────────────────────────────
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# def hash_password(password: str) -> str:
#     return pwd_context.hash(password)

# def verify_password(plain_password: str, hashed_password: str) -> bool:
#     return pwd_context.verify(plain_password, hashed_password)

# ────────────────────────────────────────────────
# User Routes
# ────────────────────────────────────────────────
@app.post("/users/", response_model=UserResponse)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = hash_password(user.password)
    db_user = DBUser(
        username=user.username,
        email=user.email,
        hashed_password=hashed_pw
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/users/", response_model=List[UserResponse])
def get_users(db: Session = Depends(get_db)):
    users = db.query(DBUser).all()
    return users


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/protected")
def read_protected(token: str = Depends(oauth2_scheme)):
    return {"msg": "You are authenticated", "token": token}

@app.get("/me")
def read_current_user(current_user: DBUser = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email
    }


# ────────────────────────────────────────────────
# Task Routes (commented out until Task model is ready)
# ────────────────────────────────────────────────
"""
@app.post("/tasks/")
def create_task(task: TaskCreate, db: Session = Depends(get_db)):
    db_task = DBTask(**task.dict())
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

@app.get("/tasks/", response_model=List[TaskResponse])
def get_tasks(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    tasks = db.query(DBTask).offset(skip).limit(limit).all()
    return tasks

@app.get("/tasks/{task_id}", response_model=TaskResponse)
def get_task(task_id: int, db: Session = Depends(get_db)):
    task = db.query(DBTask).filter(DBTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task

@app.put("/tasks/{task_id}", response_model=TaskResponse)
def update_task(task_id: int, task_data: TaskCreate, db: Session = Depends(get_db)):
    task = db.query(DBTask).filter(DBTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    task.title = task_data.title
    task.description = task_data.description
    task.completed = task_data.completed
    task.due_date = task_data.due_date

    db.commit()
    db.refresh(task)
    return task

@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db)):
    task = db.query(DBTask).filter(DBTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    db.delete(task)
    db.commit()
    return {"message": f"Task {task_id} deleted"}

@app.patch("/tasks/{task_id}/toggle", response_model=TaskResponse)
def toggle_task(task_id: int, db: Session = Depends(get_db)):
    task = db.query(DBTask).filter(DBTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    task.completed = not task.completed
    db.commit()
    db.refresh(task)
    return task
"""
