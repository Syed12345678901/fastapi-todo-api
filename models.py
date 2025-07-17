from sqlalchemy import Column, Integer, String, Boolean, DateTime
# from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from database import Base

#Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

# class Task(Base):
#     __tablename__ = "tasks"

#     id = Column(Integer, primary_key=True, index=True)
#     title = Column(String, index=True)
#     description = Column(String, nullable=True)
#     completed = Column(Boolean, default=False)
#     due_date = Column(DateTime, nullable=True)
#     created_at = Column(DateTime, default=datetime.utcnow)

