from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from typing import List, Any, Optional
import json
from json import JSONDecodeError
import aiofiles
import asyncio
from passlib.context import CryptContext
from errors import ValidationError, NotFoundError, raise_fastapi_exception, FileError, BaseAppError
import os
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer

load_dotenv()


app = FastAPI()


# File paths from environment variables
USERS_FILE = os.getenv("USERS_FILE", "users.json")
TASKS_FILE = os.getenv("TASKS_FILE", "tasks.json")

# Server configuration from environment variables
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 8000))


# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")



@app.exception_handler(BaseAppError)
async def handle_base_app_error(request, exc: BaseAppError):
    return JSONDecodeError(
        status_code=exc.status_code,
        content={"error": exc.message},
    )

@app.on_event("startup")
async def startup_event():
    await initializing_file(USERS_FILE, [])
    await initializing_file(TASKS_FILE, [])



# Initialize files
async def initializing_file(filename: str, default_data: Any) -> None:
    try:
        async with aiofiles.open(filename, mode="x") as file:
            await file.write(json.dumps(default_data, indent=4))
    except FileExistsError:
        pass

# Read from file
async def reading_from_file(filename: str) -> List[dict]:
    try:
        async with aiofiles.open(filename, mode='r') as file:
            content = await file.read()
            return json.loads(content)
    except FileNotFoundError:
        raise FileError(f"File {filename} not found.")
    except json.JSONDecodeError:
        raise FileError(f"File {filename} is corrupted and cannot be decoded.")

# Write to file
async def writing_to_file(filename: str, writing_data: List[dict]) -> None:
    try:
        async with aiofiles.open(filename, mode='w') as file:
            await file.write(json.dumps(writing_data, indent=4))
    except Exception as e:
        raise FileError(f"Failed to write to file {filename}: {str(e)}")


# Password
# Hash password
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Verify password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)



# BaseModels
class Users(BaseModel):
    user_id: int
    name: str
    email: str
    password: str

class UserCreate(BaseModel):
    name: str
    email: str
    password: str

class UserResponse(BaseModel):
    user_id: int
    name: str
    email: str

class Tasks(BaseModel):
    task_id: int
    title: str
    description: Optional[str] = None
    user_id: int

class TasksCreate(BaseModel):
    title: str
    description: Optional[str] = None
    user_id: int



# Validate users
def validate_user_data(name: str, email: str, password: str):
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("Name must be a non-empty string.")
    if "@" not in email or "." not in email.split("@")[-1]:
        raise ValidationError("Email must contain '@' and a valid domain.")
    if len(password) < 6:
        raise ValidationError("Password must be at least 6 characters long.")


# Validate tasks
async def validate_task_data(title: str, description: Optional[str], user_id: int):
    if not isinstance(title, str) or not title.strip():
        raise ValidationError("Title must be a non-empty string.")
    if description is not None and not isinstance(description, str):
        raise ValidationError("Description must be a string if provided.")
    user_data = await reading_from_file(USERS_FILE)
    if not any(u["user_id"] == user_id for u in user_data):
        raise NotFoundError("User ID must refer to an existing user.")



# Middleware for error logging
@app.middleware("http")
async def log_errors(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as e:
        return JSONDecodeError(
            status_code=500,
            content={"error": "Internal Server Error", "details": str(e)},
        )


# User endpoints
# Getting all users
@app.get("/users", response_model=List[UserResponse])
async def getting_all_users(skip: int = 0, limit: int = 10):
    user_data = await reading_from_file(USERS_FILE)
    return [UserResponse(**user) for user in user_data[skip: skip + limit]]


# Getting user by ID
@app.get("/users/{user_id}", response_model=UserResponse)
async def getting_user_by_id(user_id: int):
    user_data = await reading_from_file(USERS_FILE)
    user = next((u for u in user_data if u["user_id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User with the given ID not found.")
    return UserResponse(**user)


# Adding new user
@app.post("/users", response_model=UserResponse)
async def add_new_user(user: UserCreate):
    try:
        validate_user_data(user.name, user.email, user.password)
        user_data = await reading_from_file(USERS_FILE)
        if any(u["email"] == user.email for u in user_data):
            raise ValidationError("A user with this email already exists.")
        new_user_id = len(user_data) + 1
        hashed_password = hash_password(user.password)
        new_user = {"user_id": new_user_id, "name": user.name, "email": user.email, "password": hashed_password}
        user_data.append(new_user)
        await writing_to_file(USERS_FILE, user_data)
        return UserResponse(**new_user)
    except BaseAppError as e:
        raise_fastapi_exception(e)


# Editing user by ID
@app.put("/users/{user_id}", response_model=UserResponse)
async def updating_user(user_id: int, updated_user: UserCreate):
    validate_user_data(updated_user.name, updated_user.email, updated_user.password)
    user_data = await reading_from_file(USERS_FILE)
    user = next((u for u in user_data if u["user_id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User with the given ID not found.")
    user.update({"name": updated_user.name, "email": updated_user.email, "password": hash_password(updated_user.password)})
    await writing_to_file(USERS_FILE, user_data)
    return UserResponse(**user)


# Deleting user by ID
@app.delete("/users/{user_id}")
async def delete_user(user_id: int):
    user_data = await reading_from_file(USERS_FILE)
    user = next((u for u in user_data if u["user_id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User with the given ID not found.")
    user_data.remove(user)
    await writing_to_file(USERS_FILE, user_data)
    return {"message": "User has been removed."}




# Task endpoints
# Getting all tasks
@app.get("/tasks", response_model=List[Tasks])
async def getting_all_tasks(skip: int = 0, limit: int = 10):
    tasks_data = await reading_from_file(TASKS_FILE)
    return [Tasks(**task) for task in tasks_data[skip: skip + limit]]


# Getting task by ID
@app.get("/tasks/{task_id}", response_model=Tasks)
async def getting_task_by_id(task_id: int):
    tasks_data = await reading_from_file(TASKS_FILE)
    task = next((t for t in tasks_data if t["task_id"] == task_id), None)
    if not task:
        raise HTTPException(status_code=404, detail="Task with the given ID not found.")
    return Tasks(**task)


# Adding new task
@app.post("/tasks", response_model=Tasks)
async def adding_task(task: TasksCreate):
    await validate_task_data(task.title, task.description, task.user_id)
    tasks_data = await reading_from_file(TASKS_FILE)
    if any(t["title"] == task.title and t["user_id"] == task.user_id for t in tasks_data):
        raise HTTPException(status_code=409, detail="A task with this title already exists for this user.")
    new_task_id = len(tasks_data) + 1
    new_task = {"task_id": new_task_id, "title": task.title, "description": task.description, "user_id": task.user_id}
    tasks_data.append(new_task)
    await writing_to_file(TASKS_FILE, tasks_data)
    return Tasks(**new_task)



# Editing task by ID
@app.put("/tasks/{task_id}", response_model=Tasks)
async def updating_task(task_id: int, updated_task: TasksCreate):
    await validate_task_data(updated_task.title, updated_task.description, updated_task.user_id)
    tasks_data = await reading_from_file(TASKS_FILE)
    task = next((t for t in tasks_data if t["task_id"] == task_id), None)
    if not task:
        raise HTTPException(status_code=404, detail="Task with the given ID not found.")
    task.update({"title": updated_task.title, "description": updated_task.description, "user_id": updated_task.user_id})
    await writing_to_file(TASKS_FILE, tasks_data)
    return Tasks(**task)


# Deletig user by ID
@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int):
    tasks_data = await reading_from_file(TASKS_FILE)
    task = next((t for t in tasks_data if t["task_id"] == task_id), None)
    if not task:
        raise HTTPException(status_code=404, detail="Task with the given ID not found.")
    tasks_data.remove(task)
    await writing_to_file(TASKS_FILE, tasks_data)
    return {"message": "Task has been removed."}



# Registration
@app.post("/register")
async def registration(user: UserCreate):
    user_data = await reading_from_file(USERS_FILE)
    for existing_user in user_data:
        if existing_user["email"] == user.email:
            raise HTTPException(status_code=409, detail="This email is already used.")
    new_user_id = len(user_data) + 1
    hashed_password = hash_password(user.password)
    new_user = {"user_id": new_user_id, "name": user.name, "email": user.email, "password": hashed_password}
    user_data.append(new_user)
    await writing_to_file(USERS_FILE, user_data)
    return {"message": "User registered successfully"}


# Login
@app.post("/login")
async def logging(user_email: str, user_password: str):
    user_data = await reading_from_file(USERS_FILE)
    for existing_user in user_data:
        if existing_user['email'] == user_email and verify_password(user_password, existing_user['password']):
            return {"message": "Login successful"}
    raise HTTPException(status_code=404, detail="Invalid email or password")
