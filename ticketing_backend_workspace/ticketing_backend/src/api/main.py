"""
FastAPI backend for Ticketing System.

Features:
- User registration and login (JWT authentication)
- Ticket CRUD operations (creation, update, delete, view)
- Ticket status tracking
- Administrative dashboard endpoints
- Ticket listing and detail views

OpenAPI docs available at /docs.

The backend is structured into routers for authentication, users, and tickets for scalability.
"""

from fastapi import FastAPI, Depends, HTTPException, status, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Literal
from datetime import datetime, timedelta
from jose import JWTError, jwt


# TEMPORARY: In-memory stores. Replace with DB/database session later.
fake_users_db = {}
fake_tickets_db = {}


# --- JWT Settings (TEMP SECRETS, replace in prod) ---
SECRET_KEY = "supersecretkey"  # In prod, use os.environ
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


# --- Models ---


class UserBase(BaseModel):
    email: EmailStr = Field(..., description="User's Email Address")
    full_name: str = Field(..., description="Full name of user")
    is_admin: bool = Field(False, description="Is this user an administrator?")


class UserCreate(UserBase):
    password: str = Field(..., min_length=6, description="Password")


class UserRead(UserBase):
    id: int = Field(..., description="User ID")


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None
    is_admin: Optional[bool] = False


class TicketBase(BaseModel):
    title: str = Field(..., description="Ticket title")
    description: str = Field(..., description="Ticket description")
    priority: Optional[Literal["low", "medium", "high"]] = Field(
        "medium", description="Ticket priority"
    )
    status: Optional[Literal["open", "in_progress", "resolved", "closed"]] = Field(
        "open", description="Status of the ticket"
    )


class TicketCreate(TicketBase):
    pass


class TicketUpdate(BaseModel):
    title: Optional[str]
    description: Optional[str]
    priority: Optional[Literal["low", "medium", "high"]]
    status: Optional[Literal["open", "in_progress", "resolved", "closed"]]


class TicketRead(TicketBase):
    id: int = Field(..., description="Ticket ID")
    created_at: datetime = Field(..., description="Time ticket was created")
    updated_at: datetime = Field(..., description="Last update time")
    owner_id: int = Field(..., description="User ID of ticket owner")


# --- Auth Utilities ---


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates a JWT access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# PUBLIC_INTERFACE
def verify_password(plain_password, stored_password):
    """Password verification placeholder (plaintext; use hash in prod)"""
    return plain_password == stored_password


# PUBLIC_INTERFACE
def get_user(email: str):
    """Retrieve user from fake database."""
    return fake_users_db.get(email)


# PUBLIC_INTERFACE
def authenticate_user(email: str, password: str):
    """Authenticate user credentials."""
    user = get_user(email)
    if not user or not verify_password(password, user["password"]):
        return None
    return user


# PUBLIC_INTERFACE
def get_current_user(token: str = Depends(oauth2_scheme)) -> UserRead:
    """Dependency to retrieve current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user(email=token_data.email)
    if user is None:
        raise credentials_exception
    return UserRead(
        id=user["id"],
        email=user["email"],
        full_name=user["full_name"],
        is_admin=user["is_admin"],
    )


# PUBLIC_INTERFACE
def get_current_admin_user(current_user: UserRead = Depends(get_current_user)):
    """Dependency for admin-only access."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# --- Routers ---


# Auth Router
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


# PUBLIC_INTERFACE
@auth_router.post(
    "/register",
    response_model=UserRead,
    summary="Register new user",
    description="Create new user account",
)
def register_user(user: UserCreate):
    if user.email in fake_users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = len(fake_users_db) + 1
    fake_users_db[user.email] = {
        "id": user_id,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": False,
        "password": user.password,  # Use hashed passwords in prod
    }
    return UserRead(
        id=user_id, email=user.email, full_name=user.full_name, is_admin=False
    )


# PUBLIC_INTERFACE
@auth_router.post(
    "/token",
    response_model=Token,
    summary="Login to receive JWT",
    description="Authenticate user and obtain access token",
)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token(
        data={"sub": user["email"], "is_admin": user.get("is_admin", False)}
    )
    return {"access_token": access_token, "token_type": "bearer"}


# User Router
user_router = APIRouter(prefix="/users", tags=["Users"])


# PUBLIC_INTERFACE
@user_router.get(
    "/me",
    response_model=UserRead,
    summary="Get current user",
    description="Retrieve information about the current user",
)
def read_me(current_user: UserRead = Depends(get_current_user)):
    return current_user


# --- Ticket Router ---
ticket_router = APIRouter(prefix="/tickets", tags=["Tickets"])


# PUBLIC_INTERFACE
@ticket_router.post(
    "/",
    response_model=TicketRead,
    summary="Create a new ticket",
    description="Create and submit a new ticket",
)
def create_ticket(ticket: TicketCreate, current_user: UserRead = Depends(get_current_user)):
    ticket_id = len(fake_tickets_db) + 1
    now = datetime.utcnow()
    fake_tickets_db[ticket_id] = {
        "id": ticket_id,
        "title": ticket.title,
        "description": ticket.description,
        "priority": ticket.priority,
        "status": ticket.status,
        "created_at": now,
        "updated_at": now,
        "owner_id": current_user.id,
    }
    return TicketRead(**fake_tickets_db[ticket_id])


# PUBLIC_INTERFACE
@ticket_router.get(
    "/",
    response_model=List[TicketRead],
    summary="List tickets",
    description="List tickets for user; admins see all tickets",
)
def list_tickets(current_user: UserRead = Depends(get_current_user)):
    if current_user.is_admin:
        return [TicketRead(**t) for t in fake_tickets_db.values()]
    else:
        return [
            TicketRead(**t)
            for t in fake_tickets_db.values()
            if t["owner_id"] == current_user.id
        ]


# PUBLIC_INTERFACE
@ticket_router.get(
    "/{ticket_id}",
    response_model=TicketRead,
    summary="Get ticket details",
    description="View ticket detail by ID",
)
def get_ticket(ticket_id: int, current_user: UserRead = Depends(get_current_user)):
    ticket = fake_tickets_db.get(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    if ticket["owner_id"] != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
    return TicketRead(**ticket)


# PUBLIC_INTERFACE
@ticket_router.put(
    "/{ticket_id}",
    response_model=TicketRead,
    summary="Update a ticket",
    description="Update ticket fields if owner or admin",
)
def update_ticket(
    ticket_id: int,
    update: TicketUpdate,
    current_user: UserRead = Depends(get_current_user),
):
    ticket = fake_tickets_db.get(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    if ticket["owner_id"] != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
    update_data = update.model_dump(exclude_unset=True)
    for k, v in update_data.items():
        ticket[k] = v
    ticket["updated_at"] = datetime.utcnow()
    fake_tickets_db[ticket_id] = ticket
    return TicketRead(**ticket)


# PUBLIC_INTERFACE
@ticket_router.delete(
    "/{ticket_id}",
    summary="Delete a ticket",
    description="Delete a ticket by ID if owner or admin",
)
def delete_ticket(ticket_id: int, current_user: UserRead = Depends(get_current_user)):
    ticket = fake_tickets_db.get(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    if ticket["owner_id"] != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
    del fake_tickets_db[ticket_id]
    return {"detail": "Ticket deleted"}


# --- Admin Endpoints ---


admin_router = APIRouter(prefix="/admin", tags=["Admin"])


# PUBLIC_INTERFACE
@admin_router.get(
    "/users",
    response_model=List[UserRead],
    summary="List all users (admin)",
    description="Administrative endpoint to list all users",
)
def list_all_users(admin: UserRead = Depends(get_current_admin_user)):
    return [
        UserRead(
            id=u["id"], email=u["email"], full_name=u["full_name"], is_admin=u["is_admin"]
        )
        for u in fake_users_db.values()
    ]


# PUBLIC_INTERFACE
@admin_router.get(
    "/tickets",
    response_model=List[TicketRead],
    summary="List all tickets (admin)",
    description="Administrative endpoint to list all tickets in the system",
)
def admin_list_all_tickets(admin: UserRead = Depends(get_current_admin_user)):
    return [TicketRead(**t) for t in fake_tickets_db.values()]


# --- Application Instance & Tag Groupings ---


openapi_tags = [
    {"name": "Authentication", "description": "Registration, login, JWT access"},
    {"name": "Users", "description": "User profile and info"},
    {"name": "Tickets", "description": "Ticket operations"},
    {"name": "Admin", "description": "Administrative actions (admins only)"},
]


app = FastAPI(
    title="Ticketing System API",
    description=(
        "Web-based API for support/issue ticket management including user registration, "
        "authentication, ticket CRUD, and administrative features."
    ),
    version="0.1.0",
    openapi_tags=openapi_tags,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Register routers
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(ticket_router)
app.include_router(admin_router)


# --- Health Check ---


@app.get("/", tags=["Health"])
def health_check():
    """Check API health status"""
    return {"message": "Healthy"}
