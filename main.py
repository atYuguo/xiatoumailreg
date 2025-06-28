
import json
import logging
import os
import re
import secrets
import shutil
import datetime
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

# --- Configuration ---
MAILU_API_URL = os.getenv("MAILU_API_URL")
MAILU_API_TOKEN = os.getenv("MAILU_API_TOKEN")
MASTODON_BASE_URL = os.getenv("MASTODON_BASE_URL")
MASTODON_CLIENT_ID = os.getenv("MASTODON_CLIENT_ID")
MASTODON_CLIENT_SECRET = os.getenv("MASTODON_CLIENT_SECRET")
MASTODON_REDIRECT_URI = os.getenv("MASTODON_REDIRECT_URI")
SECRET_KEY = os.getenv("SECRET_KEY")
USER_STORAGE = os.getenv("USER_STORAGE", "100")
DOMAIN = os.getenv("DOMAIN")
WEBMAIL_URL = os.getenv("WEBMAIL_URL")

# --- FastAPI App ---
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Startup Recovery ---
@app.on_event("startup")
def startup_event():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    if not os.path.exists(REGISTRATION_LIST_FILE):
        logger.warning(f"{REGISTRATION_LIST_FILE} not found. Attempting to restore from backup.")
        backup_files = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith(os.path.basename(REGISTRATION_LIST_FILE))])
        if backup_files:
            latest_backup = os.path.join(BACKUP_DIR, backup_files[-1])
            shutil.copy2(latest_backup, REGISTRATION_LIST_FILE)
            logger.info(f"Restored {REGISTRATION_LIST_FILE} from {latest_backup}")
        else:
            logger.error("No backups found. Creating a new registration list.")
            save_json(REGISTRATION_LIST_FILE, {"registrations": []})
    else:
        try:
            load_json(REGISTRATION_LIST_FILE)
        except json.JSONDecodeError:
            logger.error(f"{REGISTRATION_LIST_FILE} is corrupted. Attempting to restore from backup.")
            backup_files = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith(os.path.basename(REGISTRATION_LIST_FILE))])
            if backup_files:
                latest_backup = os.path.join(BACKUP_DIR, backup_files[-1])
                shutil.copy2(latest_backup, REGISTRATION_LIST_FILE)
                logger.info(f"Restored {REGISTRATION_LIST_FILE} from {latest_backup}")
            else:
                logger.error("No backups found and the existing file is corrupted. A new file will be created on next registration.")


# --- Data Files ---
FORBIDDEN_NAMES_FILE = "forbidname.json"
REGISTRATION_LIST_FILE = "reglist.json"
BACKUP_DIR = "backups"

# --- Helper Functions ---
def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

def save_json(file_path, data):
    # Ensure backup directory exists
    os.makedirs(BACKUP_DIR, exist_ok=True)
    # Create a backup before writing
    if os.path.exists(file_path):
        backup_path = os.path.join(BACKUP_DIR, f"{os.path.basename(file_path)}.{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.bak")
        shutil.copy2(file_path, backup_path)
        logger.info(f"Created backup: {backup_path}")

    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

def get_user_from_session(request: Request):
    return request.session.get("user")


async def csrf_protect(request: Request):
    csrf_token = request.cookies.get("csrf_token")
    # Use .get("csrf_token", "") to avoid errors if the form is empty
    form_data = await request.form()
    form_csrf_token = form_data.get("csrf_token")
    if not csrf_token or not form_csrf_token or not secrets.compare_digest(csrf_token, form_csrf_token):
        logger.warning("CSRF token mismatch for request.")
        raise HTTPException(status_code=403, detail="CSRF token mismatch")
    return True

# --- Routes ---
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    user = get_user_from_session(request)
    if user:
        # Check if user is already registered
        reglist = load_json(REGISTRATION_LIST_FILE)
        for reg in reglist["registrations"]:
            if reg["mastodon_id"] == user["id"]:
                return templates.TemplateResponse("user.html", {"request": request, "mastodon_user": user, "email": reg["email"], "WEBMAIL_URL": WEBMAIL_URL})
        
        csrf_token = secrets.token_hex(16)
        response = templates.TemplateResponse("register.html", {"request": request, "mastodon_user": user, "DOMAIN": DOMAIN, "csrf_token": csrf_token})
        response.set_cookie(key="csrf_token", value=csrf_token, httponly=True)
        return response
        
    return templates.TemplateResponse("index.html", {"request": request, "DOMAIN": DOMAIN})

@app.get("/login")
async def login():
    auth_url = f"{MASTODON_BASE_URL}/oauth/authorize?client_id={MASTODON_CLIENT_ID}&redirect_uri={MASTODON_REDIRECT_URI}&response_type=code&scope=read:accounts"
    return RedirectResponse(auth_url)

@app.get("/callback")
async def callback(request: Request, code: str):
    # Exchange code for token
    token_url = f"{MASTODON_BASE_URL}/oauth/token"
    token_data = {
        "client_id": MASTODON_CLIENT_ID,
        "client_secret": MASTODON_CLIENT_SECRET,
        "redirect_uri": MASTODON_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code": code,
    }
    response = requests.post(token_url, data=token_data)
    if response.status_code != 200:
        return HTMLResponse("Error getting token from Mastodon.", status_code=400)
    
    access_token = response.json()["access_token"]

    # Get user info
    user_info_url = f"{MASTODON_BASE_URL}/api/v1/accounts/verify_credentials"
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        user_response = requests.get(user_info_url, headers=headers, timeout=5)
        user_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting user info from Mastodon: {e}")
        return templates.TemplateResponse("error.html", {"request": request, "error_message": "Could not retrieve your user information. Please try again later."})

    user_data = user_response.json()
    request.session["user"] = user_data
    return RedirectResponse("/")

@app.post("/register", dependencies=[Depends(csrf_protect)])
async def register(request: Request, username: str = Form(...), password: str = Form(...)):
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse("/login")

    # --- Username and Password Validation ---
    error_message = validate_user_input(username, password)
    if error_message:
        csrf_token = secrets.token_hex(16)
        response = templates.TemplateResponse("register.html", {"request": request, "mastodon_user": user, "DOMAIN": DOMAIN, "csrf_token": csrf_token, "error": error_message})
        response.set_cookie(key="csrf_token", value=csrf_token, httponly=True)
        return response

    clean_username = username.strip().lower()

    # Tier 1: Forbidden Names
    forbidden_names = load_json(FORBIDDEN_NAMES_FILE)
    if clean_username in forbidden_names or any(f.startswith(clean_username) for f in forbidden_names) or any(f.endswith(clean_username) for f in forbidden_names):
        csrf_token = secrets.token_hex(16)
        response = templates.TemplateResponse("register.html", {"request": request, "mastodon_user": user, "DOMAIN": DOMAIN, "csrf_token": csrf_token, "error": "This name is forbidden, please choose another name."})
        response.set_cookie(key="csrf_token", value=csrf_token, httponly=True)
        return response

    # Tier 2: Availability Check
    reglist = load_json(REGISTRATION_LIST_FILE)
    if any(reg["email"].startswith(f"{clean_username}@") for reg in reglist["registrations"]):
        csrf_token = secrets.token_hex(16)
        response = templates.TemplateResponse("register.html", {"request": request, "mastodon_user": user, "DOMAIN": DOMAIN, "csrf_token": csrf_token, "error": "This name is not available, please choose another name."})
        response.set_cookie(key="csrf_token", value=csrf_token, httponly=True)
        return response

    # --- Mailu API Integration ---
    email = f"{clean_username}@{DOMAIN}"
    mailu_headers = {"Authorization": f"Bearer {MAILU_API_TOKEN}"}
    mailu_payload = {
        "email": email,
        "raw_password": password,
        "quota_bytes": int(USER_STORAGE) * 1024 * 1024,  # Convert MB to Bytes
        "global_admin": False,
        "change_pw_next_login": False,
        "allow_spoofing": False,
    }
    
    # Tier 3: Create account in Mailu
    try:
        response = requests.post(f"{MAILU_API_URL}user", headers=mailu_headers, json=mailu_payload, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"Mailu API error when creating account for {clean_username}: {e}")
        csrf_token = secrets.token_hex(16)
        response = templates.TemplateResponse("register.html", {"request": request, "mastodon_user": user, "DOMAIN": DOMAIN, "csrf_token": csrf_token, "error": "Something went wrong, please try again later."})
        response.set_cookie(key="csrf_token", value=csrf_token, httponly=True)
        return response

    # Update registration list
    reglist["registrations"].append({
        "mastodon_id": user["id"],
        "email": email,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
    })
    save_json(REGISTRATION_LIST_FILE, reglist)
    logger.info(f"Successfully registered {email} for Mastodon user {user['id']}")

    return templates.TemplateResponse("user.html", {"request": request, "mastodon_user": user, "email": email, "success": f"Account created successfully! Login at {WEBMAIL_URL}"})

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")


@app.post("/validate-username")
async def validate_username(request: Request):
    data = await request.json()
    username = data.get("username", "")
    
    error_message = validate_user_input(username, "a_valid_password") # Password validation is not needed here
    if error_message and "Username" in error_message:
        return {"valid": False, "message": error_message}

    clean_username = username.strip().lower()
    
    # Tier 1: Forbidden Names
    forbidden_names = load_json(FORBIDDEN_NAMES_FILE)
    if not clean_username:
        return {"valid": False, "message": "Username cannot be empty."}
        
    if clean_username in forbidden_names or any(f.startswith(clean_username) for f in forbidden_names) or any(f.endswith(clean_username) for f in forbidden_names):
        return {"valid": False, "message": "This name is forbidden, please choose another name."}

    # Tier 2: Availability Check
    reglist = load_json(REGISTRATION_LIST_FILE)
    if any(reg["email"].startswith(f"{clean_username}@") for reg in reglist["registrations"]):
        return {"valid": False, "message": "This name is not available, please choose another name."}
        
    return {"valid": True, "message": "This name is available!"}


def validate_user_input(username, password):
    if len(username) < 3:
        return "Username must be at least 3 characters long."
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return "Username can only contain letters, numbers, and the characters: . - _"
    return None

@app.get("/health")
async def health_check():
    return {"status": "ok"}
