
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
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

load_dotenv()

# --- Configuration ---
MAILU_API_URL = os.getenv("MAILU_API_URL")
MAILU_API_TOKEN = os.getenv("MAILU_API_TOKEN")
MASTODON_BASE_URL = os.getenv("MASTODON_BASE_URL")
MASTODON_CLIENT_ID = os.getenv("MASTODON_CLIENT_ID")
MASTODON_CLIENT_SECRET = os.getenv("MASTODON_CLIENT_SECRET")
MASTODON_REDIRECT_URI = os.getenv("MASTODON_REDIRECT_URI")
MASTODON_DOMAIN = os.getenv("MASTODON_DOMAIN")
SECRET_KEY = os.getenv("SECRET_KEY")
USER_STORAGE = os.getenv("USER_STORAGE", "100")
DOMAIN = os.getenv("DOMAIN")
WEBMAIL_URL = os.getenv("WEBMAIL_URL")

# --- FastAPI App ---
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Allow form-action to self and the Mastodon domain
        csp_policy = f"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; form-action 'self' {MASTODON_DOMAIN}; frame-ancestors 'none';"
        response.headers["Content-Security-Policy"] = csp_policy
        return response

app.add_middleware(CSPMiddleware)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- Language Settings ---
SUPPORTED_LANGUAGES = ["en", "zh"]
DEFAULT_LANGUAGE = "en"

TRANSLATIONS = {
    "en": {
        "Could not retrieve your user information. Please try again later.": "Could not retrieve your user information. Please try again later.",
        "This name is forbidden, please choose another name.": "This name is forbidden, please choose another name.",
        "This name is not available, please choose another name.": "This name is not available, please choose another name.",
        "You have already registered an account.": "You have already registered an account.",
        "Something went wrong, please try again later.": "Something went wrong, please try again later.",
        "Username must be at least 3 characters long.": "Username must be at least 3 characters long.",
        "Password must be at least 8 characters long.": "Password must be at least 8 characters long.",
        "Username must start with a letter and can only contain letters, numbers,<br>and the characters: . - _": "Username must start with a letter and can only contain letters, numbers and the characters: . - _",
        "Username cannot be empty.": "Username cannot be empty.",
        "This name is available!": "This name is available!",
        "Account created successfully! Login at {WEBMAIL_URL}": "Account created successfully! Login at {WEBMAIL_URL}"
    },
    "zh": {
        "Could not retrieve your user information. Please try again later.": "无法获取您的用户信息。请稍后再试。",
        "This name is forbidden, please choose another name.": "此名称被禁止使用，请选择其他名称。",
        "This name is not available, please choose another name.": "此名称不可用，请选择其他名称。",
        "You have already registered an account.": "您已经注册了一个帐户。",
        "Something went wrong, please try again later.": "出错了，请稍后再试。",
        "Username must be at least 3 characters long.": "用户名必须至少为 3 个字符长。",
        "Password must be at least 8 characters long.": "密码必须至少为 8 个字符长。",
        "Username must start with a letter and can only contain letters, numbers,<br>and the characters: . - _": "用户名必须以字母开头，只能包含字母、数字和以下字符: . - _",
        "Username cannot be empty.": "用户名不能为空。",
        "This name is available!": "这个名字可用！",
        "Account created successfully! Login at {WEBMAIL_URL}": "帐户创建成功！在 {WEBMAIL_URL} 登录"
    }
}

def get_locale(request: Request):
    # 1. Check query parameter (for explicit language switching)
    lang_param = request.query_params.get('lang')
    if lang_param in SUPPORTED_LANGUAGES:
        request.session["lang"] = lang_param  # Store in session
        return lang_param

    # 2. Check session (for persistent language)
    if "lang" in request.session and request.session["lang"] in SUPPORTED_LANGUAGES:
        return request.session["lang"]

    # 3. Check Accept-Language header (for initial detection)
    accept_language = request.headers.get('accept-language')
    if accept_language:
        languages = [lang.split(';')[0] for lang in accept_language.split(',')]
        for lang in languages:
            if lang.startswith("zh"):
                request.session["lang"] = "zh"
                return "zh"
            elif lang.startswith("en"):
                request.session["lang"] = "en"
                return "en"
    
    # 4. Default language
    request.session["lang"] = DEFAULT_LANGUAGE
    return DEFAULT_LANGUAGE

def get_template(request: Request, name: str):
    locale = get_locale(request)
    return f"{locale}/{name}"

def _(request: Request, text: str, **kwargs):
    locale = get_locale(request)
    return TRANSLATIONS.get(locale, TRANSLATIONS[DEFAULT_LANGUAGE]).get(text, text).format(**kwargs)

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


def set_error_message(request: Request, message: str):
    request.session["error_message"] = message

def get_error_message(request: Request):
    return request.session.pop("error_message", None)


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
    success_message = request.session.pop("success_message", None)
    error_message = get_error_message(request)
    if user:
        # Check if user is already registered
        reglist = load_json(REGISTRATION_LIST_FILE)
        for reg in reglist["registrations"]:
            if reg["mastodon_id"] == user["id"]:
                return templates.TemplateResponse(get_template(request, "user.html"), {"request": request, "mastodon_user": user, "email": reg["email"], "WEBMAIL_URL": WEBMAIL_URL, "success": success_message})
        
        csrf_token = secrets.token_hex(16)
        response = templates.TemplateResponse(get_template(request, "register.html"), {"request": request, "mastodon_user": user, "DOMAIN": DOMAIN, "csrf_token": csrf_token, "error": error_message})
        response.set_cookie(key="csrf_token", value=csrf_token, httponly=True)
        return response
        
    return templates.TemplateResponse(get_template(request, "index.html"), {"request": request, "DOMAIN": DOMAIN})

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
        return templates.TemplateResponse(get_template(request, "error.html"), {"request": request, "error_message": _(request, "Could not retrieve your user information. Please try again later.")})

    user_data = user_response.json()
    request.session["user"] = user_data
    return RedirectResponse("/")

@app.post("/register", dependencies=[Depends(csrf_protect)])
async def register(request: Request, username: str = Form(...), password: str = Form(...)):
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse("/login")

    # --- Username and Password Validation ---
    username_error = validate_username_format(request, username)
    password_error = validate_password(request, password)
    if username_error:
        set_error_message(request, username_error)
        return RedirectResponse("/", status_code=303)
    if password_error:
        set_error_message(request, password_error)
        return RedirectResponse("/", status_code=303)

    clean_username = username.strip().lower()

    # Tier 1: Forbidden Names
    forbidden_names = load_json(FORBIDDEN_NAMES_FILE)
    if clean_username in forbidden_names or any(f.startswith(clean_username) for f in forbidden_names) or any(f.endswith(clean_username) for f in forbidden_names):
        set_error_message(request, _(request, "This name is forbidden, please choose another name."))
        return RedirectResponse("/", status_code=303)

    # Tier 2: Availability Check
    reglist = load_json(REGISTRATION_LIST_FILE)
    if any(reg["email"].startswith(f"{clean_username}@") for reg in reglist["registrations"]):
        set_error_message(request, _(request, "This name is not available, please choose another name."))
        return RedirectResponse("/", status_code=303)

    # Check if user has already registered
    if any(reg["mastodon_id"] == user["id"] for reg in reglist["registrations"]):
        set_error_message(request, _(request, "You have already registered an account."))
        return RedirectResponse("/", status_code=303)

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
        set_error_message(request, _(request, "Something went wrong, please try again later."))
        return RedirectResponse("/", status_code=303)

    # Update registration list
    reglist["registrations"].append({
        "mastodon_id": user["id"],
        "email": email,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
    })
    save_json(REGISTRATION_LIST_FILE, reglist)
    logger.info(f"Successfully registered {email} for Mastodon user {user['id']}")

    request.session["success_message"] = _(request, "Account created successfully! Login at {WEBMAIL_URL}", WEBMAIL_URL=WEBMAIL_URL)
    return RedirectResponse("/", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")


@app.post("/validate-username")
async def validate_username(request: Request):
    data = await request.json()
    username = data.get("username", "")
    
    format_error = validate_username_format(request, username)
    if format_error:
        return {"valid": False, "message": format_error}

    clean_username = username.strip().lower()
    
    # Tier 1: Forbidden Names
    forbidden_names = load_json(FORBIDDEN_NAMES_FILE)
    if not clean_username:
        return {"valid": False, "message": _(request, "Username cannot be empty.")}
        
    if clean_username in forbidden_names or any(f.startswith(clean_username) for f in forbidden_names) or any(f.endswith(clean_username) for f in forbidden_names):
        return {"valid": False, "message": _(request, "This name is forbidden, please choose another name.")}

    # Tier 2: Availability Check
    reglist = load_json(REGISTRATION_LIST_FILE)
    if any(reg["email"].startswith(f"{clean_username}@") for reg in reglist["registrations"]):
        return {"valid": False, "message": _(request, "This name is not available, please choose another name.")}
        
    return {"valid": True, "message": _(request, "This name is available!")}


def validate_username_format(request: Request, username: str):
    if len(username) < 3:
        return _(request, "Username must be at least 3 characters long.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_.-]*$", username):
        return _(request, "Username must start with a letter and can only contain letters, numbers,<br>and the characters: . - _")
    return None

def validate_password(request: Request, password: str):
    if len(password) < 8:
        return _(request, "Password must be at least 8 characters long.")
    return None


@app.get("/health")
async def health_check():
    return {"status": "ok"}
