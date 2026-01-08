import argparse
import json
import os
import time
import random
import logging
import unicodedata
import sqlite3
import re
from playwright.sync_api import sync_playwright
import urllib.parse
import subprocess
import pty
import errno
import sys
from typing import Dict, List
import threading
import uuid
import signal
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ConversationHandler, ContextTypes
import asyncio
from dotenv import load_dotenv
from playwright_stealth import Stealth
from instagrapi import Client
from instagrapi.exceptions import ChallengeRequired, TwoFactorRequired, PleaseWaitFewMinutes, RateLimitError, LoginRequired

load_dotenv()

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('instagram_bot.log'),
        logging.StreamHandler()
    ]
)

AUTHORIZED_FILE = 'authorized_users.json'
TASKS_FILE = 'tasks.json'
OWNER_TG_ID = int(os.environ.get('8421200250', 0))
BOT_TOKEN = os.environ.get('8421200250:AAENRgbY0KRlFG-6Q47mZu1Xt4-iLlFtQ54')
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

authorized_users = []  # list of {'id': int, 'username': str}
users_data: Dict[int, Dict] = {}  # unlocked data {'accounts': list, 'default': int, 'pairs': dict or None, 'switch_minutes': int, 'threads': int}
users_pending: Dict[int, Dict] = {}  # pending challenges
users_tasks: Dict[int, List[Dict]] = {}  # tasks per user
persistent_tasks = []
running_processes: Dict[int, subprocess.Popen] = {}

# Conversation states
LOGIN_CHOICE, USERNAME, PASSWORD, SESSION_ID = range(4)
SELECT_ACCOUNT, TARGET_TYPE, TARGET, MESSAGES = range(4, 8)
SETIG_SELECT = 8
LOGOUT_SELECT = 9
UNPAIR_SELECT = 10

# === PATCH: Fix instagrapi invalid timestamp bug ===
def _sanitize_timestamps(obj):
    """Fix invalid *_timestamp_us fields in Instagram data"""
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            if isinstance(v, int) and k.endswith("_timestamp_us"):
                try:
                    secs = int(v) // 1_000_000  # convert microseconds → seconds
                except Exception:
                    secs = None
                # skip impossible years (>2100 or negative)
                if secs is None or secs < 0 or secs > 4102444800:
                    new_obj[k] = None
                else:
                    new_obj[k] = secs
            else:
                new_obj[k] = _sanitize_timestamps(v)
        return new_obj
    elif isinstance(obj, list):
        return [_sanitize_timestamps(i) for i in obj]
    else:
        return obj

# 🧩 Monkeypatch instagrapi to fix validation crash
try:
    import instagrapi.extractors as extractors
    _orig_extract_reply_message = extractors.extract_reply_message

    def patched_extract_reply_message(data):
        data = _sanitize_timestamps(data)
        return _orig_extract_reply_message(data)

    extractors.extract_reply_message = patched_extract_reply_message
    print("[Patch] Applied timestamp sanitizer to instagrapi extractors ✅")
except Exception as e:
    print(f"[Patch Warning] Could not patch instagrapi: {e}")
# === END PATCH ===

# --- Playwright sync helper: run sync_playwright() inside a fresh thread ---
def run_with_sync_playwright(fn, *args, **kwargs):
    """
    Runs `fn(p, *args, **kwargs)` where p is the object returned by sync_playwright()
    inside a new thread and returns fn's return value (or raises exception).
    """
    result = {"value": None, "exc": None}

    def target():
        try:
            with sync_playwright() as p:
                result["value"] = fn(p, *args, **kwargs)
        except Exception as e:
            result["exc"] = e

    t = threading.Thread(target=target)
    t.start()
    t.join()
    if result["exc"]:
        raise result["exc"]
    return result["value"]

def load_authorized():
    global authorized_users
    if os.path.exists(AUTHORIZED_FILE):
        with open(AUTHORIZED_FILE, 'r') as f:
            authorized_users = json.load(f)
    # Ensure owner is authorized
    if not any(u['id'] == OWNER_TG_ID for u in authorized_users):
        authorized_users.append({'id': OWNER_TG_ID, 'username': 'owner'})

load_authorized()

def load_users_data():
    global users_data
    users_data = {}
    for file in os.listdir('.'):
        if file.startswith('user_') and file.endswith('.json'):
            user_id_str = file[5:-5]
            if user_id_str.isdigit():
                user_id = int(user_id_str)
                with open(file, 'r') as f:
                    data = json.load(f)
                # Defaults
                if 'pairs' not in data:
                    data['pairs'] = None
                if 'switch_minutes' not in data:
                    data['switch_minutes'] = 10
                if 'threads' not in data:
                    data['threads'] = 1
                users_data[user_id] = data

load_users_data()

def save_authorized():
    with open(AUTHORIZED_FILE, 'w') as f:
        json.dump(authorized_users, f)

def save_user_data(user_id: int, data: Dict):
    with open(f'user_{user_id}.json', 'w') as f:
        json.dump(data, f)

def is_authorized(user_id: int) -> bool:
    return True

def is_owner(user_id: int) -> bool:
    return True

def future_expiry(days=365):
    return int(time.time()) + days*24*3600

def convert_for_playwright(insta_file, playwright_file):
    try:
        with open(insta_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        return

    cookies = []
    auth = data.get("authorization_data", {})
    for name, value in auth.items():
        cookies.append({
            "name": name,
            "value": urllib.parse.unquote(value),
            "domain": ".instagram.com",
            "path": "/",
            "expires": future_expiry(),
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax"
        })

    playwright_state = {
        "cookies": cookies,
        "origins": [{"origin": "https://www.instagram.com", "localStorage": []}]
    }

    with open(playwright_file, "w") as f:
        json.dump(playwright_state, f, indent=4)

def get_storage_state_from_instagrapi(settings: Dict):
    cl = Client()
    cl.set_settings(settings)

    # Collect cookies from instagrapi structures (compatible with multiple instagrapi versions)
    cookies_dict = {}
    if hasattr(cl, "session") and cl.session:
        try:
            cookies_dict = cl.session.cookies.get_dict()
        except Exception:
            cookies_dict = {}
    elif hasattr(cl, "private") and hasattr(cl.private, "cookies"):
        try:
            cookies_dict = cl.private.cookies.get_dict()
        except Exception:
            cookies_dict = {}
    elif hasattr(cl, "_http") and hasattr(cl._http, "cookies"):
        try:
            cookies_dict = cl._http.cookies.get_dict()
        except Exception:
            cookies_dict = {}

    cookies = []
    for name, value in cookies_dict.items():
        cookies.append({
            "name": name,
            "value": value,
            "domain": ".instagram.com",
            "path": "/",
            "expires": int(time.time()) + 365*24*3600,
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax"
        })

    storage_state = {
        "cookies": cookies,
        "origins": [{"origin": "https://www.instagram.com", "localStorage": []}]
    }
    return storage_state

def instagrapi_login(username, password):
    cl = Client()
    session_file = f"{username}_session.json"
    playwright_file = f"{username}_state.json"
    try:
        cl.login(username, password)
        cl.dump_settings(session_file)
        convert_for_playwright(session_file, playwright_file)
    except (ChallengeRequired, TwoFactorRequired):
        raise ValueError("ERROR_004: Login challenge or 2FA required")
    except (PleaseWaitFewMinutes, RateLimitError):
        raise ValueError("ERROR_002: Rate limit exceeded")
    except Exception as e:
        raise ValueError(f"ERROR_007: Login failed - {str(e)}")
    return json.load(open(playwright_file))

def list_group_chats(user_id, storage_state, username, password, max_groups=10, amount=10):
    username = username.strip().lower()
    norm_username = username.strip().lower()
    session_file = f"sessions/{user_id}_{norm_username}_session.json"
    playwright_file = f"sessions/{user_id}_{norm_username}_state.json"
    cl = Client()
    updated = False
    new_state = None

    # Load existing session if available
    if os.path.exists(session_file):
        try:
            cl.load_settings(session_file)
        except Exception:
            pass

    try:
        threads = cl.direct_threads(amount=amount)
        time.sleep(random.uniform(1.0, 3.0))
    except LoginRequired:
        cl.login(username, password)
        cl.dump_settings(session_file)
        convert_for_playwright(session_file, playwright_file)
        updated = True
        threads = cl.direct_threads(amount=amount)
        time.sleep(random.uniform(1.0, 3.0))

    groups = []
    for thread in threads:
        if len(groups) >= max_groups:
            break
        if getattr(thread, "is_group", False):
            member_count = len(getattr(thread, "users", [])) + 1
            if member_count < 3:
                continue

            title = getattr(thread, "thread_title", None) or getattr(thread, "title", None)
            if not title or title.strip() == "":
                try:
                    users_part = ", ".join([u.username for u in getattr(thread, "users", [])][:3])
                    display = users_part if users_part else "<no name>"
                except Exception:
                    display = "<no name>"
            else:
                display = title

            url = f"https://www.instagram.com/direct/t/{getattr(thread, 'thread_id', getattr(thread, 'id', 'unknown'))}"
            groups.append({'display': display, 'url': url})

    if updated and os.path.exists(playwright_file):
        new_state = get_storage_state_from_instagrapi(cl.get_settings())
        with open(playwright_file, 'w') as f:
            json.dump(new_state, f)
    elif os.path.exists(playwright_file):
        new_state = json.load(open(playwright_file))
    else:
        new_state = storage_state

    return groups, new_state

def get_dm_thread_url(user_id, username, password, target_username):
    norm_username = username.strip().lower()
    session_file = f"sessions/{user_id}_{norm_username}_session.json"
    playwright_file = f"sessions/{user_id}_{norm_username}_state.json"
    cl = Client()
    updated = False

    if os.path.exists(session_file):
        try:
            cl.load_settings(session_file)
        except Exception:
            pass

    try:
        threads = cl.direct_threads(amount=10)
        time.sleep(random.uniform(1.0, 3.0))
    except LoginRequired:
        cl.login(username, password)
        cl.dump_settings(session_file)
        convert_for_playwright(session_file, playwright_file)
        updated = True
        threads = cl.direct_threads(amount=10)
        time.sleep(random.uniform(1.0, 3.0))

    for thread in threads:
        if not getattr(thread, 'is_group', True) and len(getattr(thread, 'users', [])) == 1:
            try:
                user = thread.users[0]
                if user.username == target_username:
                    thread_id = getattr(thread, 'thread_id', getattr(thread, 'id', None))
                    if thread_id:
                        url = f"https://www.instagram.com/direct/t/{thread_id}/"
                        if updated:
                            settings = cl.get_settings()
                            new_state = get_storage_state_from_instagrapi(settings)
                            with open(playwright_file, 'w') as f:
                                json.dump(new_state, f)
                        return url
            except Exception:
                continue

    return None

def perform_login(page, username, password):
    try:
        page.evaluate("""() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            window.chrome = { app: {}, runtime: {} };
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                Promise.resolve({ state: 'denied' }) :
                originalQuery(parameters)
            );
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                if (parameter === 37445) return 'Google Inc. (Intel)';
                if (parameter === 37446) return 'ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)';
                return getParameter.call(this, parameter);
            };
        }""")

        username_locator = page.locator('input[name="username"]')
        username_locator.wait_for(state='visible', timeout=10000)
        username_locator.focus()
        time.sleep(random.uniform(0.5, 1.5))
        for char in username:
            username_locator.press(char)
            time.sleep(random.uniform(0.05, 0.15))

        password_locator = page.locator('input[name="password"]')
        password_locator.wait_for(state='visible', timeout=10000)
        time.sleep(random.uniform(0.5, 1.5))
        password_locator.focus()
        time.sleep(random.uniform(0.3, 0.8))
        for char in password:
            password_locator.press(char)
            time.sleep(random.uniform(0.05, 0.15))

        time.sleep(random.uniform(1.0, 2.5))

        submit_locator = page.locator('button[type="submit"]')
        submit_locator.wait_for(state='visible', timeout=10000)
        if not submit_locator.is_enabled():
            raise Exception("Submit button not enabled")
        submit_locator.click()

        try:
            page.wait_for_url(lambda url: 'accounts/login' not in url and 'challenge' not in url and 'two_factor' not in url, timeout=60000)

            if page.locator('[role="alert"]').count() > 0:
                error_text = page.locator('[role="alert"]').inner_text().lower()
                if 'incorrect' in error_text or 'wrong' in error_text:
                    raise ValueError("ERROR_001: Invalid credentials")
                elif 'wait' in error_text or 'few minutes' in error_text or 'too many' in error_text:
                    raise ValueError("ERROR_002: Rate limit exceeded")
                else:
                    raise ValueError(f"ERROR_003: Login error - {error_text}")
        except TimeoutError:
            current_url = page.url
            page_content = page.content().lower()
            if 'challenge' in current_url:
                raise ValueError("ERROR_004: Login challenge required")
            elif 'two_factor' in current_url or 'verify' in current_url:
                raise ValueError("ERROR_005: 2FA verification required")
            elif '429' in page_content or 'rate limit' in page_content or 'too many requests' in page_content:
                raise ValueError("ERROR_002: Rate limit exceeded")
            elif page.locator('[role="alert"]').count() > 0:
                error_text = page.locator('[role="alert"]').inner_text().lower()
                raise ValueError(f"ERROR_006: Login failed - {error_text}")
            else:
                raise ValueError("ERROR_007: Login timeout or unknown error")

        logging.info("Login successful")
    except Exception as e:
        logging.error(f"Login failed: {str(e)}")
        raise

# ---------------- Globals for PTY ----------------
APP = None
LOOP = None
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()

# ---------------- Child PTY login ----------------
def child_login(user_id: int, username: str, password: str):
    cl = Client()
    username = username.strip().lower()
    session_file = f"sessions/{user_id}_{username}_session.json"
    playwright_file = f"sessions/{user_id}_{username}_state.json"
    try:
        print(f"[{username}] ⚙️ Attempting login.. if you are stucked here check your gmail or messages check for otp and enter otp here eg: 192122.")
        cl.login(username, password)
        cl.dump_settings(session_file)
        convert_for_playwright(session_file, playwright_file)
        print(f"[{username}] ✅ Logged in successfully. Session saved: {session_file}")
    except TwoFactorRequired:
        print(f" Enter code (6 digits) for {username} (2FA): ", end="", flush=True)
        otp = input().strip()
        try:
            cl.login(username, password, verification_code=otp)
            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)
            print(f"[{username}] ✅ OTP resolved. Logged in. Session saved: {session_file}")
        except Exception as e:
            print(f"[{username}] ❌ OTP failed: {e}")
    except ChallengeRequired:
        print(f" Enter code (6 digits) for {username} (Challenge): ", end="", flush=True)
        otp = input().strip()
        try:
            cl.challenge_resolve(cl.last_json, security_code=otp)
            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)
            print(f"[{username}] ✅ OTP resolved. Logged in. Session saved: {session_file}")
        except Exception as e:
            print(f"[{username}] ❌ OTP failed: {e}")
    except Exception as e:
        print(f"[{username}] ❌ Login failed: {e}")
    finally:
        time.sleep(0.5)
        sys.exit(0)

# ---------------- PTY reader thread ----------------
def reader_thread(user_id: int, chat_id: int, master_fd: int, username: str, password: str):
    global APP, LOOP
    buf = b""
    while True:
        try:
            data = os.read(master_fd, 1024)
            if not data:
                break
            buf += data
            while b"\n" in buf or len(buf) > 2048:
                if b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode(errors="ignore").strip()
                else:
                    text = buf.decode(errors="ignore")
                    buf = b""
                if not text:
                    continue
                if text.startswith("Code entered"):
                    continue
                lower = text.lower()
                if (
                    len(text) > 300
                    or "cdninstagram.com" in lower
                    or "http" in lower
                    or "{" in text
                    or "}" in text
                    or "debug" in lower
                    or "info" in lower
                    or "urllib3" in lower
                    or "connection" in lower
                    or "starting new https" in lower
                    or "instagrapi" in lower
                ):
                    continue
                try:
                    if APP and LOOP:
                        asyncio.run_coroutine_threadsafe(
                            APP.bot.send_message(chat_id=chat_id, text=f"🔥{text}"), LOOP
                        )
                except Exception:
                    logging.error("[THREAD] send_message failed")
        except OSError as e:
            if e.errno == errno.EIO:
                break
            else:
                logging.error("[THREAD] PTY read error: %s", e)
                break
        except Exception as e:
            logging.error("[THREAD] Unexpected error: %s", e)
            break
    try:
        playwright_file = f"sessions/{user_id}_{username}_state.json"
        if os.path.exists(playwright_file):
            with open(playwright_file, 'r') as f:
                state = json.load(f)
            if user_id in users_data:
                data = users_data[user_id]
            else:
                data = {'accounts': [], 'default': None, 'pairs': None, 'switch_minutes': 10, 'threads': 1}
            # normalize incoming username
            norm_username = username.strip().lower()

            for i, acc in enumerate(data['accounts']):
                if acc.get('ig_username', '').strip().lower() == norm_username:
                    # overwrite existing entry for exact same username (normalized)
                    data['accounts'][i] = {'ig_username': norm_username, 'password': password, 'storage_state': state}
                    data['default'] = i
                    break
            else:
                # not found -> append new normalized account
                data['accounts'].append({'ig_username': norm_username, 'password': password, 'storage_state': state})
                data['default'] = len(data['accounts']) - 1
            save_user_data(user_id, data)
            users_data[user_id] = data
            if APP and LOOP:
                asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text="✅ Login successful and saved securely! 🎉"), LOOP)
        else:
            if APP and LOOP:
                asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text="⚠️ Login failed. No session saved."), LOOP)
    except Exception as e:
        logging.error("Failed to save user data: %s", e)
        if APP and LOOP:
            asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text=f"⚠️ Error saving data: {str(e)}"), LOOP)
    finally:
        with SESSIONS_LOCK:
            if user_id in SESSIONS:
                try:
                    os.close(SESSIONS[user_id]["master_fd"])
                except Exception:
                    pass
                SESSIONS.pop(user_id, None)

async def setig_select(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    text = update.message.text
    if user_id not in users_data or not users_data[user_id]['accounts']:
        await update.message.reply_text("❌ No accounts saved. ❌")
        return ConversationHandler.END

    data = users_data[user_id]
    try:
        # Expected format: "1. username"
        match = re.match(r'^(\d+)\.', text)
        if match:
            num = int(match.group(1)) - 1
            if 0 <= num < len(data['accounts']):
                data['default'] = num
                save_user_data(user_id, data)
                acc = data['accounts'][num]['ig_username']
                from telegram import ReplyKeyboardRemove
                await update.message.reply_text(f"✅ {num+1}. {acc} now is your default account. ⭐", reply_markup=ReplyKeyboardRemove())
            else:
                await update.message.reply_text("⚠️ Invalid selection. ⚠️")
        else:
            await update.message.reply_text("⚠️ Invalid selection. Please use the buttons. ⚠️")
    except Exception:
        await update.message.reply_text("⚠️ Invalid selection. ⚠️")
    
    return ConversationHandler.END

# ---------------- Relay input ----------------
async def relay_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text
    with SESSIONS_LOCK:
        info = SESSIONS.get(user_id)
    if not info:
        return
    master_fd = info["master_fd"]
    try:
        os.write(master_fd, (text + "\n").encode())
    except OSError as e:
        await update.message.reply_text(f"Failed to write to PTY stdin: {e}")
    except Exception as e:
        logging.error("Relay input error: %s", e)

# ---------------- Kill command ----------------
async def cmd_kill(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    with SESSIONS_LOCK:
        info = SESSIONS.get(user_id)
    if not info:
        await update.message.reply_text("No active PTY session.")
        return
    pid = info["pid"]
    master_fd = info["master_fd"]
    try:
        os.kill(pid, 15)
    except Exception:
        pass
    try:
        os.close(master_fd)
    except Exception:
        pass
    with SESSIONS_LOCK:
        SESSIONS.pop(user_id, None)
    await update.message.reply_text(f"🛑 Stopped login terminal (pid={pid}) successfully.")

# ---------------- Flush command ----------------
    global users_tasks, persistent_tasks
    for uid, tasks in users_tasks.items():
        for task in tasks[:]:
            proc = task['proc']
            proc.terminate()
            await asyncio.sleep(3)
            if proc.poll() is None:
                proc.kill()
            # remove from runtime map if present
            pid = task.get('pid')
            if pid in running_processes:
                running_processes.pop(pid, None)
            if task.get('type') == 'message_attack' and 'names_file' in task:
                names_file = task['names_file']
                if os.path.exists(names_file):
                    os.remove(names_file)
            logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Task stop user={uid} task={task['id']} by flush")
            mark_task_stopped_persistent(task['id'])
            tasks.remove(task)
        users_tasks[uid] = tasks
    await update.message.reply_text("🛑 All tasks globally stopped! 🛑")

USERNAME, PASSWORD, SESSION_ID, LOGIN_CHOICE = range(4)

async def login_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    keyboard = [
        ["👤 𝐔𝐬𝐞𝐫/𝐏𝐚𝐬𝐬 𝐋𝐨𝐠𝐢𝐧"],
        ["🔑 𝐒𝐞𝐬𝐬𝐢𝐨𝐧 𝐈𝐃 𝐋𝐨𝐠𝐢𝐧"]
    ]
    from telegram import ReplyKeyboardMarkup
    reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    await update.message.reply_text("𝐂𝐡𝐨𝐨𝐬𝐞 𝐥𝐨𝐠𝐢𝐧 𝐦𝐞𝐭𝐡𝐨𝐝:", reply_markup=reply_markup)
    return LOGIN_CHOICE

async def handle_login_choice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    choice = update.message.text
    if "𝐔𝐬𝐞𝐫/𝐏𝐚𝐬𝐬" in choice:
        await update.message.reply_text("📱 𝐄𝐧𝐭𝐞𝐫 𝐈𝐧𝐬𝐭𝐚𝐠𝐫𝐚𝐦 𝐮𝐬𝐞𝐫𝐧𝐚𝐦𝐞: 📱")
        return USERNAME
    elif "𝐒𝐞𝐬𝐬𝐢𝐨𝐧 𝐈𝐃" in choice:
        await update.message.reply_text("🔑 𝐄𝐧𝐭𝐞𝐫 𝐲𝐨𝐮𝐫 𝐈𝐧𝐬𝐭𝐚𝐠𝐫𝐚𝐦 𝐬𝐞𝐬𝐬𝐢𝐨𝐧𝐢𝐝: 🔑")
        return SESSION_ID
    return ConversationHandler.END

async def login_session_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("🔑 𝐄𝐧𝐭𝐞𝐫 𝐲𝐨𝐮𝐫 𝐈𝐧𝐬𝐭𝐚𝐠𝐫𝐚𝐦 𝐬𝐞𝐬𝐬𝐢𝐨𝐧𝐢𝐝: 🔑")
    return SESSION_ID

async def get_username_session(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['ig_username'] = update.message.text.strip().lower()
    await update.message.reply_text("🔑 𝐄𝐧𝐭𝐞𝐫 𝐒𝐞𝐬𝐬𝐢𝐨𝐧 𝐈𝐃: 🔑")
    return SESSION_ID

async def get_session_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    username = context.user_data['ig_username']
    session_id = update.message.text.strip()

    cl = Client()
    try:
        cl.login_by_sessionid(session_id)
        # Verify login
        cl.get_timeline_feed()

        # Save session
        os.makedirs('sessions', exist_ok=True)
        session_file = f"sessions/{user_id}_{username}_session.json"
        cl.dump_settings(session_file)

        # Convert to playwright state
        state_file = f"sessions/{user_id}_{username}_state.json"
        convert_for_playwright(session_file, state_file)

        # Update user data
        if user_id not in users_data:
            users_data[user_id] = {'accounts': [], 'default': 0, 'pairs': None, 'switch_minutes': 10, 'threads': 1}

        data = users_data[user_id]
        # Check if exists
        for i, acc in enumerate(data['accounts']):
            if acc['ig_username'] == username:
                data['accounts'][i] = {'ig_username': username, 'password': 'session_login', 'storage_state': state_file}
                break
        else:
            data['accounts'].append({'ig_username': username, 'password': 'session_login', 'storage_state': state_file})
            data['default'] = len(data['accounts']) - 1

        save_user_data(user_id, data)
        await update.message.reply_text(f"✅ 𝐋𝐨𝐠𝐢𝐧 𝐬𝐮𝐜𝐜𝐞𝐬𝐬𝐟𝐮𝐥 𝐟𝐨𝐫 @{username} 𝐯𝐢𝐚 𝐒𝐞𝐬𝐬𝐢𝐨𝐧 𝐈𝐃! ✅")
    except Exception as e:
        await update.message.reply_text(f"❌ 𝐋𝐨𝐠𝐢𝐧 𝐟𝐚𝐢𝐥𝐞𝐝: {str(e)} ❌")

    return ConversationHandler.END

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("𝐖𝐞𝐥𝐜𝐨𝐦𝐞 𝐭𝐨 𝐃𝐄𝐕 𝐏𝐎𝐖𝐄𝐑 𝐁𝐎𝐓 ⚡ 𝐭𝐲𝐩𝐞 /𝐡𝐞𝐥𝐩 𝐭𝐨 𝐬𝐞𝐞 𝐚𝐯𝐚𝐢𝐥𝐚𝐛𝐥𝐞 𝐜𝐨𝐦𝐦𝐚𝐧𝐝𝐬")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    help_text = f"""
💎 𝐃𝐄𝐕 𝐏𝐎𝐖𝐄𝐑 𝐁𝐎𝐓 𝟐.𝟎 💎
👤 (@𝐠𝐨𝐝_𝐨𝐥𝐝𝐬)

🔑 /login — 𝐀𝐝𝐝 𝐚 𝐧𝐞𝐰 𝐚𝐜𝐜𝐨𝐮𝐧𝐭 (𝐔𝐬𝐞𝐫/𝐏𝐚𝐬𝐬 𝐨𝐫 𝐒𝐞𝐬𝐬𝐢𝐨𝐧 𝐈𝐃)
🚀 /attack — 𝐒𝐭𝐚𝐫𝐭 𝐚 𝐡𝐢𝐠𝐡-𝐬𝐩𝐞𝐞𝐝 𝐦𝐞𝐬𝐬𝐚𝐠𝐞 𝐫𝐚𝐢𝐝
📊 /task — 𝐂𝐡𝐞𝐜𝐤 𝐚𝐜𝐭𝐢𝐯𝐞 𝐫𝐚𝐢𝐝 𝐩𝐫𝐨𝐠𝐫𝐞𝐬𝐬
👥 /viewmyac — 𝐌𝐚𝐧𝐚𝐠𝐞 𝐲𝐨𝐮𝐫 𝐥𝐨𝐠𝐠𝐞𝐝-𝐢𝐧 𝐚𝐜𝐜𝐨𝐮𝐧𝐭𝐬
⚙️ /viewpref — 𝐕𝐢𝐞𝐰 𝐲𝐨𝐮𝐫 𝐫𝐚𝐢𝐝 𝐩𝐫𝐞𝐟𝐞𝐫𝐞𝐧𝐜𝐞𝐬
🔄 /setig — 𝐒𝐞𝐭 𝐝𝐞𝐟𝐚𝐮𝐥𝐭 𝐚𝐜𝐜𝐨𝐮𝐧𝐭
📦 /pair — 𝐂𝐫𝐞𝐚𝐭𝐞 𝐚𝐜𝐜𝐨𝐮𝐧𝐭 𝐩𝐚𝐢𝐫
✨ /unpair — 𝐔𝐧𝐩𝐚𝐢𝐫 𝐚𝐜𝐜𝐨𝐮𝐧𝐭𝐬
⏱️ /switch — 𝐒𝐞𝐭 𝐬𝐰𝐢𝐭𝐜𝐡 𝐢𝐧𝐭𝐞𝐫𝐯𝐚𝐥
🔢 /threads — 𝐒𝐞𝐭 𝐧𝐮𝐦𝐛𝐞𝐫 𝐨𝐟 𝐭𝐡𝐫𝐞𝐚𝐝𝐬
🚪 /logout — 𝐋𝐨𝐠𝐨𝐮𝐭 𝐚𝐧𝐝 𝐫𝐞𝐦𝐨𝐯𝐞 𝐚𝐜𝐜𝐨𝐮𝐧𝐭
❓ /help — 𝐒𝐡𝐨𝐰 𝐭𝐡𝐢𝐬 𝐠𝐮𝐢𝐝𝐞
🛑 /kill — 𝐊𝐢𝐥𝐥 𝐚𝐜𝐭𝐢𝐯𝐞 𝐥𝐨𝐠𝐢𝐧 𝐬𝐞𝐬𝐬𝐢𝐨𝐧

🛑 /stop — 𝐊𝐢𝐥𝐥 𝐚𝐜𝐭𝐢𝐯𝐞 𝐫𝐚𝐢𝐝𝐬 𝐢𝐧𝐬𝐭𝐚𝐧𝐭𝐥𝐲

💡 𝐓𝐢𝐩: 𝐔𝐬𝐞 /𝐬𝐭𝐨𝐩 𝐢𝐟 𝐲𝐨𝐮 𝐠𝐞𝐭 𝐫𝐚𝐭𝐞 𝐥𝐢𝐦𝐢𝐭𝐞𝐝! ⚡
    """
    await update.message.reply_text(help_text)

async def login_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    keyboard = [
        ["👤 𝐔𝐬𝐞𝐫/𝐏𝐚𝐬𝐬 𝐋𝐨𝐠𝐢𝐧"],
        ["🔑 𝐒𝐞𝐬𝐬𝐢𝐨𝐧 𝐈𝐃 𝐋𝐨𝐠𝐢𝐧"]
    ]
    from telegram import ReplyKeyboardMarkup
    reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    await update.message.reply_text("𝐂𝐡𝐨𝐨𝐬𝐞 𝐥𝐨𝐠𝐢𝐧 𝐦𝐞𝐭𝐡𝐨𝐝:", reply_markup=reply_markup)
    return LOGIN_CHOICE

async def get_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    # Normalize username: remove surrounding spaces and lowercase
    context.user_data['ig_username'] = update.message.text.strip().lower()
    await update.message.reply_text("🔒 𝐄𝐧𝐭𝐞𝐫 𝐩𝐚𝐬𝐬𝐰𝐨𝐫𝐝: 🔒")
    return PASSWORD

async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    username = context.user_data['ig_username']
    password = update.message.text.strip()

    with SESSIONS_LOCK:
        if user_id in SESSIONS:
            await update.message.reply_text("⚠️ PTY session already running. Use /kill first.")
            return ConversationHandler.END

    pid, master_fd = pty.fork()
    if pid == 0:
        try:
            child_login(user_id, username, password)
        except SystemExit:
            os._exit(0)
        except Exception as e:
            print(f"[CHILD] Unexpected error: {e}")
            os._exit(1)
    else:
        t = threading.Thread(target=reader_thread, args=(user_id, chat_id, master_fd, username, password), daemon=True)
        t.start()
        with SESSIONS_LOCK:
            SESSIONS[user_id] = {"pid": pid, "master_fd": master_fd, "thread": t, "username": username, "password": password, "chat_id": chat_id}

    return ConversationHandler.END

async def login_session_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("🔑 𝐄𝐧𝐭𝐞𝐫 𝐲𝐨𝐮𝐫 𝐈𝐧𝐬𝐭𝐚𝐠𝐫𝐚𝐦 𝐬𝐞𝐬𝐬𝐢𝐨𝐧𝐢𝐝: 🔑")
    return SESSION_ID

async def get_session_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    sessionid = update.message.text.strip()
    user_id = update.effective_user.id
    await update.message.reply_text("⏳ 𝐋𝐨𝐠𝐠𝐢𝐧𝐠 𝐢𝐧 𝐰𝐢𝐭𝐜𝐡 𝐬𝐞𝐬𝐬𝐢𝐨𝐧 𝐈𝐃...")
    
    cl = Client()
    try:
        cl.login_by_sessionid(sessionid)
        username = cl.account_info().username
        session_file = f"sessions/{user_id}_{username}_session.json"
        playwright_file = f"sessions/{user_id}_{username}_state.json"
        
        cl.dump_settings(session_file)
        convert_for_playwright(session_file, playwright_file)
        
        state = json.load(open(playwright_file))
        if user_id not in users_data:
            users_data[user_id] = {'accounts': [], 'default': None, 'pairs': None, 'switch_minutes': 10, 'threads': 1}
        
        data = users_data[user_id]
        norm_username = username.lower()
        for i, acc in enumerate(data['accounts']):
            if acc.get('ig_username', '').strip().lower() == norm_username:
                data['accounts'][i] = {'ig_username': username, 'password': 'session_login', 'storage_state': state}
                data['default'] = i
                break
        else:
            data['accounts'].append({'ig_username': username, 'password': 'session_login', 'storage_state': state})
            data['default'] = len(data['accounts']) - 1
            
        save_user_data(user_id, data)
        users_data[user_id] = data
        await update.message.reply_text(f"✅ Logged in as {username} using session ID! 🎉")
    except Exception as e:
        await update.message.reply_text(f"❌ Login failed: {str(e)}")
        
    return ConversationHandler.END

async def viewmyac(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if user_id not in users_data:
        await update.message.reply_text("❌ You haven't saved any account. Use /login to save one. ❌")
        return
    data = users_data[user_id]
    msg = "👀 Your saved account list 👀\n"
    for i, acc in enumerate(data['accounts']):
        default = " (default) ⭐" if data['default'] == i else ""
        msg += f"{i+1}. {acc['ig_username']}{default}\n"
    await update.message.reply_text(msg)

async def setig(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if user_id not in users_data or not users_data[user_id]['accounts']:
        await update.message.reply_text("❌ No accounts saved. ❌")
        return ConversationHandler.END

    data = users_data[user_id]
    keyboard = []
    for i, acc in enumerate(data['accounts']):
        keyboard.append([f"{i+1}. {acc['ig_username']}"])
    
    from telegram import ReplyKeyboardMarkup
    reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    await update.message.reply_text("🎯 𝐒𝐞𝐥𝐞𝐜𝐭 𝐝𝐞𝐟𝐚𝐮𝐥𝐭 𝐚𝐜𝐜𝐨𝐮𝐧𝐭:", reply_markup=reply_markup)
    return SETIG_SELECT

async def setig_select(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    text = update.message.text
    if user_id not in users_data or not users_data[user_id]['accounts']:
        await update.message.reply_text("❌ No accounts saved. ❌")
        return ConversationHandler.END

    data = users_data[user_id]
    try:
        # Expected format: "1. username"
        match = re.match(r'^(\d+)\.', text)
        if match:
            num = int(match.group(1)) - 1
            if 0 <= num < len(data['accounts']):
                data['default'] = num
                save_user_data(user_id, data)
                acc = data['accounts'][num]['ig_username']
                from telegram import ReplyKeyboardRemove
                await update.message.reply_text(f"✅ {num+1}. {acc} now is your default account. ⭐", reply_markup=ReplyKeyboardRemove())
            else:
                await update.message.reply_text("⚠️ Invalid selection. ⚠️")
        else:
            await update.message.reply_text("⚠️ Invalid selection. Please use the buttons. ⚠️")
    except Exception:
        await update.message.reply_text("⚠️ Invalid selection. ⚠️")
    
    return ConversationHandler.END

async def logout_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if user_id not in users_data or not users_data[user_id]['accounts']:
        await update.message.reply_text("❌ No accounts saved. ❌")
        return ConversationHandler.END

    data = users_data[user_id]
    keyboard = []
    for i, acc in enumerate(data['accounts']):
        keyboard.append([f"{i+1}. {acc['ig_username']}"])
    
    from telegram import ReplyKeyboardMarkup
    reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    await update.message.reply_text("🚪 𝐒𝐞𝐥𝐞𝐜𝐭 𝐚𝐜𝐜𝐨𝐮𝐧𝐭 𝐭𝐨 𝐥𝐨𝐠𝐨𝐮𝐭:", reply_markup=reply_markup)
    return LOGOUT_SELECT

async def logout_select(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    text = update.message.text
    if user_id not in users_data:
        return ConversationHandler.END
        
    data = users_data[user_id]
    try:
        match = re.match(r'^(\d+)\.', text)
        if match:
            num = int(match.group(1)) - 1
            if 0 <= num < len(data['accounts']):
                acc = data['accounts'].pop(num)
                if data['default'] == num:
                    data['default'] = 0 if data['accounts'] else None
                elif data['default'] is not None and data['default'] > num:
                    data['default'] -= 1
                
                # Update pairs if exists
                if data.get('pairs'):
                    username = acc['ig_username']
                    pl = data['pairs']['list']
                    if username in pl:
                        pl.remove(username)
                        if not pl:
                            data['pairs'] = None
                        else:
                            data['pairs']['default_index'] = 0
                            
                save_user_data(user_id, data)
                username = acc['ig_username']
                # Try to remove session files
                for ext in ['_session.json', '_state.json']:
                    path = f"sessions/{user_id}_{username}{ext}"
                    if os.path.exists(path):
                        os.remove(path)
                
                from telegram import ReplyKeyboardRemove
                await update.message.reply_text(f"✅ Logged out from {username}. Session cleared.", reply_markup=ReplyKeyboardRemove())
            else:
                await update.message.reply_text("⚠️ Invalid selection.")
        else:
            await update.message.reply_text("⚠️ Please use the buttons.")
    except Exception as e:
        await update.message.reply_text(f"⚠️ Error: {str(e)}")
    
    return ConversationHandler.END

async def unpair_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if user_id not in users_data or not users_data[user_id].get('pairs'):
        await update.message.reply_text("❌ No active pair found. ❌")
        return ConversationHandler.END

    pair_list = users_data[user_id]['pairs']['list']
    keyboard = [[u] for u in pair_list]
    keyboard.append(["All"])
    
    from telegram import ReplyKeyboardMarkup
    reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    await update.message.reply_text("🔗 𝐒𝐞𝐥𝐞𝐜𝐭 𝐚𝐜𝐜𝐨𝐮𝐧𝐭 𝐭𝐨 𝐮𝐧𝐩𝐚𝐢𝐫 (𝐨𝐫 '𝐀𝐥𝐥'):", reply_markup=reply_markup)
    return UNPAIR_SELECT

async def unpair_select(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    text = update.message.text.strip().lower()
    if user_id not in users_data or not users_data[user_id].get('pairs'):
        return ConversationHandler.END
        
    data = users_data[user_id]
    pair_info = data['pairs']
    pair_list = pair_info['list']

    from telegram import ReplyKeyboardRemove
    if text == "all":
        data['pairs'] = None
        save_user_data(user_id, data)
        await update.message.reply_text("🧹 All paired accounts removed successfully.", reply_markup=ReplyKeyboardRemove())
    elif text in [u.lower() for u in pair_list]:
        # find original casing
        target = next(u for u in pair_list if u.lower() == text)
        pair_list.remove(target)
        if not pair_list:
            data['pairs'] = None
            msg = f"✅ Removed {target}. No pairs left."
        else:
            if pair_info.get('default_index', 0) >= len(pair_list):
                pair_info['default_index'] = 0
            msg = f"✅ Removed {target}. Remaining pairs: {', '.join(pair_list)}"
        save_user_data(user_id, data)
        await update.message.reply_text(msg, reply_markup=ReplyKeyboardRemove())
    else:
        await update.message.reply_text("⚠️ Invalid selection. Please use the buttons.")
        return UNPAIR_SELECT
    
    return ConversationHandler.END

# New commands
async def pair_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("❗ Usage: /pair iguser1-iguser2-iguser3 ❗")
        return
    arg_str = '-'.join(context.args)
    us = [u.strip() for u in arg_str.split('-') if u.strip()]
    if len(us) < 2:
        await update.message.reply_text("❗ Provide at least one more account. ❗")
        return
    if user_id not in users_data or not users_data[user_id]['accounts']:
        await update.message.reply_text("❌ No accounts saved. Use /login first. ❌")
        return
    data = users_data[user_id]
    accounts_set = {acc['ig_username'] for acc in data['accounts']}
    missing = [u for u in us if u not in accounts_set]
    if missing:
        await update.message.reply_text(f"⚠️ Can't find that account: {missing[0]}. Save it again with /login. ⚠️")
        return
    data['pairs'] = {'list': us, 'default_index': 0}
    # Set default to first in pair
    first_u = us[0]
    for i, acc in enumerate(data['accounts']):
        if acc['ig_username'] == first_u:
            data['default'] = i
            break
    save_user_data(user_id, data)
    await update.message.reply_text(f"✅ Pair created! {len(us)} accounts saved.\nDefault: {first_u} ⭐\nUse /attack to start sending messages with pairing & switching.")

async def unpair_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if user_id not in users_data or not users_data[user_id].get('pairs'):
        await update.message.reply_text("❌ No active pair found. ❌")
        return ConversationHandler.END

    pair_list = users_data[user_id]['pairs']['list']
    keyboard = [[u] for u in pair_list]
    keyboard.append(["All"])
    
    from telegram import ReplyKeyboardMarkup
    reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    await update.message.reply_text("🔗 𝐒𝐞𝐥𝐞𝐜𝐭 𝐚𝐜𝐜𝐨𝐮𝐧𝐭 𝐭𝐨 𝐮𝐧𝐩𝐚𝐢𝐫 (𝐨𝐫 '𝐀𝐥𝐥'):", reply_markup=reply_markup)
    return UNPAIR_SELECT

async def unpair_select(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    text = update.message.text.strip().lower()
    if user_id not in users_data or not users_data[user_id].get('pairs'):
        return ConversationHandler.END
        
    data = users_data[user_id]
    pair_info = data['pairs']
    pair_list = pair_info['list']

    from telegram import ReplyKeyboardRemove
    if text == "all":
        data['pairs'] = None
        save_user_data(user_id, data)
        await update.message.reply_text("🧹 All paired accounts removed successfully.", reply_markup=ReplyKeyboardRemove())
    elif text in [u.lower() for u in pair_list]:
        # find original casing
        target = next(u for u in pair_list if u.lower() == text)
        pair_list.remove(target)
        if not pair_list:
            data['pairs'] = None
            msg = f"✅ Removed {target}. No pairs left."
        else:
            if pair_info.get('default_index', 0) >= len(pair_list):
                pair_info['default_index'] = 0
            msg = f"✅ Removed {target}. Remaining pairs: {', '.join(pair_list)}"
        save_user_data(user_id, data)
        await update.message.reply_text(msg, reply_markup=ReplyKeyboardRemove())
    else:
        await update.message.reply_text("⚠️ Invalid selection. Please use the buttons.")
        return UNPAIR_SELECT
    
    return ConversationHandler.END

async def switch_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    # help_text = ... (fancy font)
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("❗ Usage: /switch <minutes> ❗")
        return
    min_ = int(context.args[0])
    data = users_data[user_id]
    if not data.get('pairs') or len(data['pairs']['list']) < 2:
        await update.message.reply_text("⚠️ No pair found. Use /pair first. ⚠️")
        return
    if min_ < 5:
        await update.message.reply_text("⚠️ Minimum switch interval is 5 minutes. ⚠️")
        return
    data['switch_minutes'] = min_
    save_user_data(user_id, data)
    await update.message.reply_text(f"⏱️ Switch interval set to {min_} minutes.")

async def threads_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    # help_text = ... (fancy font)
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("❗ Usage: /threads <1-5> ❗")
        return
    n = int(context.args[0])
    if n < 1 or n > 5:
        await update.message.reply_text("⚠️ threads must be between 1 and 5. ⚠️")
        return
    data = users_data[user_id]
    data['threads'] = n
    save_user_data(user_id, data)
    await update.message.reply_text(f"🔁 Threads set to {n}.")

async def viewpref(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if user_id not in users_data:
        await update.message.reply_text("❌ No data. Use /login. ❌")
        return
    data = users_data[user_id]
    saved_accounts = ', '.join([acc['ig_username'] for acc in data['accounts']])
    msg = "🔧 Your bot preferences:\n"
    if data.get('pairs'):
        pl = data['pairs']['list']
        msg += f"Pairs: yes — {len(pl)} accounts\n"
        default_idx = data['pairs']['default_index']
        default_u = pl[default_idx]
        msg += f"Default: {default_u} ⭐\n"
    else:
        msg += "Pairs: no\n"
    switch_min = data.get('switch_minutes', 10)
    msg += f"⏱️ Switch interval: {switch_min} minutes\n"
    threads = data.get('threads', 1)
    msg += f"🧵 Threads: {threads}\n"
    msg += f"👤 Saved accounts: {saved_accounts}\n"
    # Check running attacks
    tasks = users_tasks.get(user_id, [])
    running_attacks = [t for t in tasks if t.get('type') == 'message_attack' and t['status'] == 'running' and t['proc'].poll() is None]
    if running_attacks:
        task = running_attacks[0]  # Assume one
        pid = task['pid']
        ttype = task['target_type']
        tdisplay = task['target_display']
        disp = f"dm -> @{tdisplay}" if ttype == 'dm' else tdisplay
        msg += f"\nActive attack PID {pid} ({disp})\n"
        msg += "Spamming...!\n"
        pair_list = task['pair_list']
        curr_idx = task['pair_index']
        curr_u = pair_list[curr_idx]
        for u in pair_list:
            if u == curr_u:
                msg += f"using - {u}\n"
            else:
                msg += f"cooldown - {u}\n"
    await update.message.reply_text(msg)

SELECT_ACCOUNT, TARGET_TYPE, TARGET, MESSAGES = range(4)

async def attack_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if user_id not in users_data or not users_data[user_id]['accounts']:
        await update.message.reply_text("❌ No accounts saved. Use /login first. ❌")
        return ConversationHandler.END
    
    data = users_data[user_id]
    keyboard = []
    for i, acc in enumerate(data['accounts']):
        keyboard.append([f"{i+1}. {acc['ig_username']}"])
    
    from telegram import ReplyKeyboardMarkup
    reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    await update.message.reply_text("🎯 𝐒𝐞𝐥𝐞𝐜𝐭 𝐚𝐜𝐜𝐨𝐮𝐧𝐭 𝐭𝐨 𝐮𝐬𝐞:", reply_markup=reply_markup)
    return SELECT_ACCOUNT

async def select_account(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    text = update.message.text
    try:
        idx = int(text.split('.')[0]) - 1
        context.user_data['selected_account_idx'] = idx
    except Exception:
        await update.message.reply_text("⚠️ Invalid selection. Please choose from the menu. ⚠️")
        return SELECT_ACCOUNT

    keyboard = [["👥 Group Chat (GC)"], ["👤 Direct Message (DM)"]]
    from telegram import ReplyKeyboardMarkup
    reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    await update.message.reply_text("📂 𝐒𝐞𝐥𝐞𝐜𝐭 𝐭𝐚𝐫𝐠𝐞𝐭 𝐭𝐲𝐩𝐞:", reply_markup=reply_markup)
    return TARGET_TYPE

async def select_target_type(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    choice = update.message.text
    if "Group" in choice:
        context.user_data['mode'] = 'gc'
        await update.message.reply_text("🔗 𝐄𝐧𝐭𝐞𝐫 𝐆𝐫𝐨𝐮𝐩 𝐂𝐡𝐚𝐭 𝐔𝐑𝐋:")
    else:
        context.user_data['mode'] = 'dm'
        await update.message.reply_text("👤 𝐄𝐧𝐭𝐞𝐫 𝐓𝐚𝐫𝐠𝐞𝐭 𝐔𝐬𝐞𝐫𝐧𝐚𝐦𝐞:")
    return TARGET

async def select_target(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    target = update.message.text.strip().lstrip('@')
    user_id = update.effective_user.id
    mode = context.user_data['mode']
    
    if mode == 'dm':
        data = users_data[user_id]
        acc_idx = context.user_data['selected_account_idx']
        acc = data['accounts'][acc_idx]
        await update.message.reply_text("🔍 Fetching thread ID...")
        thread_url = await asyncio.to_thread(
            get_dm_thread_url, user_id, acc['ig_username'], acc['password'], target
        )
        if not thread_url:
            await update.message.reply_text("❌ Could not find thread for this user. ❌")
            return ConversationHandler.END
        context.user_data['thread_url'] = thread_url
        context.user_data['target_display'] = target
    else:
        context.user_data['thread_url'] = target
        context.user_data['target_display'] = "Group Chat"

    await update.message.reply_text("📝 𝐄𝐧𝐭𝐞𝐫 𝐦𝐞𝐬𝐬𝐚𝐠𝐞𝐬 (𝐮𝐬𝐞 '&' 𝐨𝐫 'and' 𝐭𝐨 𝐬𝐞𝐩𝐚𝐫𝐚𝐭𝐞):")
    return MESSAGES

async def get_attack_messages(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    return await get_messages(update, context)

async def get_messages(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    raw_text = update.message.text.strip()
    logging.debug("RAW MESSAGES INPUT: %r", raw_text)

    # Normalize to handle fullwidth & etc.
    text = unicodedata.normalize("NFKC", raw_text)

    # Always make a temp file
    import uuid, os, json, time, random
    randomid = str(uuid.uuid4())[:8]
    names_file = f"{user_id}_{randomid}.txt"

    # ✅ Write raw text directly so msgb.py handles splitting correctly
    try:
        with open(names_file, 'w', encoding='utf-8') as f:
            f.write(text)
    except Exception as e:
        await update.message.reply_text(f"❌ Error creating file: {e}")
        return ConversationHandler.END

    # --- Below part unchanged (keeps rotation, task limits, etc.) ---
    data = users_data[user_id]
    pairs = data.get('pairs')
    pair_list = pairs['list'] if pairs else [data['accounts'][data['default']]['ig_username']]
    if len(pair_list) == 1:
        warning = "⚠️ Warning: You may get chat ban if you use a single account too long. Use /pair to make multi-account rotation.\n\n"
    else:
        warning = ""
    switch_minutes = data.get('switch_minutes', 10)
    threads_n = data.get('threads', 1)
    tasks = users_tasks.get(user_id, [])
    running_msg = [t for t in tasks if t.get('type') == 'message_attack' and t['status'] == 'running' and t['proc'].poll() is None]
    if len(running_msg) >= 5:
        await update.message.reply_text("⚠️ Max 5 message attacks running. Stop one first. ⚠️")
        if os.path.exists(names_file):
            os.remove(names_file)
        return ConversationHandler.END

    thread_url = context.user_data['thread_url']
    target_display = context.user_data['target_display']
    target_mode = context.user_data['mode']
    start_idx = pairs['default_index'] if pairs else 0
    start_u = pair_list[start_idx]
    start_acc = next(acc for acc in data['accounts'] if acc['ig_username'] == start_u)
    start_pass = start_acc['password']
    start_u = start_u.strip().lower()
    state_file = f"sessions/{user_id}_{start_u}_state.json"
    if not os.path.exists(state_file):
        with open(state_file, 'w') as f:
            json.dump(start_acc['storage_state'], f)

    cmd = [
        "python3", "msg.py",
        "--username", start_u,
        "--password", start_pass,
        "--thread-url", thread_url,
        "--names", names_file,
        "--tabs", str(threads_n),
        "--headless", "true",
        "--storage-state", state_file
    ]
    proc = subprocess.Popen(cmd)
    running_processes[proc.pid] = proc
    pid = proc.pid
    task_id = str(uuid.uuid4())
    task = {
        "id": task_id,
        "user_id": user_id,
        "type": "message_attack",
        "pair_list": pair_list,
        "pair_index": start_idx,
        "switch_minutes": switch_minutes,
        "threads": threads_n,
        "names_file": names_file,
        "target_thread_url": thread_url,
        "target_type": target_mode,
        "target_display": target_display,
        "last_switch_time": time.time(),
        "status": "running",
        "cmd": cmd,
        "pid": pid,
        "display_pid": pid,
        "proc_list": [pid],
        "proc": proc,
        "start_time": time.time()
    }
    persistent_tasks.append(task)
    save_persistent_tasks()
    tasks.append(task)
    users_tasks[user_id] = tasks
    logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Message attack start user={user_id} task={task_id} target={target_display} pid={pid}")

    status = "Spamming...!\n"
    curr_u = pair_list[task['pair_index']]
    for u in pair_list:
        if u == curr_u:
            status += f"using - {u}\n"
        else:
            status += f"cooldown - {u}\n"
    status += f"To stop 🛑 type /stop {task['display_pid']} or /stop all to stop all processes."

    sent_msg = await update.message.reply_text(warning + status)
    task['status_chat_id'] = update.message.chat_id
    task['status_msg_id'] = sent_msg.message_id
    return ConversationHandler.END

def load_persistent_tasks():
    global persistent_tasks
    if os.path.exists(TASKS_FILE):
        with open(TASKS_FILE, 'r') as f:
            persistent_tasks = json.load(f)
    else:
        persistent_tasks = []

def save_persistent_tasks():
    """
    Safely write persistent_tasks to TASKS_FILE.
    Removes runtime-only values (like 'proc') and ensures JSON-safe data.
    """
    safe_list = []
    for t in persistent_tasks:
        cleaned = {}
        for k, v in t.items():
            if k == 'proc':
                continue
            if isinstance(v, (int, float, str, bool, dict, list, type(None))):
                cleaned[k] = v
            else:
                try:
                    json.dumps(v)
                    cleaned[k] = v
                except Exception:
                    cleaned[k] = str(v)
        safe_list.append(cleaned)

    temp_file = TASKS_FILE + '.tmp'
    with open(temp_file, 'w') as f:
        json.dump(safe_list, f, indent=2)
    os.replace(temp_file, TASKS_FILE)

def mark_task_stopped_persistent(task_id: str):
    global persistent_tasks
    for task in persistent_tasks:
        if task['id'] == task_id:
            task['status'] = 'stopped'
            save_persistent_tasks()
            break

def update_task_pid_persistent(task_id: str, new_pid: int):
    global persistent_tasks
    for task in persistent_tasks:
        if task['id'] == task_id:
            task['pid'] = new_pid
            save_persistent_tasks()
            break

def mark_task_completed_persistent(task_id: str):
    global persistent_tasks
    for task in persistent_tasks:
        if task['id'] == task_id:
            task['status'] = 'completed'
            save_persistent_tasks()
            break

def restore_tasks_on_start():
    load_persistent_tasks()
    print(f"🔄 Restoring {len([t for t in persistent_tasks if t.get('type') == 'message_attack' and t['status'] == 'running'])} running message attacks...")
    for task in persistent_tasks[:]:
        if task.get('type') == 'message_attack' and task['status'] == 'running':
            old_pid = task['pid']
            try:
                os.kill(old_pid, signal.SIGTERM)
                time.sleep(1)
            except OSError:
                pass  # Already dead
            user_id = task['user_id']
            data = users_data.get(user_id)
            if not data:
                mark_task_stopped_persistent(task['id'])
                continue
            pair_list = task['pair_list']
            curr_idx = task['pair_index']
            curr_u = pair_list[curr_idx]
            curr_acc = None
            for acc in data['accounts']:
                if acc['ig_username'] == curr_u:
                    curr_acc = acc
                    break
            if not curr_acc:
                mark_task_stopped_persistent(task['id'])
                continue
            curr_pass = curr_acc['password']
            curr_u = curr_u.strip().lower()
            state_file = f"sessions/{user_id}_{curr_u}_state.json"
            if not os.path.exists(state_file):
                with open(state_file, 'w') as f:
                    json.dump(curr_acc['storage_state'], f)
            names_file = task['names_file']
            if not os.path.exists(names_file):
                # Recreate if missing? But skip for now
                mark_task_stopped_persistent(task['id'])
                continue
            cmd = [
                "python3", "msg.py",
                "--username", curr_u,
                "--password", curr_pass,
                "--thread-url", task['target_thread_url'],
                "--names", names_file,
                "--tabs", str(task['threads']),
                "--headless", "true",
                "--storage-state", state_file
            ]
            try:
                proc = subprocess.Popen(cmd)
                # Register runtime map
                running_processes[proc.pid] = proc
                new_pid = proc.pid
                update_task_pid_persistent(task['id'], new_pid)
                mem_task = task.copy()
                mem_task['proc'] = proc
                mem_task['proc_list'] = [proc.pid]
                mem_task['display_pid'] = task.get('display_pid', proc.pid)
                if user_id not in users_tasks:
                    users_tasks[user_id] = []
                users_tasks[user_id].append(mem_task)
                print(f"✅ Restored message attack {task['id']} for {task['target_display']} | New PID: {new_pid}")
            except Exception as e:
                logging.error(f"❌ Failed to restore message attack {task['id']}: {e}")
                mark_task_stopped_persistent(task['id'])
    save_persistent_tasks()
    print("✅ Task restoration complete!")

async def send_resume_notification(user_id: int, task: Dict):
    ttype = task['target_type']
    tdisplay = task['target_display']
    disp = f"dm -> @{tdisplay}" if ttype == 'dm' else tdisplay
    msg = f"🔄 Attack auto resumed! New PID: {task['pid']} ({disp})\n"
    pair_list = task['pair_list']
    curr_idx = task['pair_index']
    curr_u = pair_list[curr_idx]
    for u in pair_list:
        if u == curr_u:
            msg += f"using - {u}\n"
        else:
            msg += f"cooldown - {u}\n"
    await APP.bot.send_message(chat_id=user_id, text=msg)

def get_switch_update(task: Dict) -> str:
    pair_list = task['pair_list']
    curr_idx = task['pair_index']
    curr_u = pair_list[curr_idx]
    lines = []
    for u in pair_list:
        if u == curr_u:
            lines.append(f"using - {u}")
        else:
            lines.append(f"cooldown - {u}")
    return '\n'.join(lines)

def switch_task_sync(task: Dict):
    user_id = task['user_id']

    # Keep reference to old proc (don't terminate it yet)
    try:
        old_proc = task.get('proc')
        old_pid = task.get('pid')
    except Exception:
        old_proc = None
        old_pid = task.get('pid')

    # Advance index first so new account is chosen
    task['pair_index'] = (task['pair_index'] + 1) % len(task['pair_list'])
    next_u = task['pair_list'][task['pair_index']]
    data = users_data.get(user_id)
    if not data:
        logging.error(f"No users_data for user {user_id} during switch")
        return

    next_acc = next((a for a in data['accounts'] if a['ig_username'] == next_u), None)
    if not next_acc:
        logging.error(f"Can't find account {next_u} for switch")
        try:
            asyncio.run_coroutine_threadsafe(
                APP.bot.send_message(user_id, f"can't find thread Id - {next_u}"),
                LOOP
            )
        except Exception:
            pass
        return

    next_pass = next_acc['password']
    next_state_file = f"sessions/{user_id}_{next_u}_state.json"
    if not os.path.exists(next_state_file):
        try:
            with open(next_state_file, 'w') as f:
                json.dump(next_acc.get('storage_state', {}), f)
        except Exception as e:
            logging.error(f"Failed to write state file for {next_u}: {e}")

    # Launch new process FIRST so overlap prevents downtime
    new_cmd = [
        "python3", "msg.py",
        "--username", next_u,
        "--password", next_pass,
        "--thread-url", task['target_thread_url'],
        "--names", task['names_file'],
        "--tabs", str(task['threads']),
        "--headless", "true",
        "--storage-state", next_state_file
    ]
    try:
        new_proc = subprocess.Popen(new_cmd)
    except Exception as e:
        logging.error(f"Failed to launch new proc for switch to {next_u}: {e}")
        return

    # Append new to proc_list
    task['proc_list'].append(new_proc.pid)

    # Register new proc and update task/persistent info
    running_processes[new_proc.pid] = new_proc
    task['cmd'] = new_cmd
    task['pid'] = new_proc.pid
    task['proc'] = new_proc
    task['last_switch_time'] = time.time()
    try:
        update_task_pid_persistent(task['id'], task['pid'])
    except Exception as e:
        logging.error(f"Failed to update persistent pid for task {task.get('id')}: {e}")

    # Give old proc a short cooldown window before killing it (avoid downtime)
    if old_proc and old_pid != new_proc.pid:
        try:
            # Allow overlap for a short cooldown
            time.sleep(5)
            try:
                old_proc.terminate()
            except Exception:
                pass
            # wait a bit for graceful shutdown
            time.sleep(2)
            if old_proc.poll() is None:
                try:
                    old_proc.kill()
                except Exception:
                    pass
            # Remove old from proc_list and running_processes
            if old_pid in task['proc_list']:
                task['proc_list'].remove(old_pid)
            if old_pid in running_processes:
                running_processes.pop(old_pid, None)
        except Exception as e:
            logging.error(f"Error while stopping old proc after switch: {e}")

    # Send/update status message (edit if message id present)
    try:
        chat_id = task.get('status_chat_id', user_id)
        msg_id = task.get('status_msg_id')
        text = "Spamming...!\n" + get_switch_update(task)
        text += f"\nTo stop 🛑 type /stop {task['display_pid']} or /stop all to stop all processes."
        if msg_id:
            asyncio.run_coroutine_threadsafe(
                APP.bot.edit_message_text(chat_id=chat_id, message_id=msg_id, text=text),
                LOOP
            )
        else:
            asyncio.run_coroutine_threadsafe(
                APP.bot.send_message(chat_id=chat_id, text=text),
                LOOP
            )
    except Exception as e:
        logging.error(f"Failed to update status message: {e}")

def switch_monitor():
    while True:
        time.sleep(30)
        for user_id in list(users_tasks):
            if user_id not in users_tasks:
                continue
            for task in users_tasks[user_id]:
                if task.get('type') == 'message_attack' and task['status'] == 'running' and task['proc'].poll() is None:
                    due_time = task['last_switch_time'] + task['switch_minutes'] * 60
                    if time.time() >= due_time:
                        if len(task['pair_list']) > 1:
                            switch_task_sync(task)

async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    # help_text = ... (fancy font)
    if not context.args:
        await update.message.reply_text("❗ Usage: /stop <PID> or /stop all ❗")
        return
    arg = context.args[0]
    if user_id not in users_tasks or not users_tasks[user_id]:
        await update.message.reply_text("❌ No tasks running. ❌")
        return
    tasks = users_tasks[user_id]
    if arg == 'all':
        stopped_count = 0
        for task in tasks[:]:
            proc = task['proc']
            proc.terminate()
            await asyncio.sleep(3)
            if proc.poll() is None:
                proc.kill()
            # Remove from runtime map if present
            pid = task.get('pid')
            if pid in running_processes:
                running_processes.pop(pid, None)
            if task.get('type') == 'message_attack' and 'names_file' in task:
                names_file = task['names_file']
                if os.path.exists(names_file):
                    os.remove(names_file)
            logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Task stop user={user_id} task={task['id']}")
            mark_task_stopped_persistent(task['id'])
            tasks.remove(task)
            stopped_count += 1
        await update.message.reply_text(f"🛑 Stopped all your tasks! ({stopped_count}) 🛑")
    elif arg.isdigit():
        pid_to_stop = int(arg)
        stopped_task = None

        # 1) Try users_tasks by display_pid
        for task in tasks[:]:
            if task.get('display_pid') == pid_to_stop:
                proc_list = task.get('proc_list', [])
                for backend_pid in proc_list:
                    backend_proc = running_processes.get(backend_pid)
                    if backend_proc:
                        try:
                            backend_proc.terminate()
                        except Exception:
                            pass
                        await asyncio.sleep(3)
                        if backend_proc.poll() is None:
                            try:
                                backend_proc.kill()
                            except Exception:
                                pass
                    else:
                        try:
                            os.kill(backend_pid, signal.SIGTERM)
                        except Exception:
                            pass
                for backend_pid in proc_list:
                    running_processes.pop(backend_pid, None)
                mark_task_stopped_persistent(task['id'])
                if 'names_file' in task and os.path.exists(task['names_file']):
                    os.remove(task['names_file'])
                stopped_task = task
                tasks.remove(task)
                await update.message.reply_text(f"🛑 Stopped task {pid_to_stop}!")
                break

        # 2) If not found, fallback to runtime map for single pid
        if not stopped_task:
            proc = running_processes.get(pid_to_stop)
            if proc:
                try: proc.terminate()
                except Exception: pass
                await asyncio.sleep(2)
                if proc.poll() is None:
                    try: proc.kill()
                    except Exception: pass
                running_processes.pop(pid_to_stop, None)
                for t in persistent_tasks:
                    if t.get('pid') == pid_to_stop:
                        mark_task_stopped_persistent(t['id'])
                        break
                await update.message.reply_text(f"🛑 Stopped task {pid_to_stop}!")
                return

        if not stopped_task:
            await update.message.reply_text("⚠️ Task not found. ⚠️")
    else:
        await update.message.reply_text("❗ Usage: /stop <PID> or /stop all ❗")
    users_tasks[user_id] = tasks

async def task_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    # help_text = ... (fancy font)
    if user_id not in users_tasks or not users_tasks[user_id]:
        await update.message.reply_text("❌ No ongoing tasks. ❌")
        return
    tasks = users_tasks[user_id]
    active_tasks = []
    for t in tasks:
        if t['proc'].poll() is None:
            active_tasks.append(t)
        else:
            mark_task_completed_persistent(t['id'])
    users_tasks[user_id] = active_tasks
    if not active_tasks:
        await update.message.reply_text("❌ No active tasks. ❌")
        return
    msg = "📋 Ongoing tasks 📋\n"
    for task in active_tasks:
        tdisplay = task.get('target_display', 'Unknown')
        ttype = task.get('type', 'unknown')
        preview = tdisplay[:20] + '...' if len(tdisplay) > 20 else tdisplay
        display_pid = task.get('display_pid', task['pid'])
        msg += f"PID {display_pid} — {preview} ({ttype})\n"
    await update.message.reply_text(msg)

    if len(context.args) != 1:
        await update.message.reply_text("❗ Usage: /add <tg_id> ❗")
        return
    try:
        tg_id = int(context.args[0])
        if any(u['id'] == tg_id for u in authorized_users):
            await update.message.reply_text("❗ User already added. ❗")
            return
        authorized_users.append({'id': tg_id, 'username': ''})
        save_authorized()
        await update.message.reply_text(f"➕ Added {tg_id} as authorized user. ➕")
    except ValueError:
        await update.message.reply_text("❗ Invalid Telegram ID. ❗")

def main_bot():
    from telegram.request import HTTPXRequest
    request = HTTPXRequest(connect_timeout=30, read_timeout=30, write_timeout=30)
    application = Application.builder().token(BOT_TOKEN).request(request).build()
    global APP, LOOP
    APP = application
    LOOP = asyncio.get_event_loop()

    # Restore tasks
    restore_tasks_on_start()

    # Start switch monitor
    monitor_thread = threading.Thread(target=switch_monitor, daemon=True)
    monitor_thread.start()

    # Post init for notifications
    async def post_init(app):
        for user_id, tasks_list in list(users_tasks.items()):
            for task in tasks_list:
                if task.get('type') == 'message_attack' and task['status'] == 'running':
                    await send_resume_notification(user_id, task)

    application.post_init = post_init

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("viewmyac", viewmyac))
    
    conv_setig = ConversationHandler(
        entry_points=[CommandHandler("setig", setig)],
        states={
            SETIG_SELECT: [MessageHandler(filters.TEXT & ~filters.COMMAND, setig_select)],
        },
        fallbacks=[],
    )
    application.add_handler(conv_setig)

    application.add_handler(CommandHandler("pair", pair_command))

    conv_unpair = ConversationHandler(
        entry_points=[CommandHandler("unpair", unpair_command)],
        states={
            UNPAIR_SELECT: [MessageHandler(filters.TEXT & ~filters.COMMAND, unpair_select)],
        },
        fallbacks=[],
    )
    application.add_handler(conv_unpair)

    application.add_handler(CommandHandler("switch", switch_command))
    application.add_handler(CommandHandler("threads", threads_command))
    application.add_handler(CommandHandler("viewpref", viewpref))
    application.add_handler(CommandHandler("stop", stop))
    application.add_handler(CommandHandler("task", task_command))

    conv_logout = ConversationHandler(
        entry_points=[CommandHandler("logout", logout_command)],
        states={
            LOGOUT_SELECT: [MessageHandler(filters.TEXT & ~filters.COMMAND, logout_select)],
        },
        fallbacks=[],
    )
    application.add_handler(conv_logout)

    application.add_handler(CommandHandler("kill", cmd_kill))
    application.add_handler(CommandHandler("sessionid", login_session_start))

    application.add_handler(CommandHandler("login", login_start))
    conv_login_session = ConversationHandler(
        entry_points=[CommandHandler("login_session", login_session_start)],
        states={
            SESSION_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_session_id)],
        },
        fallbacks=[],
    )
    application.add_handler(conv_login_session)

    conv_login = ConversationHandler(
        entry_points=[CommandHandler("login", login_start)],
        states={
            LOGIN_CHOICE: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_login_choice)],
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_username)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_password)],
            SESSION_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_session_id)],
        },
        fallbacks=[],
    )
    application.add_handler(conv_login)

    conv_attack = ConversationHandler(
        entry_points=[CommandHandler("attack", attack_start)],
        states={
            SELECT_ACCOUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, select_account)],
            TARGET_TYPE: [MessageHandler(filters.TEXT & ~filters.COMMAND, select_target_type)],
            TARGET: [MessageHandler(filters.TEXT & ~filters.COMMAND, select_target)],
            MESSAGES: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_attack_messages)],
        },
        fallbacks=[],
    )
    application.add_handler(conv_attack)

    conv_login_session = ConversationHandler(
        entry_points=[CommandHandler("login_session", login_session_start)],
        states={
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_username_session)],
            SESSION_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_session_id)],
        },
        fallbacks=[],
    )
    application.add_handler(conv_login_session)

    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, relay_input))

    print("🚀 DEV POWER BOT starting with message attack system!")
    application.run_polling()

if __name__ == "__main__":
    main_bot()