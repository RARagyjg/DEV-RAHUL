# -*- coding: utf-8 -*-
import asyncio
import logging
import random
import os
import sys
import base64
import subprocess

# ================== AUTO INSTALL PLAYWRIGHT + BROWSERS ==================
try:
    from playwright.async_api import async_playwright
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "playwright"])
    from playwright.async_api import async_playwright
    subprocess.check_call([sys.executable, "-m", "playwright", "install", "chromium"])

# ================== CONFIG ==================
ENCODED_PASSWORD = "REVWWERJVlU="  # DEVWDDIVU (base64)
MESSAGES = ["HI BRO ❤️"]

# ================== UTILS ===================
def decode_str(s):
    return base64.b64decode(s).decode("utf-8")

logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(message)s")

# ================== ENV VARIABLES =================
SCRIPT_PASSWORD = os.getenv("SCRIPT_PASSWORD")
SESSION_ID      = os.getenv("SESSION_ID")
DM_URL          = os.getenv("DM_URL")
TARGET_NAME     = os.getenv("TARGET_NAME", "USER")
TASK_COUNT      = int(os.getenv("TASK_COUNT", "20"))

if not SCRIPT_PASSWORD or SCRIPT_PASSWORD != decode_str(ENCODED_PASSWORD):
    print("❌ Invalid or missing SCRIPT_PASSWORD")
    sys.exit(1)

if not SESSION_ID or not DM_URL:
    print("❌ SESSION_ID or DM_URL missing")
    sys.exit(1)

if TASK_COUNT > 80:
    TASK_COUNT = 80

# ================== STATS ===================
success_count = 0
unsuccess_count = 0
counter_lock = asyncio.Lock()

def print_stats():
    sys.stdout.write(f"\r✅ success: {success_count} ❌ fail: {unsuccess_count}")
    sys.stdout.flush()

# ================== WORKER ===================
async def send_loop(context):
    global success_count, unsuccess_count
    page = await context.new_page()

    # save RAM by blocking images/videos/ads
    await page.route("**/*.{png,jpg,jpeg,gif,webp,svg,mp4,webm,ogg}", lambda r: r.abort())
    await page.route("**/ads/**", lambda r: r.abort())

    page.set_default_timeout(600000)
    page.set_default_navigation_timeout(600000)

    while True:
        try:
            await page.goto(DM_URL, wait_until="domcontentloaded")
            msg_input = page.locator('div[aria-label="Message"][role="textbox"]')
            await msg_input.wait_for()

            base_msg = random.choice(MESSAGES).replace("{target}", TARGET_NAME)
            await msg_input.fill(base_msg)
            # Typing bubble simulation
            await asyncio.sleep(random.uniform(0.5, 1.5))
            await page.keyboard.press("Enter")

            async with counter_lock:
                success_count += 1
                print_stats()

            await asyncio.sleep(random.uniform(2, 5))

        except Exception:
            async with counter_lock:
                unsuccess_count += 1
                print_stats()
            await asyncio.sleep(5)

# ================== MAIN ====================
async def main():
    async with async_playwright() as p:
        # launch chromium headless
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-setuid-sandbox",
                "--no-first-run",
                "--no-zygote",
            ],
        )

        context = await browser.new_context()
        await context.add_cookies([{
            "name": "sessionid",
            "value": SESSION_ID,
            "domain": ".instagram.com",
            "path": "/",
            "httpOnly": True,
            "secure": True,
            "sameSite": "None",
        }])

        print(f"\n🚀 Starting {TASK_COUNT} tasks...\n")
        tasks = [asyncio.create_task(send_loop(context)) for _ in range(TASK_COUNT)]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
