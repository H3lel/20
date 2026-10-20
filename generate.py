"""
ElevenLabs API key generator (concurrent).

Per run:
  1. Create a disposable inbox via Mail.tm
  2. Sign up on ElevenLabs
  3. Wait for the verification email via Mail.tm
  4. Open the verification link, complete login + onboarding
  5. Create an API key (Never expires, unrestricted)
  6. Append (email, password, token) to data.csv

Usage:
  python main.py                     # one run
  python main.py 20                  # twenty runs, sequential (interactive)
  python main.py 20 5                # twenty runs, five concurrent

Environment:
  PASSWORD must be set (via .env or shell) to the ElevenLabs account password.

Notes:
  Concurrency here uses asyncio tasks + a Semaphore, not OS threads.
  Each concurrent run gets its own BrowserContext (cookies isolated).
  Requires cloakbrowser's `humanize` to apply to contexts created via
  `browser.new_context()`; if it does not, humanisation is per-browser only.
"""
from __future__ import annotations

import asyncio
import csv
import html
import logging
import os
import re
import sys
import traceback
import uuid
from pathlib import Path
from typing import Awaitable, Callable, Optional

import httpx
from dotenv import load_dotenv
from playwright.async_api import Browser, BrowserContext, Page, expect

from cloakbrowser import launch_async

# --------------------------------------------------------------------- config
CSV_PATH = Path("data.csv")
SIGNUP_URL = "https://elevenlabs.io/app/sign-up"
KEYS_URL = "https://elevenlabs.io/app/developers/api-keys"

MAILTM_BASE = "https://api.mail.tm"
MAILTM_POLL_S = 5.0
MAILTM_WAIT_S = 180.0

BLOCKED_DOMAINS: set[str] = {
    "guerrillamailblock.com",
    "sharklasers.com",
    "grr.la",
    "guerrillamail.info",
}

VERIFY_URL_RE = re.compile(r'https?://[^\s"\'<>]+mode=verifyEmail[^\s"\'<>]*')
TOKEN_MIN, TOKEN_MAX = 20, 200

log = logging.getLogger("elevenlabs-bot")


# --------------------------------------------------------------------- helpers
def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%H:%M:%S",
    )


def parse_args(argv: list[str]) -> tuple[int, int]:
    """Return (total_runs, concurrency) from argv[1:]."""
    total = 1
    concurrency = 1

    if len(argv) >= 2:
        try:
            total = int(argv[1])
        except ValueError:
            raise SystemExit(f"Usage: python {argv[0]} [N] [CONCURRENCY]")
        if total < 1:
            raise SystemExit("N must be a positive integer")

    if len(argv) >= 3:
        try:
            concurrency = int(argv[2])
        except ValueError:
            raise SystemExit(f"Usage: python {argv[0]} [N] [CONCURRENCY]")
        if concurrency < 1:
            raise SystemExit("CONCURRENCY must be a positive integer")

    return total, concurrency


async def retry_async(
    fn: Callable[[], Awaitable[dict]],
    *,
    attempts: int = 3,
    base_delay: float = 1.0,
    label: str = "request",
) -> dict:
    for i in range(attempts):
        try:
            return await fn()
        except (httpx.ConnectError, httpx.ReadError,
                httpx.RemoteProtocolError) as e:
            if i == attempts - 1:
                raise
            delay = base_delay * (2 ** i)
            log.warning("%s attempt %d/%d failed (%r); retry in %.1fs",
                        label, i + 1, attempts, e, delay)
            await asyncio.sleep(delay)
    raise RuntimeError("unreachable")


def validate_token(token: Optional[str]) -> None:
    if not token or "\n" in token:
        raise ValueError(f"Invalid token: {token!r}")
    if not (TOKEN_MIN <= len(token) <= TOKEN_MAX):
        raise ValueError(
            f"Token length {len(token)} not in "
            f"[{TOKEN_MIN}, {TOKEN_MAX}]: {token!r}"
        )
    if not token.startswith("sk_"):
        log.warning("Token does not start with 'sk_': %r", token[:20])


def append_to_csv(email: str, password: str, token: str) -> None:
    new_file = not CSV_PATH.exists() or CSV_PATH.stat().st_size == 0
    with CSV_PATH.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["email", "password", "token"])
        w.writerow([email, password, token])
    log.info("Saved row to %s", CSV_PATH)


# --------------------------------------------------------------------- Mail.tm
class MailTM:
    """Async client for Mail.tm with retry + domain selection."""

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None
        self.address: Optional[str] = None
        self.password: Optional[str] = None
        self.jwt: Optional[str] = None

    async def __aenter__(self) -> "MailTM":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, read=60.0),
            follow_redirects=True,
            trust_env=False,
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request(self, method: str, path: str, **kw) -> dict:
        assert self._client is not None, "use MailTM as async context manager"

        async def _do() -> dict:
            r = await self._client.request(method, f"{MAILTM_BASE}{path}", **kw)
            r.raise_for_status()
            return r.json()

        return await retry_async(_do, label=f"mail.tm {method} {path}")

    async def create_inbox(self) -> str:
        domains = (await self._request("GET", "/domains")).get(
            "hydra:member", [])
        candidates = [
            d["domain"] for d in domains
            if d.get("isActive", True)
            and d["domain"] not in BLOCKED_DOMAINS
        ]
        if not candidates:
            raise RuntimeError("Mail.tm: no unblocked domain available")

        self.password = str(uuid.uuid4())
        local = f"user{int(asyncio.get_running_loop().time() * 1000) % 10**9}"

        for domain in candidates:
            address = f"{local}@{domain}"
            try:
                account = await self._request(
                    "POST", "/accounts",
                    json={"address": address, "password": self.password},
                )
            except httpx.HTTPStatusError:
                log.warning("Mail.tm: %s rejected, trying next", domain)
                continue
            self.address = account.get("address", address)
            break
        else:
            raise RuntimeError("Mail.tm: every domain rejected account creation")

        token_data = await self._request(
            "POST", "/token",
            json={"address": self.address, "password": self.password},
        )
        self.jwt = token_data["token"]
        log.info("Mail.tm inbox: %s", self.address)
        return self.address

    async def wait_for_verification_link(self) -> str:
        assert self.jwt and self._client is not None
        headers = {"Authorization": f"Bearer {self.jwt}"}
        deadline = asyncio.get_running_loop().time() + MAILTM_WAIT_S

        while asyncio.get_running_loop().time() < deadline:
            data = await self._request("GET", "/messages", headers=headers)
            for msg in data.get("hydra:member", []):
                if not self._is_verification(msg):
                    continue
                link = await self._fetch_link(msg["id"], headers)
                if link:
                    log.info("Verification link: %s...", link[:70])
                    return link
            await asyncio.sleep(MAILTM_POLL_S)

        raise TimeoutError(
            f"Mail.tm: no verification email within {MAILTM_WAIT_S:.0f}s"
        )

    @staticmethod
    def _is_verification(msg: dict) -> bool:
        sender = (msg.get("from") or {}).get("address", "").lower()
        subject = (msg.get("subject") or "").lower()
        haystack = f"{sender} {subject}"
        return any(k in haystack for k in
                   ("elevenlabs", "eleven", "verify", "verification"))

    async def _fetch_link(self, msg_id: str, headers: dict) -> Optional[str]:
        full = await self._request(
            "GET", f"/messages/{msg_id}", headers=headers)
        bodies: list[str] = []
        if isinstance(full.get("text"), str):
            bodies.append(full["text"])
        html_val = full.get("html")
        if isinstance(html_val, list):
            bodies.extend(html_val)
        elif isinstance(html_val, str):
            bodies.append(html_val)

        for body in bodies:
            m = VERIFY_URL_RE.search(html.unescape(body))
            if m:
                return m.group(0)
        return None


# --------------------------------------------------------------------- Playwright steps
async def submit_signup(
    context: BrowserContext, email: str, password: str
) -> Page:
    page = await context.new_page()
    await page.goto(SIGNUP_URL, wait_until="domcontentloaded")

    email_field = page.get_by_test_id("sign-up-email-input")
    await email_field.wait_for(state="visible")
    await email_field.fill(email)

    pw_field = page.get_by_test_id("sign-up-password-input")
    await pw_field.wait_for(state="visible")
    await pw_field.fill(password)

    btn = page.locator('xpath=//button[normalize-space()="Sign up"]').first
    await btn.wait_for(state="attached")
    try:
        await expect(btn).to_be_enabled(timeout=15000)
    except AssertionError:
        await page.screenshot(path="debug_signup_disabled.png")
        raise RuntimeError("Sign up button never became enabled")

    await btn.click()
    log.info("Signup submitted for %s", email)
    return page


async def open_verification(
    context: BrowserContext, verify_url: str
) -> Page:
    page = await context.new_page()
    await page.goto(verify_url, wait_until="domcontentloaded", timeout=90000)
    log.info("Opened verify URL: %s", page.url)
    return page


async def login_and_onboard(page: Page, email: str, password: str) -> None:
    await page.wait_for_load_state("domcontentloaded")

    dialog = page.get_by_role("dialog", name="Email Verification")
    await dialog.wait_for(state="visible", timeout=60000)
    await page.keyboard.press("Enter")

    email_field = page.get_by_test_id("sign-in-email-input")
    await email_field.wait_for(state="visible")
    await email_field.fill(email)

    pw_field = page.get_by_test_id("sign-in-password-input")
    await pw_field.wait_for(state="visible")
    await pw_field.fill(password)
    await page.keyboard.press("Enter")
    log.info("Login submitted")

    continue_btn = page.locator(
        'xpath=//*[contains(concat(" ", @class, " "), '
        'concat(" ", "duration-0", " "))]'
    ).first
    await continue_btn.wait_for(state="visible", timeout=60000)
    await continue_btn.click()

    checkbox = page.get_by_role("checkbox", name="reached the age of 18")
    await checkbox.wait_for(state="visible")
    await checkbox.check()

    submit = page.locator('button[type="submit"]')
    await expect(submit).to_be_enabled(timeout=60000)
    await submit.click()

    skip = page.get_by_role("button", name="Skip", exact=True)
    try:
        await skip.wait_for(state="visible", timeout=30000)
    except Exception:
        log.info("No skip screens to dismiss")
        return

    for _ in range(3):
        try:
            if not await skip.is_visible():
                break
            await skip.click(timeout=5000)
            await page.wait_for_timeout(150)
        except Exception:
            break
    log.info("Onboarding completed")


async def _configure_key_dialog(page: Page, dialog) -> None:
    try:
        combo = dialog.locator('button[role="combobox"]').first
        if await combo.count() > 0:
            if "never" not in (await combo.inner_text()).strip().lower():
                await combo.click()
                option = page.get_by_role("option", name="Never", exact=True)
                await option.wait_for(state="visible", timeout=5000)
                await option.click()
                log.info("Set Expire After = Never")
    except Exception as e:
        log.warning("Expiry toggle skipped: %r", e)

    switch = dialog.locator(
        'xpath=(//label[normalize-space(.)="Restrict Key"]'
        '/following::button[@role="switch"])[1]'
    )
    try:
        await switch.wait_for(state="visible", timeout=10000)
        if await switch.get_attribute("aria-checked") == "true":
            await switch.click()
            try:
                await expect(switch).to_have_attribute(
                    "aria-checked", "false", timeout=5000)
            except AssertionError:
                pass
            log.info("Restrict Key = OFF (full permissions)")
    except Exception as e:
        log.warning("Restrict Key toggle failed: %r", e)


async def _read_api_key(
    page: Page, container, timeout_s: float = 6.0
) -> Optional[str]:
    deadline = asyncio.get_running_loop().time() + timeout_s
    while asyncio.get_running_loop().time() < deadline:
        for sel, extract in (
            ("input", lambda l, i: l.nth(i).input_value()),
            ("code", lambda l, i: l.nth(i).inner_text()),
        ):
            loc = container.locator(sel)
            for i in range(await loc.count()):
                try:
                    v = (await extract(loc, i)).strip()
                except Exception:
                    continue
                if v.startswith("sk_"):
                    return v
        await page.wait_for_timeout(150)
    return None


async def create_api_key(page: Page) -> str:
    await page.goto(KEYS_URL, wait_until="domcontentloaded")

    create_btn = page.locator(
        'xpath=//*[contains(concat(" ", @class, " "), '
        'concat(" ", "justify-center", " "))]'
        '//*[contains(concat(" ", @class, " "), '
        'concat(" ", "rounded-xl", " "))]'
    ).first
    await create_btn.click()

    dialog = page.get_by_role("dialog")
    await expect(dialog).to_be_visible(timeout=60000)

    await _configure_key_dialog(page, dialog)

    confirm = dialog.get_by_role("button", name="Create Key", exact=True)
    await expect(confirm).to_be_enabled(timeout=60000)
    await confirm.click()

    token = (await _read_api_key(page, dialog)
             or await _read_api_key(page, page))
    if not token:
        await page.screenshot(path="no_token.png", full_page=True)
        raise RuntimeError("Could not read API key; see no_token.png")

    log.info("Token: %s...", token[:16])
    return token


# --------------------------------------------------------------------- orchestration
async def execute_run(
    context: BrowserContext,
    elevenlabs_password: str,
    csv_lock: asyncio.Lock,
) -> str:
    async with MailTM() as mail:
        email = await mail.create_inbox()

        await submit_signup(context, email, elevenlabs_password)
        verify_url = await mail.wait_for_verification_link()
        page = await open_verification(context, verify_url)

        await login_and_onboard(page, email, elevenlabs_password)
        token = await create_api_key(page)

        validate_token(token)
        async with csv_lock:
            await asyncio.to_thread(
                append_to_csv, email, elevenlabs_password, token)
        return token


async def main() -> int:
    setup_logging()
    load_dotenv()

    password = os.getenv("PASSWORD")
    if not password:
        raise SystemExit("PASSWORD missing in .env")

    total, concurrency = parse_args(sys.argv)
    interactive = concurrency == 1
    log.info("Running %d iteration(s), %d concurrent", total, concurrency)

    browser = await launch_async(headless=False, humanize=True)
    csv_lock = asyncio.Lock()
    sem = asyncio.Semaphore(concurrency)
    deferred: list[BrowserContext] = []   # sequential mode: failed contexts
    results: list[bool] = []

    async def run_one(run_id: int) -> None:
        async with sem:
            # Sequential mode: close the previous failed run's window
            if interactive:
                while deferred:
                    ctx = deferred.pop()
                    try:
                        await ctx.close()
                    except Exception as e:
                        log.warning("deferred close: %r", e)

            context = await browser.new_context()
            log.info("%s", "=" * 60)
            log.info("Run %d/%d", run_id, total)
            defer = False
            try:
                await execute_run(context, password, csv_lock)
                results.append(True)
            except Exception as e:
                log.error("Run %d FAILED: %r", run_id, e)
                traceback.print_exc()
                results.append(False)
                if interactive:
                    deferred.append(context)
                    defer = True
                    log.info("Browser is open. Enter=continue, q=abort.")
                    try:
                        ans = await asyncio.to_thread(input)
                    except (EOFError, KeyboardInterrupt):
                        raise KeyboardInterrupt
                    if ans.strip().lower() == "q":
                        raise KeyboardInterrupt
            finally:
                if not defer:
                    try:
                        await context.close()
                    except Exception as e:
                        log.warning("context close: %r", e)

    aborted = False
    tasks = [asyncio.create_task(run_one(i)) for i in range(1, total + 1)]
    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        aborted = True
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        log.warning("Interrupted by user")
    finally:
        succeeded = sum(results)
        failed = len(results) - succeeded
        log.info("Summary: %d succeeded, %d failed%s",
                 succeeded, failed, " (aborted)" if aborted else "")
        try:
            await asyncio.wait_for(browser.close(), timeout=15)
        except Exception as e:
            log.warning("Browser close: %r", e)

    return 0 if succeeded > 0 and failed == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))