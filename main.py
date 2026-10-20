"""
ElevenLabs API key generator with automated signup and email verification.

Flow per run:
  1. Create disposable inbox via Mail.tm
  2. Sign up on ElevenLabs
  3. Wait for verification email via Mail.tm
  4. Complete onboarding
  5. Generate API key (never expires, unrestricted)
  6. Append {email, password, token} to data.csv

Usage:
  python main.py           # one run
  python main.py 20        # twenty runs
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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx
from dotenv import load_dotenv
from playwright.async_api import Browser, Page, expect

from cloakbrowser import launch_async

# ---------------------------------------------------------------- config
CSV_PATH = Path("data.csv")
ELEVENLABS_SIGNUP_URL = "https://elevenlabs.io/app/sign-up"
ELEVENLABS_KEYS_URL = "https://elevenlabs.io/app/developers/api-keys"

MAILTM_BASE = "https://api.mail.tm"
MAILTM_POLL_INTERVAL = 5.0
MAILTM_MAX_WAIT = 180.0

BLOCKED_MAIL_DOMAINS = {
    "guerrillamailblock.com",
    "sharklasers.com",
    "grr.la",
    "guerrillamail.info",
}

VERIFY_URL_RE = re.compile(r'https?://[^\s"\'<>]+mode=verifyEmail[^\s"\'<>]*')
TOKEN_MIN_LEN = 20
TOKEN_MAX_LEN = 200

log = logging.getLogger("elevenlabs-bot")

# ---------------------------------------------------------------- utilities
def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%H:%M:%S",
    )


def parse_count(argv: list[str]) -> int:
    if len(argv) < 2:
        return 1
    try:
        n = int(argv[1])
    except ValueError:
        raise SystemExit(f"Usage: python {argv[0]} [N]")
    if n < 1:
        raise SystemExit("N must be a positive integer")
    return n


async def retry_async(coro_factory, *, attempts: int = 3,
                      base_delay: float = 1.0, label: str = "request",
                      retry_on: tuple = (httpx.ConnectError,
                                         httpx.ReadError,
                                         httpx.RemoteProtocolError)):
    last_exc: Optional[Exception] = None
    for i in range(attempts):
        try:
            return await coro_factory()
        except retry_on as e:
            last_exc = e
            delay = base_delay * (2 ** i)
            log.warning("%s attempt %d/%d failed (%r); retrying in %.1fs",
                        label, i + 1, attempts, e, delay)
            await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc