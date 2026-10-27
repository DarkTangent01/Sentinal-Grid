from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import User
from ..db.pg import get_session
from ..security import (burn_password_check, create_session_token, hash_password, validate_password_strength,
                        verify_password)
from .deps import iso, CSRF_COOKIE, SESSION_COOKIE, audit, client_ip, current_user, limiter, require_admin

router = APIRouter(prefix="/api", tags=["auth"])
LOCK_AFTER = 5
LOCK_MINUTES = 15


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


def user_out(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "timezone": u.timezone, "is_active": u.is_active,
            "last_login": iso(u.last_login)}


@router.post("/auth/login")
async def login(body: LoginIn, request: Request, response: Response, s: AsyncSession = Depends(get_session)):
    st = get_settings()
    ip = client_ip(request)
    if not limiter.check(f"login:{ip}", st.login_rate_limit_per_minute):
        raise HTTPException(429, "too many login attempts")
    u = (await s.execute(select(User).where(User.username == body.username))).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if u and u.locked_until and (u.locked_until if u.locked_until.tzinfo else u.locked_until.replace(tzinfo=timezone.utc)) > now:
        await audit(s, request, body.username, "login", detail={"reason": "locked"}, success=False)
        raise HTTPException(401, "invalid credentials or account locked")
    if not u:
        burn_password_check(body.password)
    if not u or not u.is_active or not verify_password(body.password, u.password_hash):
        if u:
            u.failed_logins = (u.failed_logins or 0) + 1
            if u.failed_logins >= LOCK_AFTER:
                u.locked_until = now + timedelta(minutes=LOCK_MINUTES)
                u.failed_logins = 0
        await audit(s, request, body.username, "login", success=False)
        raise HTTPException(401, "invalid credentials or account locked")
    u.failed_logins = 0
    u.locked_until = None
    u.last_login = now
    token, csrf = create_session_token(u.id, u.role, u.session_version or 0)
    common = {"secure": st.cookie_secure, "samesite": "strict", "max_age": st.session_ttl_minutes * 60, "path": "/"}
    response.set_cookie(SESSION_COOKIE, token, httponly=True, **common)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, **common)
    await audit(s, request, u.username, "login")
    return {"user": user_out(u), "csrf_token": csrf}


@router.post("/auth/logout")
async def logout(request: Request, response: Response, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    u = await s.get(User, user.id)
    u.session_version = (u.session_version or 0) + 1  # the JWT stays valid until exp unless revoked server-side
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    await audit(s, request, user.username, "logout")
    return {"ok": True}


@router.get("/auth/me")
async def me(user: User = Depends(current_user)):
    return user_out(user)


class PrefsIn(BaseModel):
    timezone: str = Field(max_length=64)


@router.put("/auth/me/preferences")
async def prefs(body: PrefsIn, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    try:
        ZoneInfo(body.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        raise HTTPException(422, "unknown timezone")
    u = await s.get(User, user.id)
    u.timezone = body.timezone
    await s.commit()
    return user_out(u)


class PasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


@router.put("/auth/me/password")
async def change_password(body: PasswordIn, request: Request, response: Response, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    u = await s.get(User, user.id)
    if not verify_password(body.current_password, u.password_hash):
        await audit(s, request, u.username, "password_change", success=False)
        raise HTTPException(400, "current password incorrect")
    u.password_hash = hash_password(body.new_password)
    u.session_version = (u.session_version or 0) + 1  # sign out every other session; this one gets a fresh cookie
    st = get_settings()
    token, csrf = create_session_token(u.id, u.role, u.session_version)
    common = {"secure": st.cookie_secure, "samesite": "strict", "max_age": st.session_ttl_minutes * 60, "path": "/"}
    response.set_cookie(SESSION_COOKIE, token, httponly=True, **common)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, **common)
    await audit(s, request, u.username, "password_change")
    return {"ok": True, "csrf_token": csrf}


class UserIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.\-]{3,64}$")
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(pattern=r"^(admin|analyst)$")


class UserPatch(BaseModel):
    role: str | None = Field(None, pattern=r"^(admin|analyst)$")
    is_active: bool | None = None
    password: str | None = Field(None, min_length=12, max_length=256)


@router.get("/users")
async def list_users(_: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    return [user_out(u) for u in (await s.execute(select(User).order_by(User.username))).scalars()]


@router.post("/users", status_code=201)
async def create_user(body: UserIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    validate_password_strength(body.password)
    if (await s.execute(select(User).where(User.username == body.username))).scalar_one_or_none():
        raise HTTPException(409, "username exists")
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    s.add(u)
    await s.commit()
    await audit(s, request, admin.username, "user_create", body.username, {"role": body.role})
    return user_out(u)


@router.patch("/users/{user_id}")
async def update_user(user_id: int, body: UserPatch, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    u = await s.get(User, user_id)
    if not u:
        raise HTTPException(404, "not found")
    if u.id == admin.id and (body.role == "analyst" or body.is_active is False):
        raise HTTPException(400, "cannot demote or disable yourself")
    changes = {}
    if body.role:
        u.role = changes["role"] = body.role
    if body.is_active is not None:
        u.is_active = changes["is_active"] = body.is_active
    if body.password:
        u.password_hash = hash_password(body.password)
        changes["password"] = "reset"
    if changes:
        u.session_version = (u.session_version or 0) + 1  # the user's open sessions must not keep the old role/password
    await s.commit()
    await audit(s, request, admin.username, "user_update", u.username, changes)
    return user_out(u)
