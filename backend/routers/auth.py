from fastapi import APIRouter, HTTPException, Cookie, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from services.auth import (
    login, logout, verify_token,
    list_users, create_user, update_user, delete_user,
    ROLES, PERMISSIONS
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

class LoginBody(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username:  str
    password:  str
    role:      str = "soc1"
    full_name: str = ""
    email:     str = ""

class UserUpdate(BaseModel):
    role:      Optional[str] = None
    full_name: Optional[str] = None
    is_active: Optional[int] = None
    password:  Optional[str] = None

@router.post("/login")
def do_login(body: LoginBody, response: Response):
    result = login(body.username, body.password)
    if not result:
        raise HTTPException(401, "Sai tên đăng nhập hoặc mật khẩu")
    response.set_cookie(
        key="soc_token", value=result["token"],
        httponly=True, max_age=8*3600, samesite="lax"
    )
    return result

@router.post("/logout")
def do_logout(response: Response,
              soc_token: Optional[str] = Cookie(None)):
    if soc_token:
        logout(soc_token)
    response.delete_cookie("soc_token")
    return {"status": "ok"}

@router.get("/me")
def get_me(soc_token: Optional[str] = Cookie(None)):
    user = verify_token(soc_token)
    if not user:
        raise HTTPException(401, "Chưa đăng nhập")
    user["permissions"] = PERMISSIONS.get(user["role"], [])
    user["role_label"]  = ROLES.get(user["role"], {}).get("label", "")
    return user

@router.get("/verify")
def verify(soc_token: Optional[str] = Cookie(None)):
    user = verify_token(soc_token)
    if not user:
        raise HTTPException(401, "Token không hợp lệ")
    return {"valid": True, "role": user["role"]}

@router.get("/users")
def get_users(soc_token: Optional[str] = Cookie(None)):
    user = verify_token(soc_token)
    if not user or user["role"] != "admin":
        raise HTTPException(403, "Chỉ admin mới xem được")
    return list_users()

@router.post("/users")
def add_user(body: UserCreate,
             soc_token: Optional[str] = Cookie(None)):
    user = verify_token(soc_token)
    if not user or user["role"] != "admin":
        raise HTTPException(403, "Chỉ admin mới tạo được")
    return create_user(body.username, body.password, body.role,
                       body.full_name, body.email)

@router.patch("/users/{user_id}")
def patch_user(user_id: int, body: UserUpdate,
               soc_token: Optional[str] = Cookie(None)):
    user = verify_token(soc_token)
    if not user or user["role"] != "admin":
        raise HTTPException(403, "Chỉ admin mới sửa được")
    update_user(user_id, body.role, body.full_name,
                body.is_active, body.password)
    return {"status": "updated"}

@router.delete("/users/{user_id}")
def remove_user(user_id: int,
                soc_token: Optional[str] = Cookie(None)):
    user = verify_token(soc_token)
    if not user or user["role"] != "admin":
        raise HTTPException(403, "Chỉ admin mới xóa được")
    delete_user(user_id)
    return {"status": "deleted"}

@router.get("/roles")
def get_roles():
    return ROLES
