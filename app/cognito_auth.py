# backend/app/cognito_auth.py
import os
import requests
from jose import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

AWS_REGION = os.getenv("AWS_REGION")
USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")

if not AWS_REGION or not USER_POOL_ID or not CLIENT_ID:
    raise RuntimeError("Cognito environment variables not set")

JWKS_URL = (
    f"https://cognito-idp.{AWS_REGION}.amazonaws.com/"
    f"{USER_POOL_ID}/.well-known/jwks.json"
)

security = HTTPBearer()
jwks = requests.get(JWKS_URL).json()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token = credentials.credentials

    try:
        header = jwt.get_unverified_header(token)
        key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{USER_POOL_ID}",
        )

        return payload  # Cognito user info

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
