import logging
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
import requests
import os

error_logger = logging.getLogger("uvicorn.error")
access_logger = logging.getLogger("uvicorn.access")
app_logger = logging.getLogger("reports_api")

for handler in error_logger.handlers:
    app_logger.addHandler(handler)

for handler in access_logger.handlers:
    app_logger.addHandler(handler)

app_logger.setLevel(logging.INFO)
app_logger.propagate = True

app_logger.info("Custom logger integrated with Uvicorn error and access loggers.")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

KEYCLOAK_SERVER_URL = "http://keycloak:8080"
REALM_NAME = "reports-realm"
CLIENT_ID = "reports-backend"
jwks = {}

security = HTTPBearer()


def get_jwks():
    global jwks
    if not jwks:
        url = f"{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"
        response = requests.get(url)
        response.raise_for_status()
        jwks = response.json()
    return jwks


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    app_logger.info("Token received for verification.")
    jwks = get_jwks()
    try:
        unverified_header = jwt.get_unverified_header(token)
        app_logger.info(f"Unverified header: {unverified_header}")
        kid = unverified_header["kid"]
        key = next((key for key in jwks["keys"] if key["kid"] == kid), None)
        if key is None:
            app_logger.error("Key not found for kid.")
            raise HTTPException(status_code=401, detail="Invalid token.")

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=f"http://localhost:8080/realms/{REALM_NAME}"
        )
        app_logger.info(f"Token payload: {payload}")

        roles = payload.get("realm_access", {}).get("roles", [])
        app_logger.info(f"Roles from token: {roles}")
        if not roles:
            app_logger.error("No roles found in token.")
            raise HTTPException(status_code=401, detail="Forbidden: No roles found.")

        if "prothetic_user" not in roles:
            app_logger.error("User does not have the required role.")
            raise HTTPException(status_code=401, detail="Forbidden: You do not have access to this resource.")

        return payload
    except jwt.JWTError as e:
        app_logger.error(f"Token verification error: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


@app.get("/reports")
def download_report(payload: dict = Depends(verify_token)):
    app_logger.info("Starting the report download process.")
    report_file_path = os.path.abspath("./report.pdf")
    app_logger.info(f"Checking if file exists: {report_file_path}")
    if not os.path.exists(report_file_path):
        app_logger.error("Report file not found.")
        raise HTTPException(status_code=404, detail="Report not found")

    app_logger.info("Report file exists, sending response to the client.")
    return FileResponse(report_file_path, media_type="application/pdf", filename="report.pdf")
