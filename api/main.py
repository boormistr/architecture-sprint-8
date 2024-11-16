from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
import requests

app = FastAPI()

# Настройка CORS для фронтенда
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Разрешаем запросы от фронтенда
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Конфигурация Keycloak
KEYCLOAK_SERVER_URL = "http://localhost:8080"
REALM_NAME = "prothetic_user"
CLIENT_ID = "reports-backend"

jwks = {}


# Получение JWKS (публичных ключей) для проверки токенов
def get_jwks():
    global jwks
    if not jwks:
        url = f"{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"
        response = requests.get(url)
        response.raise_for_status()
        jwks = response.json()
    return jwks


# Проверка токена
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    jwks = get_jwks()
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]
        key = next((key for key in jwks["keys"] if key["kid"] == kid), None)
        if key is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Проверяем подпись токена и дополнительные параметры
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=CLIENT_ID,  # Проверяем, что токен предназначен для бекенда
            issuer=f"{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}"  # Проверяем Keycloak как издателя
        )
        return payload
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Маршрут для скачивания отчёта
@app.get("/reports")
def download_report(payload: dict = Depends(verify_token)):
    report_file_path = "report.pdf"
    try:
        return FileResponse(report_file_path, media_type="application/pdf", filename="report.pdf")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not found")
