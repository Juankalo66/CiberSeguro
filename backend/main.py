from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import hashlib
import httpx

app = FastAPI(title="ms-breach-check", version="1.0")

# Modelo de datos para la solicitud
class PasswordRequest(BaseModel):
    password: str

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HIBP_URL = "https://api.pwnedpasswords.com/range/"

@app.post("/api/v1/check/password")
async def check_password(request: PasswordRequest):
    password = request.password
    
    if not password:
        raise HTTPException(status_code=400, detail="La contraseña es requerida")
    
    # Generar hash SHA-1
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{HIBP_URL}{prefix}")
        
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="Error al consultar HIBP")
        
        # Buscar coincidencia
        for line in response.text.splitlines():
            if ":" not in line:
                continue
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return {"compromised": True, "times_exposed": int(count)}
        
        return {"compromised": False, "times_exposed": 0}
    
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="La API de HIBP no respondió a tiempo")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@app.get("/api/v1/check/health")
def health():
    return {"status": "ok", "service": "ms-breach-check"}
