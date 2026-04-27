from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import hashlib
import httpx

app = FastAPI(title="ms-breach-check", version="1.0")

# Configurar CORS para que funcione desde GitHub Pages
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HIBP_URL = "https://api.pwnedpasswords.com/range/"

@app.post("/api/v1/check/password")
async def check_password(password: str):
    if not password:
        raise HTTPException(status_code=400, detail="La contraseña es requerida")
    
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{HIBP_URL}{prefix}")
        
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="Error al consultar HIBP")
        
        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return {"compromised": True, "times_exposed": int(count)}
        
        return {"compromised": False, "times_exposed": 0}
    
    except Exception:
        raise HTTPException(status_code=500, detail="Error interno")

@app.get("/api/v1/check/health")
def health():
    return {"status": "ok", "service": "ms-breach-check"}
