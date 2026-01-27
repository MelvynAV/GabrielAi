from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict

app = FastAPI()

# Simulation d'une base de données de Whitelist
whitelist_db: Dict[int, str] = {1: "google.com", 2: "uottawa.ca"}

class UrlEntry(BaseModel):
    url: str

@app.get("/whitelist")
async def get_whitelist():
    return whitelist_db

@app.post("/whitelist/{id}")
async def add_to_whitelist(id: int, entry: UrlEntry):
    whitelist_db[id] = entry.url
    return {"message": "Ajouté", "id": id, "url": entry.url}

@app.put("/whitelist/{id}")
async def update_whitelist(id: int, entry: UrlEntry):
    if id not in whitelist_db: raise HTTPException(status_code=404)
    whitelist_db[id] = entry.url
    return {"message": "Mis à jour", "id": id}

@app.patch("/whitelist/{id}")
async def patch_whitelist(id: int, entry: UrlEntry):
    if id not in whitelist_db: raise HTTPException(status_code=404)
    whitelist_db[id] = entry.url
    return {"message": "Partiellement modifié"}

@app.delete("/whitelist/{id}")
async def delete_from_whitelist(id: int):
    if id in whitelist_db: 
        del whitelist_db[id]
        return {"message": "Supprimé"}
    raise HTTPException(status_code=404)