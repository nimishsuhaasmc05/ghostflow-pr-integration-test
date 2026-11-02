from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    id: int
    name: str

@app.get("/api/v1/users")
def get_users() -> list[User]:
    return [{"id": 1, "name": "Alice"}]

@app.get("/api/v1/health")
def health_check():
    return {"status": "ok"}
