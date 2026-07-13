from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .agent import handle_agent_message, serialize_doc
from .db import domains


app = FastAPI(title="Agentic ASM Platform")


class AgentRequest(BaseModel):
    message: str
    session_id: str = "default"


@app.get("/")
def root():
    return {"status": "Agentic ASM API is running"}


@app.post("/agent/chat")
def agent_chat(request: AgentRequest):
    try:
        return handle_agent_message(
            message=request.message,
            session_id=request.session_id,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/domains/{domain}")
def get_domain(domain: str):
    result = domains.find_one({"domain": domain.lower().strip()})

    if not result:
        raise HTTPException(status_code=404, detail="Domain not found")

    return serialize_doc(result)