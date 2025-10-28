# app.py
"""
NexusGuard – LLM Reasoning API (Phase 1);
Runs a lightweight API that accepts ML outputs and returns
MITRE-mapped reasoning + mitigations + retrieved context.
"""

from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from llm_component import llm_reasoning, get_mitre_context
from context_retriever import Retriever

app = FastAPI(title="NexusGuard LLM Reasoning API", version="0.1.0")
retriever = Retriever(k=5)

class Event(BaseModel):
    timestamp: str
    sensor_id: str
    command: str
    risk_score: int = Field(ge=0, le=100)
    ml_label: str
    extra: Optional[Dict[str, Any]] = None

class ReasoningResponse(BaseModel):
    reasoning_text: str
    mitre: Optional[Dict[str, Any]] = None
    retrieved_context: List[Dict[str, Any]] = []
    mitigation: List[str] = []

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/reason", response_model=ReasoningResponse)
def reason(event: Event):
    mitre = get_mitre_context(event.command)
    reasoning_text = llm_reasoning(event.dict())

    # RAG-ish context from local KB (BM25/TF-IDF approximate)
    ctx = retriever.search(event.command)

    mitigation = [
        "Isolate affected host/container/WSL session",
        "Revoke unnecessary privileges",
        "Collect artifacts (process tree, recent downloads, bash history)",
        "Restore from known-good backups if integrity impacted"
    ]
    return ReasoningResponse(
        reasoning_text=reasoning_text,
        mitre=mitre,
        retrieved_context=ctx,
        mitigation=mitigation
    )
