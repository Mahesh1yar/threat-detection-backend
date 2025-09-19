from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from transformers import pipeline

app = FastAPI()

# Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# Load zero-shot classifier once
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

@app.post("/analyze")
async def analyze(request: Request):
    data = await request.json()
    text = data.get("text", "")
    
    if not text:
        return {"result": "No text provided"}

    labels = ["Threat", "Safe", "Sensitive Info"]
    result = classifier(text, candidate_labels=labels)

    return {"result": result}
