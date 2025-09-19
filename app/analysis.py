# backend/app/analysis.py
import re
from typing import List, Dict

THREAT_KEYWORDS = [
    "attack", "secure", "enemy", "troop", "soldier", "bomb", "weapon",
    "deploy", "patrol", "midnight", "ambush", "strike", "target", "infiltrate", "destroy","place"
]
ACTIONABLE_KEYWORDS = ["deploy", "schedule", "patrol", "attack", "secure", "move", "meeting", "arrive"]

SENSITIVE_PATTERNS = {
    "time": re.compile(r"\b(?:[01]?\d|2[0-3]):[0-5]\d\b"),
    "number": re.compile(r"\b\d{2,}\b"),
    "phone": re.compile(r"(\+?\d{1,3}[-.\s]?)?(\d{3}[-.\s]?\d{3}[-.\s]?\d{4})"),
    "coordinates": re.compile(r"\b\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+\b"),
}

def sentence_split(text: str) -> List[str]:
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    return [s.strip() for s in sentences if s.strip()]

def classify_sentence(sentence: str) -> Dict:
    lower = sentence.lower()
    threat_score = sum(lower.count(k) for k in THREAT_KEYWORDS)
    actionable_score = sum(lower.count(k) for k in ACTIONABLE_KEYWORDS)

    if threat_score >= 2 or ("secure" in lower and "midnight" in lower):
        level = "High"
    elif threat_score == 1 or actionable_score >= 1:
        level = "Medium"
    else:
        level = "Low"

    sensitive = []
    for name, patt in SENSITIVE_PATTERNS.items():
        for m in patt.findall(sentence):
            val = m if isinstance(m, str) else (m[0] if isinstance(m, tuple) and m[0] else ''.join(m))
            sensitive.append({"type": name, "match": val})

    return {
        "content": sentence,
        "threat_score": threat_score,
        "actionable_score": actionable_score,
        "level": level,
        "sensitive": sensitive,
    }

def seconds_to_mmss(sec: int) -> str:
    m = sec // 60
    s = sec % 60
    return f"{m:02d}:{s:02d}"

def analyze_text(text: str) -> Dict:
    sentences = sentence_split(text)
    details = []
    total_threats = 0
    sensitive_flags = 0
    actionable_insights = 0

    for idx, s in enumerate(sentences):
        row = classify_sentence(s)
        details.append({
            "timestamp": seconds_to_mmss(idx * 15),
            "content": row["content"],
            "threat_level": row["level"],
            "sensitive": row["sensitive"],
            "threat_score": row["threat_score"],
            "actionable_score": row["actionable_score"],
        })
        if row["threat_score"] > 0:
            total_threats += 1
        if row["sensitive"]:
            sensitive_flags += len(row["sensitive"])
        if row["actionable_score"] > 0:
            actionable_insights += 1

    summary = {
        "total_threats_detected": total_threats,
        "sensitive_information_flags": sensitive_flags,
        "actionable_insights": actionable_insights,
    }

    return {"summary": summary, "details": details}
