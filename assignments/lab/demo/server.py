"""
Demo UI cho pipeline Guardrails của HR Assistant.

Chạy:
    cd assignments/lab/demo
    export GEMINI_API_KEY="..."          # hoặc OPENROUTER_API_KEY="sk-or-..."
    python server.py            # mở http://127.0.0.1:8000

Server KHÔNG cài lại logic guardrail: mọi request đi qua đúng `process_user_input` của
guardrails_lab.py. Server chỉ bọc 2 hàm gọi LLM để ghi lại verdict / độ trễ của từng lần gọi,
rồi suy ra trạng thái từng lớp từ kết quả trả về để hiển thị.
"""
import os
import re
import sys
import threading
import time
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

LAB_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
sys.path.insert(0, str(LAB_DIR))

import guardrails_lab as lab  # noqa: E402

KEY_ENV = "GEMINI_API_KEY" if lab.PROVIDER == "gemini" else "OPENROUTER_API_KEY"


def api_key_set() -> bool:
    if lab.PROVIDER == "gemini":
        return bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    return bool(os.environ.get("OPENROUTER_API_KEY"))

# ==========================================
# GHI VẾT CÁC LẦN GỌI LLM
# ==========================================
_TOPIC_PREFIX = lab.TOPIC_CLASSIFIER_PROMPT.split("{prompt}")[0]
_original_ask = lab.ask_llm_one_word
_original_main = lab.call_hr_assistant_llm

# Pipeline dùng state toàn cục (RATE_LIMIT_STORE) và bộ ghi vết dùng chung -> chạy tuần tự
_pipeline_lock = threading.Lock()
_calls: list[dict] = []


def _traced_ask(prompt: str) -> str:
    kind = "topic" if prompt.startswith(_TOPIC_PREFIX) else "injection"
    record = {"kind": kind, "model": lab.CLASSIFIER_MODEL}
    start = time.perf_counter()
    try:
        record["verdict"] = _original_ask(prompt)
        return record["verdict"]
    except Exception as e:
        record["error"] = str(e)[:200]
        raise
    finally:
        record["ms"] = round((time.perf_counter() - start) * 1000)
        _calls.append(record)


def _traced_main(prompt: str) -> str:
    record = {"kind": "main", "model": lab.MODEL}
    start = time.perf_counter()
    try:
        record["raw"] = _original_main(prompt)
        return record["raw"]
    except Exception as e:
        record["error"] = str(e)[:200]
        raise
    finally:
        record["ms"] = round((time.perf_counter() - start) * 1000)
        _calls.append(record)


lab.ask_llm_one_word = _traced_ask
lab.call_hr_assistant_llm = _traced_main

# ==========================================
# SUY RA TRẠNG THÁI TỪNG LỚP
# ==========================================
STAGES = [
    ("L1", lab.LAYER_1),
    ("L2", lab.LAYER_2),
    ("L3", lab.LAYER_3),
    ("L4", lab.LAYER_4),
    ("LLM", "Main LLM"),
    ("L5", lab.LAYER_5),
]


def _stage_details(key: str, calls: list[dict], prompt: str, result: dict) -> dict:
    by_kind = {c["kind"]: c for c in calls}
    if key == "L3":
        normalized = lab.normalize_for_matching(prompt)
        for i, pattern in enumerate(lab.INJECTION_PATTERNS):
            if re.search(pattern, normalized):
                return {"method": "Regex", "pattern": i + 1, "llm": None}
        return {"method": "Regex → LLM Guard", "llm": by_kind.get("injection")}
    if key == "L4":
        return {"llm": by_kind.get("topic")}
    if key == "LLM":
        main = by_kind.get("main")
        return {"llm": {k: v for k, v in main.items() if k != "raw"} if main else None}
    if key == "L5" and result.get("status") == "SUCCESS":
        return {"redactions": result["response"].count("[ĐÃ ẨN ")}
    return {}


def build_trace(prompt: str, result: dict, calls: list[dict]) -> list[dict]:
    blocked_layer = result.get("layer") if result.get("status") == "BLOCKED" else None
    error_stage = "LLM" if result.get("status") == "ERROR" else None
    trace, reached_end = [], False
    for key, name in STAGES:
        if reached_end:
            status = "skip"
        elif name == blocked_layer:
            status, reached_end = "block", True
        elif key == error_stage:
            status, reached_end = "error", True
        else:
            status = "pass"
        details = _stage_details(key, calls, prompt, result) if status != "skip" else {}
        trace.append({"key": key, "name": name, "status": status, **details})
    return trace


def rate_usage(user_id: str) -> int:
    now = time.time()
    return sum(1 for t in lab.RATE_LIMIT_STORE.get(user_id, []) if now - t < lab.WINDOW_SECONDS)


# ==========================================
# API
# ==========================================
app = FastAPI(title="HR Assistant Guardrails Demo")


class ChatRequest(BaseModel):
    user_id: str
    prompt: str


class ResetRequest(BaseModel):
    user_id: str | None = None


@app.get("/api/config")
def config():
    return {
        "main_model": lab.MODEL,
        "classifier_model": lab.CLASSIFIER_MODEL,
        "provider": lab.PROVIDER,
        "key_env": KEY_ENV,
        "api_key_set": api_key_set(),
        "rate_limit": lab.MAX_REQUESTS_PER_MINUTE,
        "window_seconds": lab.WINDOW_SECONDS,
        "min_len": lab.MIN_PROMPT_LENGTH,
        "max_len": lab.MAX_PROMPT_LENGTH,
        "regex_count": len(lab.INJECTION_PATTERNS),
    }


@app.get("/api/quota")
def quota():
    """Quota request free trong ngày của key OpenRouter (endpoint /key không tính vào quota)."""
    if lab.PROVIDER == "gemini":
        return {"available": False, "reason": "Gemini API không có endpoint xem quota — xem tại aistudio.google.com"}
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        return {"available": False, "reason": "Chưa đặt OPENROUTER_API_KEY"}
    try:
        res = httpx.get(f"{lab.OPENROUTER_BASE_URL}/key", headers={"Authorization": f"Bearer {key}"}, timeout=5)
        data = res.json()["data"]
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}
    free = data.get("free_model_daily_requests") or {}
    return {
        "available": True,
        "free_tier": data.get("is_free_tier"),
        "used": free.get("used"),
        "limit": free.get("limit"),
        "remaining": free.get("remaining"),
    }


@app.post("/api/chat")
def chat(req: ChatRequest):
    user_id = req.user_id.strip() or "anonymous"
    with _pipeline_lock:
        _calls.clear()
        start = time.perf_counter()
        try:
            result = lab.process_user_input(user_id, req.prompt)
        except Exception as e:  # Main LLM lỗi (quota, mạng...) sau khi đã qua 4 lớp
            result = {"status": "ERROR", "layer": "Main LLM", "message": str(e)[:300]}
        latency = round((time.perf_counter() - start) * 1000)
        calls = list(_calls)
    return {
        "result": result,
        "trace": build_trace(req.prompt, result, calls),
        "llm_calls": len(calls),
        "latency_ms": latency,
        "rate": {"used": rate_usage(user_id), "limit": lab.MAX_REQUESTS_PER_MINUTE},
    }


@app.get("/api/rate/{user_id}")
def rate(user_id: str):
    return {"used": rate_usage(user_id), "limit": lab.MAX_REQUESTS_PER_MINUTE}


@app.post("/api/reset")
def reset(req: ResetRequest):
    with _pipeline_lock:
        if req.user_id:
            lab.RATE_LIMIT_STORE.pop(req.user_id, None)
        else:
            lab.RATE_LIMIT_STORE.clear()
    return {"ok": True}


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    host = os.environ.get("DEMO_HOST", "127.0.0.1")
    port = int(os.environ.get("DEMO_PORT", "8000"))
    # Nếu một server cũ còn giữ cổng, uvicorn thoát ngay còn trình duyệt vẫn nói chuyện với server cũ
    # (code/API key cũ) -> báo rõ thay vì để người dùng tưởng đã khởi động lại thành công.
    import socket
    with socket.socket() as probe:
        if probe.connect_ex((host, port)) == 0:
            print(f"[LỖI] Cổng {port} đang bị một server khác chiếm (có thể là bản demo cũ vẫn chạy).")
            print("      Tắt server cũ (Ctrl+C ở terminal của nó) hoặc chạy với DEMO_PORT=8001.")
            sys.exit(1)
    print(f"Provider: {lab.PROVIDER} | main: {lab.MODEL} | classifier: {lab.CLASSIFIER_MODEL}")
    if not api_key_set():
        print(f"[Cảnh báo] Chưa đặt {KEY_ENV}: Lớp 3 sẽ fail-closed với mọi input qua được regex.")
    print(f"Demo UI: http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning")
