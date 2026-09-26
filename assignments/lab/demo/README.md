# Guardrails Console: giao diện demo

Giao diện web để trình diễn pipeline 5 lớp của [guardrails_lab.py](../guardrails_lab.py). Mỗi request hiển thị
lớp nào **pass**, lớp nào **chặn**, lớp nào **không chạy**, kèm verdict của classifier, độ trễ và số lần gọi LLM.

```
demo/
├── server.py          FastAPI: bọc process_user_input của lab, ghi vết các lần gọi LLM
├── requirements.txt
└── static/
    ├── index.html
    ├── app.css        Theme sáng / tối, responsive
    └── app.js         Chat, sơ đồ pipeline, thống kê phiên
```

## Chạy

```bash
cd assignments/lab/demo
pip install -r requirements.txt
export GEMINI_API_KEY="..."                 # PowerShell: $env:GEMINI_API_KEY="..."
python server.py                            # mở http://127.0.0.1:8000
```

Provider được chọn tự động: có `GEMINI_API_KEY` thì dùng **Gemini** (main `gemini-3.8-flash`, classifier
`gemini-3.1-flash-lite`), còn không thì dùng **OpenRouter** (`OPENROUTER_API_KEY`). Có thể ép bằng
`LLM_PROVIDER=gemini|openrouter`.

Đổi cổng bằng `DEMO_PORT=9000`. Server chỉ nghe ở `127.0.0.1`.

## Cách dùng khi demo

| Khu vực | Chức năng |
|---|---|
| **User ID** + thanh Rate limit | Mỗi user có quota riêng 5 request / 60 giây. Nút **Reset** xóa quota của user hiện tại |
| **Kịch bản mẫu** | Chip xanh: câu hợp lệ · xám: input lỗi (gửi ngay) · đỏ: tấn công · vàng: ngoài chủ đề · tím: PII |
| **⚡ Flood × 6** | Gửi 6 request liên tiếp để thấy Lớp 1 chặn ở lần thứ 6 |
| **Pipeline** | Sơ đồ 6 bước. Bấm vào một câu trả lời cũ để xem lại pipeline của request đó |
| **Thống kê phiên** | Tổng số request, số bị chặn theo từng lớp, tổng số lần gọi LLM |

Kịch bản gợi ý (khoảng 5 phút):
1. *Nghỉ phép năm*: đi hết 6 bước, 3 lần gọi LLM.
2. *Chuỗi rỗng* → chặn ở L2, **0 lần gọi LLM** (lớp rẻ đứng trước).
3. *Bỏ qua hướng dẫn (VI)* → chặn ở L3 bằng regex, **0 token**.
4. *Persona HRBot-X* → lọt regex, bị **LLM Guard** chặn.
5. *Bitcoin* → chặn ở L4 (Topic Filter).
6. *Email & hotline HR* → model tự bịa thông tin liên hệ, **L5 che PII**.
7. *Flood × 6* → lần 6 bị L1 chặn.

## Lưu ý

- Server **không cài lại** logic guardrail. Nó gọi đúng `process_user_input` của lab, chỉ bọc
  `ask_llm_one_word` / `call_hr_assistant_llm` để ghi verdict, rồi suy ra trạng thái từng lớp từ kết quả.
- Free tier có giới hạn: Gemini 3.8 Flash khoảng **5 request/phút**; OpenRouter `:free` **50 request/ngày**
  (chip *Quota* trên thanh trên cùng chỉ hiện với OpenRouter). Một câu hợp lệ tốn 3 request LLM,
  *Flood × 6* tốn tới 15. Khi bị 429, Lớp 3 fail-closed sẽ chặn và khung chat ghi rõ **Nguyên nhân**.
- Nếu chưa đặt API key, chấm trạng thái ở góc phải chuyển đỏ và **mọi input lọt qua regex đều bị chặn ở L3**
  (fail-closed). Đây cũng là một tình huống đáng demo.
- Câu trả lời của LLM được escape trước khi render markdown, nên prompt chứa HTML không gây XSS trên giao diện.
