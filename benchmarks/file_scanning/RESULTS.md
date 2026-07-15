# File & Image Scanning — Benchmark Results & Improvement Proposals

## Benchmark Summary

**Dataset**: 29 samples (22 positive, 7 negative)  
**File Types**: images (PNG screenshots), documents (text), spreadsheets (CSV), code files  
**Categories**: SSN, email, phone, credit_card, api_key, credential, name, address

### Results (After Improvements)

| Metric | Value |
|--------|-------|
| **File-Level F1** | **100%** |
| Accuracy | 100% |
| Precision | 100% |
| Recall | 100% |
| TP=22, FP=0, FN=0, TN=7 | |

### Per-Category Detection

| Category | Precision | Recall | Notes |
|----------|-----------|--------|-------|
| SSN | 100% | 100% | Strong regex pattern |
| Email | 92% | 100% | 1 FP (auto-generated string) |
| Phone | 100% | 100% | |
| Credit Card | 100% | 100% | |
| API Key | 100% | 78% | 2 FN — non-standard prefixes |
| Credential | 100% | 100% | Improved keyword matching |
| Name | 100% | 90% | Context-aware detection |
| Address | 100% | 100% | Street pattern matching |

### Latency

| File Type | Avg | p50 | p95 | Method |
|-----------|-----|-----|-----|--------|
| Image (OCR) | 68ms | 56ms | 334ms* | Apple Vision |
| Document | 0.1ms | 0.1ms | 0.1ms | Direct read |
| Spreadsheet | 0.1ms | 0.1ms | 0.2ms | CSV parser |
| Code | 0.1ms | 0.1ms | 0.1ms | Direct read |
| **Overall** | **42ms** | — | **58ms** | — |

*First OCR call incurs ~340ms model load; subsequent calls ~55ms

---

## Architecture

```
Request with file attachment
    │
    ├─ multipart/form-data ──► Parse boundaries ──► Extract file bytes
    │
    ├─ JSON with base64 ──────► Find base64 fields ──► Decode
    │
    ▼
File bytes
    │
    ├─ Magic byte detection ──► Route to extractor
    │
    ▼
┌─────────────────────────────────────────────┐
│  Text Extraction (per file type)            │
│                                             │
│  Image ──► Apple Vision OCR (Neural Engine) │
│  PDF   ──► pdfminer.six                    │
│  XLSX  ──► openpyxl                         │
│  CSV   ──► csv module                       │
│  Code  ──► Direct UTF-8 decode              │
└─────────────────────────────────────────────┘
    │
    ▼
Extracted text ──► Detection pipeline (regex → NER → LLM)
    │
    ▼
Block / Redact / Allow
```

---

## Improvement Proposals

### 1. Model-Based Detection for Names & Addresses (Priority: HIGH)

**Problem**: Regex alone can't reliably detect names/addresses without labeled context.  
**Solution**: Integrate GLiNER or a small NER model for the file scanner.

- Use the existing `create_detector_pipeline()` from `domestique/detectors/` instead of regex-only
- GLiNER can detect names, addresses, and other entities regardless of format
- Expected improvement: name recall 90% → 98%, address recall in unstructured text

**Latency impact**: +5-15ms per scan (GLiNER is lightweight)

### 2. Entropy-Based Secret Detection (Priority: HIGH)

**Problem**: `api_key` recall is 78% — some keys with non-standard prefixes are missed.  
**Solution**: Add Shannon entropy analysis for high-entropy strings.

- Strings >20 chars with entropy >4.5 bits/char are likely secrets
- Combined with context (assignment to `KEY`, `SECRET`, `TOKEN` variables)
- Catches novel key formats without needing prefix-specific regex
- Already proven in tools like TruffleHog and detect-secrets

**Latency impact**: +0.5ms (pure computation, no model)

### 3. OCR Warm-Keep for Sustained Low Latency (Priority: MEDIUM)

**Problem**: First OCR call is 340ms (model load), subsequent are ~55ms.  
**Solution**: Pre-warm the Vision pipeline on app startup.

- Call `VNRecognizeTextRequest` once with a 1x1 white image at startup
- Keep the recognition model in memory
- Eliminates the cold-start penalty entirely

**Latency impact**: First call 340ms → 55ms (6× improvement)

### 4. Parallel File Scanning (Priority: MEDIUM)

**Problem**: If a request contains multiple images (e.g., ChatGPT vision with 3 images), they're scanned sequentially.  
**Solution**: Use `concurrent.futures.ThreadPoolExecutor` for parallel extraction.

- Apple Vision is thread-safe and uses the Neural Engine efficiently
- 3 images: 3×55ms → ~60ms total (parallel)

**Latency impact**: Linear → constant for multi-file requests

### 5. Image Pre-filtering (Priority: MEDIUM)

**Problem**: Every image goes through full OCR even if it contains no text (photos, diagrams).  
**Solution**: Quick pre-filter using image analysis.

- Check if image has text-like regions using Apple Vision's `VNDetectTextRectanglesRequest`
- If no text regions detected: skip OCR entirely (~5ms check vs 55ms full OCR)
- Only useful for non-screenshot images (photos, charts)

**Latency impact**: -50ms per image that has no text

### 6. PDF with Embedded Images (Priority: LOW)

**Problem**: Current PDF extraction is text-only. Scanned PDFs (image-based) get no text.  
**Solution**: Detect image-only PDFs and route through OCR.

- Use pdfminer to check if text layer is empty
- If empty: extract embedded images and OCR them
- Common for scanned contracts, faxes, etc.

**Latency impact**: +55ms per page for scanned PDFs

### 7. Caching with Content-Hash (Priority: LOW)

**Problem**: Same file might be scanned multiple times (retries, multi-tab).  
**Solution**: SHA-256 hash of file content → LRU cache of scan results.

- Cache size: 100 entries (covers recent files)
- TTL: 5 minutes (handles policy changes)
- Second scan of same file: 0ms

**Latency impact**: Repeat scans 55ms → 0ms

---

## Comparison with Alternatives

| Approach | Accuracy | Latency | Pros | Cons |
|----------|----------|---------|------|------|
| **Apple Vision (current)** | High | 55ms | Native, hardware-accelerated, no deps | macOS only |
| Tesseract | Medium | 200-500ms | Cross-platform, open source | Slow, lower accuracy |
| Google Cloud Vision | High | 200-800ms | Excellent accuracy | Network call, cost, privacy |
| AWS Textract | High | 500-2000ms | Document understanding | Network call, cost, privacy |
| Local multimodal LLM (Phi-3V) | Very High | 2-5s | Context understanding | Too slow for inline |

**Recommendation**: Apple Vision is the clear winner for our use case (local, fast, accurate). For cross-platform (Windows/Linux), use Tesseract 5 with LSTM backend or PaddleOCR.

---

## Next Steps

1. ✅ Integrate file scanner into mitm_addon (done)
2. ✅ Benchmark with Apple Vision OCR (done)
3. ⬜ Add entropy-based secret detection
4. ⬜ Pre-warm OCR model on startup
5. ⬜ Integrate GLiNER for name/address in unstructured files
6. ⬜ Add parallel scanning for multi-image requests
7. ⬜ Add real PDF and XLSX test samples (current benchmark uses text files)
8. ⬜ Test with real-world LLM API payloads containing images
