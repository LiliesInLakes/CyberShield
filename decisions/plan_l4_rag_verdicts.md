# L4 RAG-Grounded Verdicts — Implementation Plan

## Context

L4 currently explains obfuscated code but contributes zero points to L5 and zero
findings to the spine. The LLM's understanding of what each class DOES is thrown
away. This plan upgrades L4 to produce **grounded verdicts** — per-class
maliciousness judgments backed by retrieved threat intelligence, not free-form
LLM opinion.

## Architecture

```
Decompiled class + L0/L1/L2 findings
        │
        ▼
  ┌──────────────┐
  │ Feature       │  Extract: API calls, string patterns, permissions,
  │ Extraction    │  data flows, class structure
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │ RAG Retrieval │  TF-IDF + cosine similarity against knowledge base
  │ (sklearn)     │  → top-K matching threat patterns
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │ Analyst LLM   │  Existing deobfuscation + NEW: verdict with grounding
  │ (OpenRouter)  │  "This matches [retrieved pattern]. Verdict: malicious"
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │ Verifier      │  Second LLM call: tries to break the verdict
  │ (OpenRouter)  │  + mechanical checks (verify.py extended)
  └──────┬───────┘
         │
         ├── GROUNDED:   matched known pattern, verifier confirmed  → ±5 pts in L5
         ├── UNVERIFIED: no pattern match OR verifier weakened       → 0 pts, in report
         └── REFUTED:    verifier broke the reasoning                → dropped
```

## Decision Tree

```
For each class:
│
├─ Source code available?
│  ├─ NO  → skip (existing behavior)
│  └─ YES → continue
│
├─ Extract code signatures (API calls, strings, patterns)
│
├─ RAG retrieval: search knowledge base for similar patterns
│  ├─ similarity >= 0.3 → include top-3 matches as context
│  └─ similarity < 0.3  → no grounding context, flag as novel
│
├─ LLM Analyst call (single call, extended prompt):
│  ├─ Existing: purpose, renamed, decoded_strings, api_calls, iocs, behaviours
│  └─ NEW: verdict (malicious|suspicious|benign|unclear),
│         evidence_chain (step-by-step reasoning),
│         grounding (which retrieved pattern matches, or "novel"),
│         mitre_techniques (ATT&CK IDs)
│
├─ Mechanical verification (verify.py — unchanged):
│  └─ decoded_strings, renamed, api_calls, iocs checked as before
│
├─ Verdict verification (NEW — second LLM call):
│  ├─ Receives: same source code + analyst's verdict + evidence_chain
│  ├─ Task: "Find a flaw in this reasoning. Is there a benign explanation?"
│  ├─ Output: status (confirmed|weakened|refuted), counter_argument
│  │
│  ├─ confirmed + had RAG match → GROUNDED (contributes to L5)
│  ├─ confirmed + no RAG match  → UNVERIFIED (in report, 0 pts)
│  ├─ weakened                   → UNVERIFIED (downgraded, in report, 0 pts)
│  └─ refuted                    → REFUTED (dropped entirely)
│
└─ If LLM calls fail → graceful fallback to current behavior (explain only)
```

## Phases

### Phase 1: Knowledge Base (L4/knowledge/)

**Files:**
- `L4/knowledge/build_kb.py` — scraper/builder for the knowledge base
- `L4/knowledge/kb.json` — the knowledge base itself (committed, versioned)
- `L4/knowledge/retriever.py` — TF-IDF indexing + cosine similarity retrieval

**Knowledge base sources (no API keys, no approval needed):**
1. MITRE ATT&CK Mobile techniques — scrape from the public JSON at
   `https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json`
   (~100 mobile techniques with descriptions, procedure examples)
2. Our own YARA rules — parse `L1/yara_templates/*.yar` meta descriptions,
   extract what each rule detects and the API patterns it matches
3. Indian banking malware patterns — hand-curated from our corpus findings:
   SMS interception+forwarding, overlay attacks, accessibility abuse,
   UPI phishing, fake OTP harvesting. ~20-30 entries based on what we've
   already observed in the 12 India-targeted samples.
4. L1/schema.py MITRE mapping — use the existing `MITRE_MAP` as a seed

**Retrieval approach:** TF-IDF (sklearn) over the concatenated technique
descriptions + code indicators. No new dependencies. ~500 documents total,
fits in memory trivially. Cosine similarity threshold 0.3 for "match found".

**Index format per document:**
```json
{
  "id": "T1636.004",
  "source": "mitre_attack",
  "title": "Protected User Data: SMS Messages",
  "description": "Adversary accesses SMS messages...",
  "code_indicators": ["SmsManager", "getSubscriptionId", "BroadcastReceiver",
                       "SMS_RECEIVED", "pdus"],
  "severity": "high",
  "mitre_techniques": ["T1636.004"],
  "families": ["EventBot", "Cerberus", "FluBot"]
}
```

### Phase 2: Extended Analyst Prompt

**File:** `L4/deobfuscate.py` — modify `explain_class()`

Extended prompt schema (additions in **bold**):
```
{
  "purpose": "one sentence",
  "renamed": {...},
  "decoded_strings": {...},
  "api_calls": [...],
  "iocs": [...],
  "behaviours": [...],
  **"verdict": "malicious|suspicious|benign|unclear",**
  **"evidence_chain": [**
  **  "Step 1: Class registers BroadcastReceiver for SMS_RECEIVED",**
  **  "Step 2: onReceive extracts PDU and reads message body",**
  **  "Step 3: Sends body via HTTP POST to hardcoded URL"**
  **],**
  **"matched_pattern": "retrieved_pattern_id or null",**
  **"mitre_techniques": ["T1636.004"],**
  "confidence": "high|medium|low"
}
```

The system prompt is extended to include retrieved context:
```
KNOWN MALWARE PATTERNS (from threat intelligence database):
1. [T1636.004] SMS Interception: Registers BroadcastReceiver for SMS_RECEIVED,
   extracts PDU, forwards via HTTP. Families: EventBot, Cerberus...
2. [T1417.002] Overlay Attack: Uses WindowManager.addView with TYPE_APPLICATION_OVERLAY...

If the code matches a known pattern, cite it. If it does not match any known
pattern, set matched_pattern to null — do not fabricate a match.
```

### Phase 3: Verdict Verifier

**File:** `L4/verify_verdict.py` (new)

Second LLM call with adversarial prompt:
```
You are a security code reviewer checking another analyst's work.
Given the same source code, the analyst concluded:
  Verdict: {verdict}
  Evidence chain: {evidence_chain}
  Matched pattern: {matched_pattern}

Your job: find a flaw. Is there a benign explanation for this code?
Could the evidence chain be wrong? Is the pattern match valid?

Return JSON:
{
  "status": "confirmed|weakened|refuted",
  "counter_argument": "explanation if weakened/refuted, empty if confirmed",
  "confidence": "high|medium|low"
}
```

**Mechanical checks (extend verify.py):**
- `mitre_techniques`: must be valid T-codes from ATT&CK Mobile (checked against kb.json)
- `matched_pattern`: must be a real ID in the knowledge base
- `evidence_chain`: each step's API/class references must occur in the source code

### Phase 4: Wire into Spine + L5 + L6

**L4 findings in spine (NEW — L4 currently writes `findings=[]`):**
- Only GROUNDED verdicts become findings
- Category mapped from MITRE technique (reuse `L1/schema.py:MITRE_MAP` reverse lookup)
- Severity: from the knowledge base entry
- Observation: `inferred` (LLM-derived, not runtime-observed)
- New field: `grounding_source` — which KB entry grounded this

**L5 scoring (modify `L5/score.py`):**
- New stage between ML and gates: `apply_l4_verdicts()`
- GROUNDED verdicts contribute ±5 points max (bounded like L3's ±10)
- `malicious` + GROUNDED → +3 to +5 points
- `suspicious` + GROUNDED → +1 to +2 points
- `benign` + GROUNDED → -2 to -3 points
- Cannot push score to Critical alone (same clamp as L3)
- UNVERIFIED/REFUTED → 0 points

**L6 report (modify `L6/report.py`):**
- New section: "AI-Assisted Code Analysis"
- Each class shows: verdict badge, evidence chain, grounding citation
- GROUNDED verdicts highlighted, UNVERIFIED shown with caveat

## Files to Create/Modify

| File | Action | What |
|------|--------|------|
| `L4/knowledge/__init__.py` | CREATE | package |
| `L4/knowledge/build_kb.py` | CREATE | scrape MITRE + parse YARA + curate India patterns |
| `L4/knowledge/kb.json` | CREATE | the knowledge base (committed) |
| `L4/knowledge/retriever.py` | CREATE | TF-IDF index + retrieve() |
| `L4/verify_verdict.py` | CREATE | second-pass verdict verification |
| `L4/deobfuscate.py` | MODIFY | extended prompt, RAG context, verdict output |
| `L4/verify.py` | MODIFY | add mitre_techniques + matched_pattern checks |
| `L5/score.py` | MODIFY | add apply_l4_verdicts() stage |
| `L6/report.py` | MODIFY | render L4 verdicts in report |
| `tests/test_l4_rag.py` | CREATE | test retriever, verdict verification |

## Verification

1. `python -m pytest tests/test_l4_rag.py` — unit tests for retriever + verdict verifier
2. Build KB: `$SENTINEL_PYTHON L4/knowledge/build_kb.py` — should produce kb.json with 200+ entries
3. Run L4 on SBI sample: `$SENTINEL_PYTHON L4/deobfuscate.py <sha256> --src <jadx_src> --explain`
   - Should show GROUNDED verdict for the SMS interception class
   - Should cite T1636.004 and the KB entry
4. Run L5 on same sample: `$SENTINEL_PYTHON L5/l5.py <sha256> --explain`
   - L4 verdicts should contribute ≤5 points
5. Existing tests must still pass: `python -m pytest tests/`

## Constraints

- No new pip dependencies (sklearn TF-IDF + cosine_similarity already available)
- KB is a JSON file, not a database — versioned in git, rebuilt on demand
- LLM cost: +1 call per class for verifier = ~12-16 calls per APK total (was 6-8)
- Budget cap in provider.py handles this automatically
- Graceful degradation: if RAG retrieval or verifier fails, fall back to current behavior
