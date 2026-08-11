"""LLM provider abstraction for L4.

    source source_env.sh
    $SENTINEL_PYTHON L4/provider.py --smoke

L4's job is verified deobfuscation and explanation. It contributes **zero
points** to the L5 score — that is a standing architectural decision, not a
default. The model generates evidence and prose; it never votes. Nothing in
this module returns a number that a score could read.

**Why an abstraction rather than a client.** The proposal commits to on-premise
deployability, and the demo runs against a hosted API. Both have to stay true
at once, so provider selection is configuration and the on-prem path stays a
real code path rather than a paragraph. ``LocalProvider`` is deliberately a
stub that raises: an honest missing implementation, not a silent fallback that
would let "we can run this air-gapped" drift into fiction.

**Why there is a hard budget cap.** L4 runs ~6-8 calls per APK over a corpus of
649 samples. A loop bug is not a bug that wastes a second — it is a bug that
spends money until someone notices. ``CostLedger`` refuses the call that would
cross the cap rather than reporting the overspend afterwards.

**Reasoning tokens are billed output.** Some models emit reasoning before
content; with a small ``max_tokens`` the whole budget goes to reasoning and
``content`` comes back ``None``. Measured on deepseek-v4-flash: ``max_tokens=10``
on "reply OK" returned ``content=None`` and 10 reasoning tokens. Reasoning is
off by default and asked for explicitly where it earns its cost — except that
some endpoints *mandate* it (``gpt-oss-20b`` returns HTTP 400, "Reasoning is
mandatory for this endpoint and cannot be disabled"), so the flag is dropped
and retried rather than treated as fatal.

**Model choice was measured, not assumed.** Four free models were given the same
obfuscated SMS-interceptor class and asked for structured JSON:

===========================  =======  ==========================================
model                        result
===========================  =======  ==========================================
nemotron-3-ultra-550b:free   ✅       decoded the base64 C2 URL correctly
                                      (``http://192.168.1.100/gate.php``), 7
                                      behaviour tags, valid JSON, 30 s
north-mini-code:free         ❌       faster at 17 s, but decoded the same string
                                      as ``get.php`` — wrong
gemma-4-31b-it:free          ⚠️       HTTP 429, rate-limited upstream
gpt-oss-20b:free             ⚠️       HTTP 400, reasoning cannot be disabled
===========================  =======  ==========================================

That ``get.php`` is the argument for the execution verifier in one line: the
model asserted a decoded value that ``base64.b64decode`` refutes in a
microsecond. **L4 must verify every claim it can cheaply check, and this is why.**
Free endpoints also rate-limit, so a fallback chain is not optional.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env.local"

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Chosen by measurement (see module docstring): it was the only free model that
# decoded the base64 C2 URL in the benchmark correctly, and its 1M context holds
# a whole decompiled class without chunking.
DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"

# Free endpoints rate-limit. Tried in order when the primary is unavailable.
DEFAULT_FALLBACKS = (
    "nvidia/nemotron-3-super-120b-a12b:free",
    "cohere/north-mini-code:free",
    "google/gemma-4-31b-it:free",
)

# Attribution headers OpenRouter uses for its dashboard. Harmless, and it makes
# this project's traffic identifiable if the key is ever audited.
_ATTRIBUTION = {"X-Title": "APK Sentinel", "HTTP-Referer": "https://github.com/cybershield"}

_RETRY_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504})


class ProviderError(RuntimeError):
    """A call failed in a way retrying will not fix."""


class BudgetExceeded(ProviderError):
    """The call was refused because it would cross the run's spend cap."""


def load_env(path: Path = ENV_FILE) -> dict[str, str]:
    """Read ``KEY=value`` pairs from .env.local. Absent file is not an error.

    Values are never logged or echoed anywhere in this module — the file is
    mode 600 and gitignored, and it should stay the only place the key lives.
    """
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


@dataclass
class Completion:
    text: str
    model: str
    provider: str
    prompt_tokens: int
    completion_tokens: int
    reasoning_chars: int
    cost_usd: float
    latency_s: float
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def json(self) -> Any:
        """Parse ``text`` as JSON, raising ProviderError with context on failure."""
        try:
            return json.loads(self.text)
        except json.JSONDecodeError as exc:
            raise ProviderError(
                f"expected JSON from {self.model}, got {self.text[:200]!r}"
            ) from exc


@dataclass
class CostLedger:
    """Running spend for one L4 run, with a cap that refuses rather than reports."""

    cap_usd: float = 5.0
    spent_usd: float = 0.0
    calls: int = 0

    def check(self) -> None:
        if self.spent_usd >= self.cap_usd:
            raise BudgetExceeded(
                f"spend cap reached: ${self.spent_usd:.4f} of ${self.cap_usd:.2f} "
                f"over {self.calls} calls"
            )

    def record(self, cost: float) -> None:
        self.spent_usd += cost
        self.calls += 1

    def summary(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "spent_usd": round(self.spent_usd, 6),
            "cap_usd": self.cap_usd,
        }


class Provider(Protocol):
    name: str
    model: str

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 2048,
        temperature: float = 0.0,
        json_object: bool = False,
        reasoning: bool = False,
    ) -> Completion: ...


@dataclass
class OpenRouterProvider:
    """OpenAI-compatible chat completions via OpenRouter."""

    api_key: str
    model: str = DEFAULT_MODEL
    fallbacks: tuple[str, ...] = DEFAULT_FALLBACKS
    ledger: CostLedger = field(default_factory=CostLedger)
    timeout_s: float = 180.0
    max_retries: int = 3
    name: str = "openrouter"
    last_model_used: str = ""

    @classmethod
    def from_env(cls, **kwargs: Any) -> OpenRouterProvider:
        env = {**load_env(), **os.environ}
        key = env.get("OPENROUTER_API_KEY")
        if not key:
            raise ProviderError(
                "OPENROUTER_API_KEY not found. Put it in .env.local (mode 600, "
                "gitignored) or export it."
            )
        kwargs.setdefault("model", env.get("OPENROUTER_MODEL", DEFAULT_MODEL))
        if "fallbacks" not in kwargs:
            raw = env.get("OPENROUTER_FALLBACKS", "")
            kwargs["fallbacks"] = (
                tuple(m.strip() for m in raw.split(",") if m.strip())
                if raw else DEFAULT_FALLBACKS
            )
        return cls(api_key=key, **kwargs)

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 2048,
        temperature: float = 0.0,
        json_object: bool = False,
        reasoning: bool = False,
    ) -> Completion:
        self.ledger.check()

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            **_ATTRIBUTION,
        }

        started = time.perf_counter()
        body: dict[str, Any] | None = None
        failures: list[str] = []

        for model in (self.model, *self.fallbacks):
            payload: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "reasoning": {"enabled": reasoning},
            }
            if json_object:
                payload["response_format"] = {"type": "json_object"}
            try:
                body = self._post_with_retries(payload, headers)
                self.last_model_used = model
                break
            except ProviderError as exc:
                # A free endpoint being rate-limited or refusing a parameter is a
                # reason to try the next model, not to fail the analysis.
                failures.append(f"{model}: {exc}")
                continue

        if body is None:
            raise ProviderError(
                "every model failed:\n  " + "\n  ".join(failures)
            )
        latency = time.perf_counter() - started

        choice = body["choices"][0]["message"]
        usage = body.get("usage", {})
        text = choice.get("content") or ""
        reasoning_text = choice.get("reasoning") or ""

        if not text:
            # Almost always max_tokens swallowed by reasoning tokens. Say which,
            # because "the model returned nothing" sends you looking in the wrong place.
            raise ProviderError(
                f"{self.model} returned empty content "
                f"(finish_reason={body['choices'][0].get('finish_reason')!r}, "
                f"{len(reasoning_text)} reasoning chars, "
                f"{usage.get('completion_tokens')} completion tokens). "
                "Raise max_tokens or keep reasoning disabled."
            )

        cost = float(usage.get("cost", 0.0))
        self.ledger.record(cost)

        return Completion(
            text=text,
            model=body.get("model", self.model),
            provider=self.name,
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            reasoning_chars=len(reasoning_text),
            cost_usd=cost,
            latency_s=latency,
            raw=body,
        )

    def _post_with_retries(
        self, payload: dict[str, Any], headers: dict[str, str]
    ) -> dict[str, Any]:
        delay = 1.0
        last: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = requests.post(
                    OPENROUTER_URL, json=payload, headers=headers, timeout=self.timeout_s
                )
            except requests.RequestException as exc:
                last = exc
            else:
                if resp.status_code == 200:
                    body = resp.json()
                    # OpenRouter can return 200 with an error body.
                    if "error" in body:
                        raise ProviderError(f"provider error: {body['error']}")
                    return body
                if resp.status_code == 400 and "reasoning" in resp.text.lower() \
                        and "mandatory" in resp.text.lower():
                    # gpt-oss-20b and friends refuse reasoning:{enabled:false}.
                    # Drop the parameter and retry the same model rather than
                    # discarding an otherwise usable endpoint.
                    if "reasoning" in payload:
                        payload.pop("reasoning")
                        continue
                if resp.status_code not in _RETRY_STATUS:
                    raise ProviderError(
                        f"HTTP {resp.status_code}: {resp.text[:300]}"
                    )
                last = ProviderError(f"HTTP {resp.status_code}: {resp.text[:200]}")

            if attempt < self.max_retries - 1:
                time.sleep(delay)
                delay *= 2
        raise ProviderError(f"giving up after {self.max_retries} attempts: {last}")


@dataclass
class LocalProvider:
    """On-premise open-weights path. Not implemented — deliberately not faked.

    The proposal's on-prem claim is only true if this is real. Until it is, it
    raises, so that "we can run air-gapped" cannot quietly become false by a
    fallback silently routing to a hosted API.
    """

    model: str = "qwen2.5-coder-3b-instruct"
    name: str = "local"

    def complete(self, *args: Any, **kwargs: Any) -> Completion:
        raise ProviderError(
            "LocalProvider is not implemented. The on-premise path needs a local "
            "runtime (ollama or llama.cpp) plus a 3B-class coder model on the "
            "6 GB GPU. Use OpenRouterProvider, and do not describe this build as "
            "air-gapped until this method works."
        )


def get_provider(name: str = "openrouter", **kwargs: Any) -> Provider:
    if name == "openrouter":
        return OpenRouterProvider.from_env(**kwargs)
    if name == "local":
        return LocalProvider(**kwargs)
    raise ProviderError(f"unknown provider {name!r}; expected 'openrouter' or 'local'")


def _smoke() -> int:
    """End-to-end check: plain call, JSON mode, budget refusal, error clarity."""
    provider = OpenRouterProvider.from_env()
    print(f"provider  : {provider.name}\nmodel     : {provider.model}")
    print(f"fallbacks : {', '.join(provider.fallbacks) or '(none)'}")

    c = provider.complete([{"role": "user", "content": "Reply with exactly: OK"}], max_tokens=256)
    print(f"\n[1] plain      -> {c.text.strip()!r}  via {c.model} "
          f"({c.completion_tokens} tok, ${c.cost_usd:.6f}, {c.latency_s:.1f}s)")
    assert "OK" in c.text

    c = provider.complete(
        [{"role": "user", "content": 'Return JSON: {"verdict":"clean","count":3}'}],
        max_tokens=256, json_object=True,
    )
    parsed = c.json()
    print(f"[2] json mode  -> {parsed}  via {c.model} (${c.cost_usd:.6f})")
    assert parsed["count"] == 3

    # A model that does not exist must fall through to a working one rather
    # than failing the analysis.
    fb = OpenRouterProvider.from_env(model="nonexistent/model-that-is-not-real")
    c = fb.complete([{"role": "user", "content": "Reply with exactly: OK"}], max_tokens=256)
    print(f"[3] fallback   -> recovered on {c.model}")

    tight = OpenRouterProvider.from_env(ledger=CostLedger(cap_usd=0.0))
    try:
        tight.complete([{"role": "user", "content": "hi"}], max_tokens=16)
    except BudgetExceeded as exc:
        print(f"[3] budget cap -> refused: {exc}")
    else:
        print("[3] budget cap -> !! FAILED: call was not refused")
        return 1

    try:
        LocalProvider().complete([])
    except ProviderError:
        print("[4] local path -> raises, as intended (on-prem claim stays honest)")

    print(f"\nledger: {provider.ledger.summary()}")
    return 0


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--smoke", action="store_true", help="run a live end-to-end check")
    args = ap.parse_args()
    if args.smoke:
        raise SystemExit(_smoke())
    ap.print_help()
