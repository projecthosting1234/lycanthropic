"""Centralized prompt template loader.

All LLM prompt files live under analysis/prompts/. This module provides
a single cached loader so every step module doesn't have to duplicate
the Path construction and file-reading boilerplate.
"""

from __future__ import annotations

import logging
import os
import json 

from pathlib import Path
from analysis.sym_object_helper import get_llm_config, load_key_from_env_file

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"
_cache: dict[str, str] = {}


def load_prompt(name: str) -> str:
    """Load a prompt template by filename. Cached after first load.

    Args:
        name: Prompt filename, e.g. "01-classify-function-extract-facts.txt"

    Returns:
        The prompt template text.

    Raises:
        FileNotFoundError: If the prompt file does not exist.
    """
    if name in _cache:
        return _cache[name]

    path = _PROMPTS_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Prompt file not found: {path}")

    text = path.read_text(encoding="utf-8")
    _cache[name] = text
    return text


from analysis.sym_object_helper import get_llm_max_tokens

_LLM_MAX_TOKENS = get_llm_max_tokens()


def load_llm_config() -> tuple[str, str, str] | None:
    """Load LLM configuration from config.json.

    Reads the default provider and its associated model from config.json,
    then retrieves the API key. Priority order:
      1. .env file in project root
      2. Environment variables
    
    The env_key specified in config.json determines which key to look for.

    Returns:
        Tuple of (provider, api_key, model) or None if no valid config found.
    """
    from analysis.sym_object_helper import get_llm_config

    llm_config = get_llm_config()
    
    # Get default provider
    default_provider = llm_config.get("default_provider", "openai")
    providers = llm_config.get("providers", {})
    
    # Get provider config
    provider_config = providers.get(default_provider)
    if not provider_config:
        print(f"[!] Provider '{default_provider}' not found in config.json")
        return None
    
    # Get model from provider config
    model = provider_config.get("model")
    if not model:
        print(f"[!] No model specified for provider '{default_provider}'")
        return None
    
    # Get the env key name from provider config
    env_key = provider_config.get("env_key")
    if not env_key:
        print(f"[!] No env_key specified for provider '{default_provider}'")
        return None
    
    # Try to load from .env file first
    api_key = load_key_from_env_file(env_key)
    
    # Fall back to environment variable if not found in .env
    if not api_key:
        api_key = os.environ.get(env_key)
    
    if not api_key:
        print(f"[!] API key '{env_key}' not found in .env or environment variables")
        return None
    
    return (default_provider, api_key, model)

def call_llm(provider: str, api_key: str, model: str, prompt: str, max_tokens: int = _LLM_MAX_TOKENS) -> str:
    """Call the LLM and return the response text."""
    try:
        if provider == "openai":
            import openai
            client = openai.OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model=model,
                max_completion_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            choice = resp.choices[0]
            content = choice.message.content
            finish = choice.finish_reason
            logger.info(f"  [debug] finish_reason={finish}, content_len={len(content) if content else 'None'}, usage={resp.usage}")
            if not content or not content.strip():
                logger.info(f"[!] OpenAI returned empty content (finish_reason={finish})")
                if hasattr(choice.message, 'refusal') and choice.message.refusal:
                    logger.info(f"[!] Refusal: {choice.message.refusal}")
                return ""
            return content.strip()
        elif provider == "openrouter":
            import openai
            client = openai.OpenAI(
                api_key=api_key,
                base_url="https://openrouter.ai/api/v1",
                default_headers={
                    "HTTP-Referer": "http://localhost",
                    "X-Title": "Finder",
                },
            )
            resp = client.chat.completions.create(
                model=model,
                max_completion_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            choice = resp.choices[0]
            content = choice.message.content
            finish = choice.finish_reason
            logger.info(f"  [debug] finish_reason={finish}, content_len={len(content) if content else 'None'}, usage={resp.usage}")
            if not content or not content.strip():
                logger.info(f"[!] OpenAI returned empty content (finish_reason={finish})")
                if hasattr(choice.message, 'refusal') and choice.message.refusal:
                    logger.info(f"[!] Refusal: {choice.message.refusal}")
                return ""
            return content.strip()
        elif provider == "deepseek":
            import openai
            client = openai.OpenAI(
                api_key=api_key,
                base_url="https://api.deepseek.com"
            )
            resp = client.chat.completions.create(
                model=model,
                max_completion_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
                extra_body={ "thinking": { "type": "enabled" } }
            )
            choice = resp.choices[0]
            content = choice.message.content
            finish = choice.finish_reason
            logger.info(f"  [debug] finish_reason={finish}, content_len={len(content) if content else 'None'}, usage={resp.usage}")
            if not content or not content.strip():
                logger.info(f"[!] OpenAI returned empty content (finish_reason={finish})")
                if hasattr(choice.message, 'refusal') and choice.message.refusal:
                    logger.info(f"[!] Refusal: {choice.message.refusal}")
                return ""
            return content.strip()
        else:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            resp = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            if not resp.content:
                logger.info(f"[!] Anthropic returned empty content (stop_reason={resp.stop_reason})")
                return ""
            return resp.content[0].text.strip()
    except Exception as e:
        import traceback
        logger.info(f"[!] LLM API call failed ({provider}/{model}): {e}")
        traceback.print_exc()
        raise



# ── LLM ranking ──────────────────────────────────────────────────────────────


def _llm_rank_sinks(all_imports: list[dict], top_n: int = 10) -> list[str] | None:
    """Hand every import to the LLM, let it pick the top-N dangerous ones."""
    cfg = load_llm_config()
    if not cfg:
        logger.info("\n[!] No API key found. Set OPENAI_API_KEY or ANTHROPIC_API_KEY, or add to .env.")
        return None

    provider, api_key, model = cfg

    import_lines = "\n".join(
        f"- {imp['name']}  ({imp['module']})"
        for imp in all_imports
    )

    prompt = (
        "You are a Windows kernel vulnerability researcher specializing in "
        "Local Privilege Escalation from standard user to SYSTEM.\n\n"
        "Below is the COMPLETE import table of a kernel-mode driver. "
        "Most of these are harmless. Your job is to identify the ones that "
        "are dangerous — functions that, if called with attacker-controlled "
        "arguments, could lead to privilege escalation.\n\n"
        f"{import_lines}\n\n"
        f"From this list, pick the top {top_n} most dangerous imports for LPE. "
        "Consider:\n"
        "- Memory mapping (arbitrary R/W): MmMapIoSpace, ZwMapViewOfSection\n"
        "- Unsafe copy with user-controlled size: memcpy, RtlCopyMemory\n"
        "- Process/token manipulation: ZwOpenProcess, ZwOpenProcessToken\n"
        "- MSR/CR/IO port access: __writemsr, __readcr0\n"
        "- Pool allocation (overflow targets): ExAllocatePoolWithTag\n\n"
        "Respond with ONLY a JSON array of exactly the function names "
        "from the list above, most dangerous first. No explanations.\n"
        'Example: ["MmMapIoSpace", "ZwMapViewOfSection", "memcpy"]'
    )

    logger.info(f"\n[*] Asking LLM ({provider}/{model}) to identify top-{top_n} sinks...")

    try:
        text = call_llm(provider, api_key, model, prompt)

        from analysis.common.json_repair import strip_code_fences
        text = strip_code_fences(text)

        top_10 = json.loads(text)
        if not isinstance(top_10, list):
            raise ValueError("expected JSON array")

        top_10 = top_10[:top_n]
        logger.info()
        for i, name in enumerate(top_10, 1):
            logger.info(f"  [{i:>2d}] {name}")

        return top_10
    except Exception as e:
        import traceback
        logger.info(f"\n[!] LLM ranking failed: {e}")
        traceback.print_exc()
        return None
    
    # ── LLM config accessors ────────────────────────────────────────

def get_llm_config() -> dict[str, Any]:
    """Get the LLM section of the configuration.
    
    Returns:
        Dictionary containing LLM settings including:
        - default_provider, default_model
        - provider-specific settings
    """
    config = load_config()
    return config.get("llm", {})

def get_llm_max_tokens() -> int:
    """Default max tokens for LLM calls."""
    return get_llm_config().get("max_tokens", 50000)


def get_advanced_extraction() -> int:
    """Get the advanced_extraction flag from llm config.

    Returns:
        -1: never use pro model
         0: auto retry with pro on failure (default)
         1: always use pro model
    """
    return get_llm_config().get("advanced_extraction", 0)


def get_pro_model() -> str:
    """Get the pro model identifier for LLM escalation.

    Returns:
        Model string, defaults to 'gpt-5.4-pro-2026-03-05'.
    """
    return get_llm_config().get("pro_model", "gpt-5.4-pro-2026-03-05")

def load_key_from_env_file(env_key: str) -> str | None:
    """Load a specific environment variable from .env file in project root.
    
    Args:
        env_key: The environment variable name to look for (e.g., "OPENAI_API_KEY")
        
    Returns:
        The value of the key if found, None otherwise.
    """
    env_file = _PROJECT_ROOT / ".env"
    if not env_file.exists():
        return None
    
    try:
        # Parse .env file
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                # Parse KEY=VALUE format
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    if key == env_key:
                        return value
    except Exception as e:
        logger.info(f"[!] Warning: Failed to parse .env file: {e}")
    
    return None
