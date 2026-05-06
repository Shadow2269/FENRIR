from config import ENGINE
from logger import log
 
_engine = None
 
 
def _get_engine():
    global _engine
    if _engine is not None:
        return _engine
 
    if ENGINE == "anthropic":
        log("Engine: Anthropic API (claude)")
        from engines.engine_anthropic import AnthropicEngine
        _engine = AnthropicEngine()
 
    else:  # default: local
        log("Engine: Lokales Mistral-Modell (gratis)")
        from engines.engine_local import LocalEngine
        _engine = LocalEngine()
 
    return _engine
 
 
def ask_ai(prompt: str, conversation_history: list[dict] | None = None) -> str:
    return _get_engine().ask_ai(prompt, conversation_history)
 