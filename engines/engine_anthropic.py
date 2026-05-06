
import anthropic
from engines.base import BaseEngine, SYSTEM_PROMPT
from config import ANTHROPIC_API_KEY, AI_MODEL, MAX_TOKENS
 
 
class AnthropicEngine(BaseEngine):
 
    def __init__(self):
        if not ANTHROPIC_API_KEY:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY fehlt in der .env-Datei.\n"
                "Konto anlegen: https://console.anthropic.com\n"
                
            )
        self._client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        print(f"[AnthropicEngine] Verbunden mit Modell '{AI_MODEL}' ✓")
 
    def ask_ai(
        self,
        prompt: str,
        conversation_history: list[dict] | None = None,
    ) -> str:
        messages = list(conversation_history or [])
        messages.append({"role": "user", "content": prompt})
 
        response = self._client.messages.create(
            model=AI_MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=messages,
        )
        return response.content[0].text