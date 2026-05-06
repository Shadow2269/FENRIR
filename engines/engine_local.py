from transformers import AutoTokenizer, AutoModelForCausalLM
from engines.base import BaseEngine, SYSTEM_PROMPT
from config import MAX_TOKENS, HF_TOKEN
 
 
MODEL_NAME = "mistralai/Mistral-7B-Instruct-v0.2"
 
 
class LocalEngine(BaseEngine):
 
    def __init__(self):
        print(f"[LocalEngine] Lade Modell '{MODEL_NAME}' …")
        print("  (Erster Start dauert einige Minuten — Modell wird heruntergeladen)")
 
        self.tokenizer = AutoTokenizer.from_pretrained(
            MODEL_NAME,
            token=HF_TOKEN,
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME,
            token=HF_TOKEN,
            device_map="auto",    # ← verteilt automatisch auf GPU/CPU
            torch_dtype="auto",   # ← wählt float16/bfloat16 je nach Hardware
        )
        print("[LocalEngine] Modell geladen ✓")
 
    def ask_ai(
        self,
        prompt: str,
        conversation_history: list[dict] | None = None,
    ) -> str:
        # Baue den vollen Prompt zusammen (System + History + neue Frage)
        full_prompt = SYSTEM_PROMPT + "\n"
 
        for turn in (conversation_history or []):
            role = "User" if turn["role"] == "user" else "Assistant"
            full_prompt += f"{role}: {turn['content']}\n"
 
        full_prompt += f"User: {prompt}\nAssistant:"
 
        inputs = self.tokenizer(full_prompt, return_tensors="pt").to(
            self.model.device
        )
 
        output = self.model.generate(
            **inputs,
            max_new_tokens=MAX_TOKENS,
            temperature=0.7,
            do_sample=True,
            pad_token_id=self.tokenizer.eos_token_id,
        )
 
        # Nur den neu generierten Teil zurückgeben (nicht den Prompt wiederholen)
        new_tokens = output[0][inputs["input_ids"].shape[1]:]
        return self.tokenizer.decode(new_tokens, skip_special_tokens=True).strip()