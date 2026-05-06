"""
engines/base.py
Gemeinsames Interface — beide Engines implementieren genau diese Klasse.
Wer eine neue Engine hinzufügt (z.B. Ollama, OpenAI) erbt einfach von hier.
"""
from abc import ABC, abstractmethod
 
SYSTEM_PROMPT = """
You are an expert security analyst and red-team engineer.
 
Your mission:
1. Identify vulnerabilities in the target system (network or AI).
2. Attempt specific attack techniques as requested.
3. For EACH attempt report:
   - TECHNIQUE: <name of the technique used>
   - RESULT: <SUCCESS | FAIL | PARTIAL>
   - EXPLANATION: <what you tried and why>
   - NEXT_STEP: <improved attack if failed, or mitigation if succeeded>
 
If you determine a network tool should be run, output EXACTLY:
TOOL: nmap
TARGET: <ip or hostname>
 
Only use tools against targets that are in scope.
"""
 
 
class BaseEngine(ABC):
    @abstractmethod
    def ask_ai(
        self,
        prompt: str,
        conversation_history: list[dict] | None = None,
    ) -> str:
        """Schickt einen Prompt ab und gibt die Antwort als String zurück."""
        ...
 