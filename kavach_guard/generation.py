"""Bounded real-model adapter. Protected workflows never fall back to simulation."""

import os
from typing import Any, Protocol

import requests
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class BackendUnavailable(RuntimeError):
    pass


class GenerationError(RuntimeError):
    pass


class ProposedToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tool_name: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ModelTurn(BaseModel):
    content: str = Field(default="", max_length=65536)
    tool_calls: list[ProposedToolCall] = Field(default_factory=list, max_length=4)

    def as_message(self) -> dict[str, Any]:
        message: dict[str, Any] = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            message["tool_calls"] = [
                {"type": "function", "function": {"name": call.tool_name, "arguments": call.arguments}}
                for call in self.tool_calls
            ]
        return message


class GenerationBackend(Protocol):
    backend_id: str
    kind: str

    def next_turn(self, messages: list[dict], tools: list[dict]) -> ModelTurn: ...


class OllamaChatBackend:
    kind = "real"

    def __init__(self, model: str | None = None, endpoint: str | None = None):
        self.model = model or os.getenv("KAVACH_LLM_MODEL", "qwen2.5:3b")
        self.endpoint = (endpoint or os.getenv("KAVACH_OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.backend_id = f"ollama/{self.model}"
        self.timeout = min(60.0, max(1.0, float(os.getenv("KAVACH_LLM_TIMEOUT", "45"))))

    def next_turn(self, messages: list[dict], tools: list[dict]) -> ModelTurn:
        payload = {
            "model": self.model, "messages": messages, "stream": False,
            "options": {"temperature": 0, "num_predict": 1024, "num_ctx": 8192},
        }
        if tools:
            payload["tools"] = tools
        try:
            # Disable ambient proxy credentials and redirects for this configured service.
            with requests.Session() as session:
                session.trust_env = False
                response = session.post(
                    f"{self.endpoint}/api/chat", json=payload,
                    timeout=(5, self.timeout), allow_redirects=False, stream=True,
                )
                if response.status_code != 200:
                    raise BackendUnavailable("The configured model service is unavailable or rejected the request.")
                body = bytearray()
                for part in response.iter_content(8192):
                    body.extend(part)
                    if len(body) > 262144:
                        raise GenerationError("Model response exceeded the allowed size.")
                import json
                data = json.loads(body)
        except requests.RequestException as exc:
            raise BackendUnavailable("Cannot reach the configured Ollama model. Start Ollama and install the configured model.") from exc
        except (ValueError, TypeError) as exc:
            raise GenerationError("The model service returned an invalid response.") from exc
        try:
            if data.get("done_reason") == "length" or data.get("done") is False:
                raise GenerationError("The model exhausted its generation budget; an incomplete response was withheld.")
            message = data["message"]
            calls = [
                ProposedToolCall(tool_name=call["function"]["name"], arguments=call["function"]["arguments"])
                for call in message.get("tool_calls", [])
            ]
            turn = ModelTurn(content=message.get("content", ""), tool_calls=calls)
            if not turn.content.strip() and not turn.tool_calls:
                raise GenerationError("The model returned neither an answer nor a tool proposal.")
            return turn
        except (KeyError, TypeError, AttributeError, ValidationError) as exc:
            raise GenerationError("The model returned a malformed answer or tool proposal.") from exc


def get_generation_backend() -> GenerationBackend:
    backend = os.getenv("KAVACH_LLM_BACKEND", "ollama").lower()
    if backend != "ollama":
        raise BackendUnavailable("Protected workflows require the Ollama backend. Simulation is available only in the attack sandbox.")
    return OllamaChatBackend()
