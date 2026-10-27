import json

import pytest

from kavach_guard.generation import BackendUnavailable, GenerationError, OllamaChatBackend, get_generation_backend


class FakeResponse:
    status_code = 200

    def __init__(self, data):
        self.data = json.dumps(data).encode()

    def iter_content(self, size):
        yield self.data


def adapter_response(monkeypatch, data):
    monkeypatch.setattr("requests.Session.post", lambda *args, **kwargs: FakeResponse(data))


def test_ollama_native_tool_call_parsing(monkeypatch):
    adapter_response(monkeypatch, {"message": {"content": "", "tool_calls": [
        {"function": {"name": "retrieve_bank_rates", "arguments": {"product": "savings"}}}
    ]}})
    turn = OllamaChatBackend().next_turn([], [])
    assert turn.tool_calls[0].arguments == {"product": "savings"}


@pytest.mark.parametrize("message", [{}, {"content": ""}, {"content": "answer", "tool_calls": [
    {"function": {"name": "retrieve_bank_rates", "arguments": "unparsed string"}}
]}])
def test_malformed_responses_fail_explicitly(monkeypatch, message):
    adapter_response(monkeypatch, {"message": message})
    with pytest.raises(GenerationError):
        OllamaChatBackend().next_turn([], [])


def test_protected_backend_configuration_cannot_fall_back_to_simulation(monkeypatch):
    monkeypatch.setenv("KAVACH_LLM_BACKEND", "calibrated")
    with pytest.raises(BackendUnavailable):
        get_generation_backend()


def test_partial_generation_is_not_delivered_or_executed(monkeypatch):
    adapter_response(monkeypatch, {"done": True, "done_reason": "length", "message": {"content": "Incomplete answer"}})
    with pytest.raises(GenerationError, match="incomplete response"):
        OllamaChatBackend().next_turn([], [])
