"""
KAVACH v2 - Layer 2: Pretrained ML Injection Classifier & Model Manager
Provides cached instance lifecycle management for transformer-based
prompt-injection classifiers (primary: deepset/deberta-v3-base-injection).
Supports Apple Silicon (MPS) / CPU auto-detection, batch inference,
truncation handling, exact latency measurement, and graceful degradation.
"""

import os
import time
import logging
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("kavach_guard.model_manager")

# Default production model: ungated, runs locally on CPU/MPS
DEFAULT_MODEL_ID = os.getenv("KAVACH_ML_MODEL", "deepset/deberta-v3-base-injection")
DEFAULT_THRESHOLD = float(os.getenv("KAVACH_ML_THRESHOLD", "0.50"))
MAX_TOKEN_LENGTH = int(os.getenv("KAVACH_MAX_TOKEN_LEN", "512"))


class MLInferenceResult(BaseModel):
    model_id: str
    predicted_label: str       # "INJECTION" or "LEGIT"
    raw_scores: Dict[str, float] = Field(default_factory=dict)
    injection_score: float     # Raw model probability for injection class (not calibrated)
    threshold: float
    latency_ms: float
    truncated: bool = False
    device: str = "cpu"
    status: str = "completed"  # "completed", "degraded", "error"
    error_message: Optional[str] = None


class ModelManager:
    """Manages tokenizer and model lifecycle per model_id without cross-contamination."""
    _instances: Dict[str, "ModelManager"] = {}

    def __init__(self, model_id: Optional[str] = None):
        self._model_id = model_id or DEFAULT_MODEL_ID
        self._model = None
        self._tokenizer = None
        self._device = "cpu"
        self._status = "uninitialized"  # "uninitialized", "loading", "ready", "failed"
        self._error: Optional[str] = None
        self._id2label: Dict[int, str] = {}
        self._label2id: Dict[str, int] = {}

    @property
    def status(self) -> str:
        return self._status

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def device(self) -> str:
        return self._device

    def is_available(self) -> bool:
        return self._status == "ready" and self._model is not None

    def initialize(self, force_reload: bool = False) -> bool:
        """Loads tokenizer and weights lazily. Safe for repeated calls."""
        if self._status == "ready" and not force_reload:
            return True

        self._status = "loading"
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            # Detect hardware acceleration: Apple Silicon MPS or CUDA if available
            if torch.backends.mps.is_available():
                self._device = "mps"
            elif torch.cuda.is_available():
                self._device = "cuda"
            else:
                self._device = "cpu"

            logger.info(f"Loading ML model '{self._model_id}' on device '{self._device}'...")
            t0 = time.time()
            self._tokenizer = AutoTokenizer.from_pretrained(self._model_id)
            self._model = AutoModelForSequenceClassification.from_pretrained(self._model_id)
            self._model.to(self._device)
            self._model.eval()
            t_load = time.time() - t0

            # Inspect label mapping
            self._id2label = getattr(self._model.config, "id2label", {0: "LEGIT", 1: "INJECTION"})
            self._label2id = getattr(self._model.config, "label2id", {"LEGIT": 0, "INJECTION": 1})

            self._status = "ready"
            self._error = None
            logger.info(f"Model '{self._model_id}' initialized in {t_load:.2f}s on {self._device}.")
            return True

        except Exception as e:
            self._status = "failed"
            self._error = str(e)
            logger.error(f"Failed to load ML model '{self._model_id}': {e}")
            return False

    def predict_single(self, text: str, threshold: float = DEFAULT_THRESHOLD) -> MLInferenceResult:
        """Infers single text input, measuring exact latency and truncation status."""
        results = self.predict_batch([text], threshold=threshold)
        return results[0]

    def predict_batch(self, texts: List[str], threshold: float = DEFAULT_THRESHOLD) -> List[MLInferenceResult]:
        """Runs batch inference, handling tokenization, truncation, and latency measurement."""
        if not texts:
            return []

        # If model is uninitialized, attempt lazy load
        if not self.is_available():
            success = self.initialize()
            if not success:
                # Graceful degradation response: does not crash, reports degraded state
                return [
                    MLInferenceResult(
                        model_id=self._model_id,
                        predicted_label="UNKNOWN",
                        raw_scores={},
                        injection_score=0.0,
                        threshold=threshold,
                        latency_ms=0.0,
                        device=self._device,
                        status="degraded",
                        error_message=f"Model unavailable: {self._error}"
                    )
                    for _ in texts
                ]

        import torch

        results: List[MLInferenceResult] = []
        try:
            # Tokenize batch with truncation flag tracking
            encoded = self._tokenizer(
                texts,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=MAX_TOKEN_LENGTH
            )

            # Check if any input exceeded max tokens
            truncation_flags = []
            for t in texts:
                raw_tokens_len = len(self._tokenizer.encode(t, truncation=False))
                truncation_flags.append(raw_tokens_len > MAX_TOKEN_LENGTH)

            # Move tensors to device
            input_ids = encoded["input_ids"].to(self._device)
            attention_mask = encoded["attention_mask"].to(self._device)

            # Run inference with timing
            t_start = time.perf_counter()
            with torch.no_grad():
                outputs = self._model(input_ids=input_ids, attention_mask=attention_mask)
                probs = torch.softmax(outputs.logits, dim=-1).cpu()
            t_end = time.perf_counter()

            total_batch_latency_ms = (t_end - t_start) * 1000
            per_item_latency_ms = round(total_batch_latency_ms / max(len(texts), 1), 2)

            # Determine injection class index
            injection_idx = 1
            for idx, label_name in self._id2label.items():
                if any(w in label_name.upper() for w in ("INJECT", "MALICIOUS", "ATTACK")):
                    injection_idx = idx
                    break

            for i in range(len(texts)):
                raw_scores = {}
                for idx, label_name in self._id2label.items():
                    raw_scores[label_name] = round(float(probs[i][idx].item()), 4)

                inj_prob = float(probs[i][injection_idx].item())
                predicted_label = "INJECTION" if inj_prob >= threshold else "LEGIT"

                results.append(
                    MLInferenceResult(
                        model_id=self._model_id,
                        predicted_label=predicted_label,
                        raw_scores=raw_scores,
                        injection_score=round(inj_prob, 4),
                        threshold=threshold,
                        latency_ms=per_item_latency_ms,
                        truncated=truncation_flags[i],
                        device=self._device,
                        status="completed"
                    )
                )

        except Exception as e:
            logger.error(f"Inference error in ModelManager: {e}")
            for _ in texts:
                results.append(
                    MLInferenceResult(
                        model_id=self._model_id,
                        predicted_label="UNKNOWN",
                        raw_scores={},
                        injection_score=0.0,
                        threshold=threshold,
                        latency_ms=0.0,
                        device=self._device,
                        status="error",
                        error_message=str(e)
                    )
                )

        return results


def get_model_manager(model_id: Optional[str] = None) -> ModelManager:
    """Returns or creates a cached ModelManager instance for the specified model_id."""
    target_id = model_id or DEFAULT_MODEL_ID
    if target_id not in ModelManager._instances:
        ModelManager._instances[target_id] = ModelManager(model_id=target_id)
    return ModelManager._instances[target_id]
