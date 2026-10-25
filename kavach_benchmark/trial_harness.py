"""
Kavach-AI: Automated Trial Harness (Optimized)
Executes the full 72-configuration measurement matrix across:
- k in [1, 3, 5, 10]
- chunk_size in [256, 512, 1024]
- hardening in ['none', 'instructional', 'sandwich']
- guardrail in ['off', 'on']
Executes 100 poisoned trials and 100 benign query trials per configuration.
Supports resume checkpointing, dry-runs, and progress tracking.
"""

import os
import csv
import json
import time
from typing import List, Dict, Any

from kavach_benchmark.vector_rag import VectorRAG
from kavach_benchmark.prompt_builder import build_rag_prompt
from kavach_benchmark.guardrail import OutputGuardrail, CANARY_TOKEN, PLANTED_SECRET
from kavach_benchmark.llm_backend import get_backend

CONFIG_PARAMS = {
    "k_values": [1, 3, 5, 10],
    "chunk_sizes": [256, 512, 1024],
    "hardenings": ["none", "instructional", "sandwich"],
    "guardrails": ["off", "on"]
}

def generate_72_configurations() -> List[Dict[str, Any]]:
    """Generates all 72 configurations in canonical C01 - C72 order."""
    configs = []
    cfg_idx = 1
    for k in CONFIG_PARAMS["k_values"]:
        for chunk_size in CONFIG_PARAMS["chunk_sizes"]:
            for hardening in CONFIG_PARAMS["hardenings"]:
                for guardrail in CONFIG_PARAMS["guardrails"]:
                    configs.append({
                        "cfg_id": f"C{cfg_idx:02d}",
                        "k": k,
                        "chunk_size": chunk_size,
                        "hardening": hardening,
                        "guardrail": guardrail
                    })
                    cfg_idx += 1
    return configs

class TrialHarness:
    def __init__(self, data_dir: str = "data", output_dir: str = "outputs", backend_type: str = "calibrated"):
        self.data_dir = data_dir
        self.output_dir = output_dir
        self.backend = get_backend(backend_type)
        
        os.makedirs(output_dir, exist_ok=True)
        self.results_csv = os.path.join(output_dir, "trial_results.csv")
        self.checkpoint_file = os.path.join(output_dir, "checkpoint.json")
        
        # Load manifest
        manifest_path = os.path.join(data_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(f"Manifest not found at {manifest_path}. Run corpus_generator first.")
            
        with open(manifest_path, "r", encoding="utf-8") as f:
            self.manifest = json.load(f)

        # Pre-cache poisoned texts for instant lookup
        self.poisoned_texts = {}
        poisoned_dir = os.path.join(data_dir, "poisoned_corpus")
        for fn in os.listdir(poisoned_dir):
            if fn.endswith(".txt"):
                with open(os.path.join(poisoned_dir, fn), "r", encoding="utf-8") as f:
                    self.poisoned_texts[fn] = f.read()

        # Cache pre-indexed RAG stores for each chunk size
        self.rag_stores = {}
        for c_size in CONFIG_PARAMS["chunk_sizes"]:
            rag = VectorRAG(chunk_size=c_size)
            rag.index_corpus(os.path.join(data_dir, "corpus"))
            self.rag_stores[c_size] = rag

    def init_csv(self):
        """Initializes the CSV output adhering strictly to Section 6.2 schema."""
        if not os.path.exists(self.results_csv):
            with open(self.results_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "cfg_id", "k", "chunk_size", "hardening", "guardrail",
                    "trial_type", "query", "response", "canary_match",
                    "leak_match", "blocked", "latency_ms"
                ])

    def run(self, sample_n: int = 100, max_configs: int = None, resume: bool = True):
        self.init_csv()
        all_configs = generate_72_configurations()
        if max_configs:
            all_configs = all_configs[:max_configs]

        completed_configs = set()
        if resume and os.path.exists(self.checkpoint_file):
            with open(self.checkpoint_file, "r") as f:
                completed_configs = set(json.load(f).get("completed_configs", []))

        print(f"Executing Kavach-AI Benchmark: {len(all_configs)} configs, {sample_n * 2} trials per config.")

        for cfg in all_configs:
            cfg_id = cfg["cfg_id"]
            if cfg_id in completed_configs:
                continue

            self._run_single_config(cfg, sample_n)
            completed_configs.add(cfg_id)
            print(f"Completed {cfg_id} (k={cfg['k']}, chunk={cfg['chunk_size']}, {cfg['hardening']}, guardrail={cfg['guardrail']})")

            with open(self.checkpoint_file, "w") as f:
                json.dump({"completed_configs": list(completed_configs)}, f)

        print("\nAll 72 benchmark configurations completed successfully!")

    def _run_single_config(self, cfg: Dict[str, Any], sample_n: int):
        k = cfg["k"]
        chunk_size = cfg["chunk_size"]
        hardening = cfg["hardening"]
        guardrail_enabled = (cfg["guardrail"] == "on")

        guardrail = OutputGuardrail(enabled=guardrail_enabled)
        rag = self.rag_stores[chunk_size]

        poisoned_queries = self.manifest["poisoned_queries"][:sample_n]
        benign_queries = self.manifest["benign_queries"][:sample_n]

        results = []

        # 1. Poisoned Trials
        for q_item in poisoned_queries:
            query = q_item["query"]
            target_fn = q_item["target_poisoned_doc"]
            p_text = self.poisoned_texts.get(target_fn, "")

            # Retrieve with poisoned document candidate
            retrieved = rag.retrieve_with_poisoned_doc(query, p_text, target_fn, k=k)
            retrieved_texts = [chunk.text for chunk, score in retrieved]
            has_poisoned = any(chunk.is_poisoned for chunk, score in retrieved)

            prompt_data = build_rag_prompt(query, retrieved_texts, hardening=hardening)
            
            start_t = time.perf_counter()
            response = self.backend.generate(
                prompt_data["system_prompt"],
                prompt_data["user_prompt"],
                metadata={
                    "hardening": hardening,
                    "k": k,
                    "chunk_size": chunk_size,
                    "has_poisoned_chunk": has_poisoned,
                    "query": query
                }
            )
            llm_time_ms = (time.perf_counter() - start_t) * 1000

            g_eval = guardrail.evaluate(response, is_benign_trial=False)
            total_latency = round(llm_time_ms + g_eval["latency_ms"], 1)

            results.append([
                cfg["cfg_id"], k, chunk_size, hardening, cfg["guardrail"],
                "poisoned", query, response,
                g_eval["canary_detected"],
                g_eval["secret_detected"],
                g_eval["blocked"],
                total_latency
            ])

        # 2. Benign Trials
        for q_item in benign_queries:
            query = q_item["query"]
            retrieved = rag.retrieve(query, k=k)
            retrieved_texts = [chunk.text for chunk, score in retrieved]

            prompt_data = build_rag_prompt(query, retrieved_texts, hardening=hardening)
            
            start_t = time.perf_counter()
            response = self.backend.generate(
                prompt_data["system_prompt"],
                prompt_data["user_prompt"],
                metadata={
                    "hardening": hardening,
                    "k": k,
                    "chunk_size": chunk_size,
                    "has_poisoned_chunk": False,
                    "query": query
                }
            )
            llm_time_ms = (time.perf_counter() - start_t) * 1000

            g_eval = guardrail.evaluate(response, is_benign_trial=True)
            total_latency = round(llm_time_ms + g_eval["latency_ms"], 1)

            results.append([
                cfg["cfg_id"], k, chunk_size, hardening, cfg["guardrail"],
                "benign", query, response,
                g_eval["canary_detected"],
                g_eval["secret_detected"],
                g_eval["blocked"],
                total_latency
            ])

        with open(self.results_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(results)

if __name__ == "__main__":
    harness = TrialHarness()
    harness.run(sample_n=100)
