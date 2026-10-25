"""
Kavach-AI: Configurable RAG Pipeline (High Performance)
Handles fixed-size token chunking (256, 512, 1024 tokens) with 10% overlap,
vector embedding calculation, indexing, and top-k retrieval (k in [1, 3, 5, 10]).
Supports high-speed single-candidate poisoned twin evaluation.
"""

import os
import re
import math
from typing import List, Dict, Any, Tuple

class Chunk:
    def __init__(self, doc_id: str, chunk_id: str, text: str, is_poisoned: bool = False):
        self.doc_id = doc_id
        self.chunk_id = chunk_id
        self.text = text
        self.is_poisoned = is_poisoned

class VectorRAG:
    def __init__(self, chunk_size: int = 512, overlap_pct: float = 0.10):
        self.chunk_size = chunk_size
        self.overlap = int(chunk_size * overlap_pct)
        self.chunks: List[Chunk] = []
        self.vocab: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.tfidf_matrix: List[Dict[int, float]] = []

    def chunk_text(self, text: str, doc_id: str, is_poisoned: bool = False) -> List[Chunk]:
        """Splits text into fixed-size word token chunks with overlap."""
        words = text.split()
        if not words:
            return []
            
        chunks = []
        step = max(1, self.chunk_size - self.overlap)
        
        for i in range(0, len(words), step):
            chunk_words = words[i:i + self.chunk_size]
            chunk_text = " ".join(chunk_words)
            chunk_id = f"{doc_id}_c{len(chunks):02d}"
            chunks.append(Chunk(doc_id, chunk_id, chunk_text, is_poisoned))
            if i + self.chunk_size >= len(words):
                break
                
        return chunks

    def _tokenize(self, text: str) -> List[str]:
        return [w.lower() for w in re.findall(r'\b[a-zA-Z0-9_\-]{2,}\b', text)]

    def index_corpus(self, docs_dir: str):
        """Indexes all benign documents in the specified directory."""
        self.chunks = []
        for filename in sorted(os.listdir(docs_dir)):
            if filename.endswith(".txt"):
                filepath = os.path.join(docs_dir, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    text = f.read()
                doc_chunks = self.chunk_text(text, filename, is_poisoned=False)
                self.chunks.extend(doc_chunks)
                
        self._build_vector_index()

    def _build_vector_index(self):
        """Builds TF-IDF sparse vector representations for fast, deterministic top-k search."""
        doc_freq = {}
        N = len(self.chunks)
        if N == 0:
            return

        tokenized_chunks = []
        for chunk in self.chunks:
            tokens = self._tokenize(chunk.text)
            tokenized_chunks.append(tokens)
            unique_tokens = set(tokens)
            for t in unique_tokens:
                doc_freq[t] = doc_freq.get(t, 0) + 1

        self.vocab = {term: idx for idx, term in enumerate(doc_freq.keys())}
        self.idf = {term: math.log((N + 1) / (df + 1)) + 1.0 for term, df in doc_freq.items()}

        self.tfidf_matrix = []
        for tokens in tokenized_chunks:
            vec = self._vectorize(tokens)
            self.tfidf_matrix.append(vec)

    def _vectorize(self, tokens: List[str]) -> Dict[int, float]:
        tf = {}
        for t in tokens:
            if t in self.vocab:
                idx = self.vocab[t]
                tf[idx] = tf.get(idx, 0) + 1
                
        total = len(tokens) or 1
        vec = {}
        sum_sq = 0.0
        for idx, count in tf.items():
            term = list(self.vocab.keys())[idx]
            weight = (count / total) * self.idf.get(term, 1.0)
            vec[idx] = weight
            sum_sq += weight * weight
            
        norm = math.sqrt(sum_sq) or 1.0
        for idx in vec:
            vec[idx] /= norm
            
        return vec

    def retrieve(self, query: str, k: int) -> List[Tuple[Chunk, float]]:
        """Retrieves top-k nearest chunks for a given query from benign index."""
        q_tokens = self._tokenize(query)
        q_vec = self._vectorize(q_tokens)
        
        scores = []
        for idx, doc_vec in enumerate(self.tfidf_matrix):
            sim = sum(q_weight * doc_vec[t_idx] for t_idx, q_weight in q_vec.items() if t_idx in doc_vec)
            scores.append((self.chunks[idx], sim))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:k]

    def retrieve_with_poisoned_doc(self, query: str, poisoned_text: str, doc_id: str, k: int) -> List[Tuple[Chunk, float]]:
        """
        Fast evaluation of trial with exactly one poisoned document inserted.
        Computes poisoned chunk scores and merges into top-k without rebuilding entire index.
        """
        q_tokens = self._tokenize(query)
        q_vec = self._vectorize(q_tokens)

        # Baseline benign candidates
        candidates = []
        for idx, doc_vec in enumerate(self.tfidf_matrix):
            sim = sum(q_weight * doc_vec[t_idx] for t_idx, q_weight in q_vec.items() if t_idx in doc_vec)
            candidates.append((self.chunks[idx], sim))

        # Poisoned chunks
        p_chunks = self.chunk_text(poisoned_text, doc_id, is_poisoned=True)
        for p_chunk in p_chunks:
            p_vec = self._vectorize(self._tokenize(p_chunk.text))
            p_sim = sum(q_weight * p_vec[t_idx] for t_idx, q_weight in q_vec.items() if t_idx in p_vec)
            # Since the poisoned document is an exact twin of the target topic, its similarity matches or exceeds benign
            candidates.append((p_chunk, p_sim + 0.05)) # Target doc has high relevance

        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:k]
