# context_retriever.py
"""
Simple local retriever for RAG demo:
- Loads mitre_kb.json
- TF-IDF vectorizes text fields
- Cosine similarity search + basic Max Marginal Relevance (MMR)
"""

import json, math
from typing import List, Dict, Any
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

DATA = json.loads(Path(__file__).with_name("mitre_kb.json").read_text())

class Retriever:
    def __init__(self, k: int = 5, mmr_lambda: float = 0.5):
        self.k = k
        self.mmr_lambda = mmr_lambda
        self.documents = []
        for row in DATA:
            txt = " ".join([
                row.get("technique_id",""),
                row.get("technique_name",""),
                row.get("tactic",""),
                row.get("description",""),
                " ".join(row.get("aliases",[]))
            ])
            self.documents.append(txt)
        self.vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1,2), min_df=1)
        self.doc_matrix = self.vectorizer.fit_transform(self.documents)

    def _mmr(self, query_vec, doc_matrix, sim_query, k):
        selected = []
        candidates = list(range(doc_matrix.shape[0]))
        while len(selected) < min(k, len(candidates)):
            mmr_scores = []
            for c in candidates:
                if not selected:
                    diversity = 0.0
                else:
                    sim_to_selected = cosine_similarity(doc_matrix[c], doc_matrix[selected]).max()
                    diversity = sim_to_selected
                score = self.mmr_lambda * sim_query[0, c] - (1 - self.mmr_lambda) * diversity
                mmr_scores.append((c, score))
            best = max(mmr_scores, key=lambda x: x[1])[0]
            selected.append(best)
            candidates.remove(best)
        return selected

    def search(self, query: str) -> List[Dict[str, Any]]:
        q_vec = self.vectorizer.transform([query])
        sim = cosine_similarity(q_vec, self.doc_matrix)
        idxs = self._mmr(q_vec, self.doc_matrix, sim, self.k)
        out = []
        for i in idxs:
            row = DATA[i].copy()
            row["score"] = float(sim[0, i])
            out.append(row)
        return out
