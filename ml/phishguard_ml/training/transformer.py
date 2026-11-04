"""DistilBERT transformer training script for Colab/local."""

from __future__ import annotations


class DistilBERTTrainer:
    def __init__(self, model_name: str = "distilbert-base-uncased"):
        self.model_name = model_name

    def train(self, train_data, val_data):
        # Stub - implementation for Colab/local
        raise NotImplementedError("Use transformers/torch on GPU environment")
