"""1D-CNN for text classification."""
from __future__ import annotations

import torch
import torch.nn as nn


class TextCNN(nn.Module):
    def __init__(self, vocab_size: int, embed_dim: int = 128, num_filters: int = 100, filter_sizes: list = None, dropout: float = 0.3):
        super().__init__()
        if filter_sizes is None:
            filter_sizes = [3, 4, 5]
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.convs = nn.ModuleList([nn.Conv1d(embed_dim, num_filters, k) for k in filter_sizes])
        self.fc = nn.Linear(len(filter_sizes) * num_filters, 1)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        emb = self.embedding(x).permute(0, 2, 1)  # [batch, embed, seq]
        conved = [torch.relu(conv(emb)) for conv in self.convs]
        pooled = [torch.max(c, dim=2)[0] for c in conved]
        cat = torch.cat(pooled, dim=1)
        return torch.sigmoid(self.fc(self.dropout(cat))).squeeze(1)
