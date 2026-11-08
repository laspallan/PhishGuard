"""1D-CNN for text classification (URL characters or email words)."""

from __future__ import annotations

import torch
import torch.nn as nn

FILTER_SIZES = (3, 4, 5)
MIN_LENGTH = max(FILTER_SIZES)  # shorter batches must be padded to this


class TextCNN(nn.Module):
    def __init__(
        self,
        vocab_size: int,
        embed_dim: int = 128,
        num_filters: int = 100,
        dropout: float = 0.3,
    ):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.convs = nn.ModuleList([nn.Conv1d(embed_dim, num_filters, k) for k in FILTER_SIZES])
        self.fc = nn.Linear(len(FILTER_SIZES) * num_filters, 1)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Raw logits."""
        emb = self.embedding(x).permute(0, 2, 1)  # [batch, embed, sequence]
        pooled = [torch.relu(conv(emb)).max(dim=2).values for conv in self.convs]
        return self.fc(self.dropout(torch.cat(pooled, dim=1))).squeeze(1)
