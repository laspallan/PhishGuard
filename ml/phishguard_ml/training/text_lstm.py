"""LSTM for text classification (URL/email text)."""
from __future__ import annotations

import torch
import torch.nn as nn


class TextLSTM(nn.Module):
    def __init__(self, vocab_size: int, embed_dim: int = 128, hidden_dim: int = 256, num_layers: int = 2, dropout: float = 0.3):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, num_layers=num_layers, batch_first=True, dropout=dropout, bidirectional=True)
        self.fc = nn.Linear(hidden_dim * 2, 1)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        emb = self.embedding(x)
        _, (h_n, _) = self.lstm(emb)
        # Concatenate forward and backward hidden states
        h = torch.cat((h_n[-2], h_n[-1]), dim=1)
        return torch.sigmoid(self.fc(self.dropout(h))).squeeze(1)
