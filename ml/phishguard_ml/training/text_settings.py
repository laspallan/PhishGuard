"""Token settings of the LSTM and CNN, without PyTorch: the Colab export runs in backend/.venv."""

import hashlib
from dataclasses import dataclass

from phishguard.services.text_input import text_code_hash


@dataclass(frozen=True)
class Tokens:
    kind: str  # "char" or "word"
    max_length: int
    max_vocabulary: int


# 99% of development URLs have at most 194 characters; emails are cut to their first 400 words.
TOKENS = {
    "url": Tokens("char", 200, 256),
    "email": Tokens("word", 400, 30_000),
}


def code_hash(modality: str) -> str:
    """The text selection and the tokeniser settings: what a text model depends on."""
    joined = f"{text_code_hash()}|{TOKENS[modality]}"
    return hashlib.sha256(joined.encode()).hexdigest()
