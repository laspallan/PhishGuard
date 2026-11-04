"""Inference: registry reading, parity check, and no placeholder verdicts."""

import asyncio
import json

import pytest

from phishguard.services.features.extractor import feature_code_hash
from phishguard.services.inference.feature_parity import check_parity
from phishguard.services.inference.model_loader import ModelLoader
from phishguard.services.inference.service import InferenceService, ModelNotLoadedError


def test_registry_written_by_ml_is_a_list(tmp_path):
    (tmp_path / "registry.json").write_text(json.dumps([{"version": "url-all-xgboost-abc"}]))
    loader = ModelLoader(tmp_path)
    assert loader.load_registry() == [{"version": "url-all-xgboost-abc"}]
    assert loader.loaded


def test_missing_or_broken_registry_means_no_models(tmp_path):
    assert ModelLoader(tmp_path).load_registry() == []
    (tmp_path / "registry.json").write_text("{not json")
    assert ModelLoader(tmp_path).load_registry() == []


def test_scans_refuse_instead_of_inventing_a_verdict(tmp_path):
    service = InferenceService(ModelLoader(tmp_path))
    with pytest.raises(ModelNotLoadedError):
        asyncio.run(service.scan_url("http://paypal-login-verify.xyz/secure"))
    with pytest.raises(ModelNotLoadedError):
        asyncio.run(service.scan_email("Subject: verify\n\nclick here"))


def test_parity_flags_models_built_with_other_feature_code():
    entries = [
        {"version": "ok", "feature_code_hash": feature_code_hash()},
        {"version": "old", "feature_code_hash": "0" * 64},
    ]
    result = check_parity(entries)
    assert result["stale_models"] == ["old"] and result["ok"] is False
    assert check_parity(entries[:1])["ok"] is True
