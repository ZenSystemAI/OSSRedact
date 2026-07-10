"""Regression guard: the neural tiers must default to max_len 512, not 256.

The prod gate chunks at 600 chars; a token-dense 600-char chunk reaches ~300 tokens, so max_len 256 silently
truncated the chunk tail and dropped PII there (measured: password recall 0.85 -> 0.99 going 256 -> 512).
This guards against a silent revert. Torch-free (only inspects the signature default). Run with the gate suite.
"""
import sys, os, inspect
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from privacy_gate import GPUTier, NPUTier  # noqa: E402


def test_gpu_tier_max_len_default_is_512():
    assert inspect.signature(GPUTier.__init__).parameters['max_len'].default == 512


def test_npu_tier_max_len_default_is_512():
    assert inspect.signature(NPUTier.__init__).parameters['max_len'].default == 512
