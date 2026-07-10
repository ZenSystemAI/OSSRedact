"""B13 regression guard (appliance copy): the neural tiers must default to max_len 512, not 256.

The appliance GPUTier is the tier that will run on the dedicated GPU appliance box (the spare 3090s). Its
sibling NPUTier/OVTier already use 512; a 256 default would silently truncate the tail of a token-dense
600-char chunk and drop PII there (measured on the gate: password recall 0.85 -> 0.99 going 256 -> 512).
This guards the appliance copy against the same silent revert the gate copy is guarded against in
gate/tests/test_maxlen.py. Torch-free (only inspects the signature default). Run with the appliance suite.
"""
import sys, os, inspect
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from privacy_gate import GPUTier, NPUTier  # noqa: E402


def test_gpu_tier_max_len_default_is_512():
    assert inspect.signature(GPUTier.__init__).parameters['max_len'].default == 512


def test_npu_tier_max_len_default_is_512():
    assert inspect.signature(NPUTier.__init__).parameters['max_len'].default == 512
