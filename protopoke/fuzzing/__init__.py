"""
ProtoPoke fuzzing subsystem.

Entry points:
    FuzzerEngine  — run campaigns against a target server
    FuzzCampaign  — campaign configuration and results
    FuzzResult    — outcome of one fuzzing iteration

Mutators (protopoke.fuzzing.mutators):
    Raw (protocol-unaware):
        BitFlipMutator, ByteInsertMutator, ByteDeleteMutator,
        KnownBadMutator, RadamsaMutator, ChainMutator

    Protocol-aware (require DefinitionBasedEncoder):
        FieldBoundaryMutator, FieldOverflowMutator,
        NullByteMutator, LengthMangleMutator

Quick start:
    from protopoke.fuzzing import FuzzCampaign, FuzzerEngine
    from protopoke.fuzzing.mutators import BitFlipMutator, KnownBadMutator

    mutators = [BitFlipMutator(), KnownBadMutator()]
    campaign = FuzzCampaign.create(
        session_id="<captured-session-id>",
        mutators=mutators,
        iterations=100,
    )
    engine = FuzzerEngine(
        forge_engine=api.forge_engine,
        session_registry=api.session_registry,
        decoder=api._decoder,
    )
    campaign = await engine.run_campaign(campaign, mutators)
    print(f"Interesting: {len(campaign.interesting_results)}")
"""

from .engine import FuzzerEngine
from .models import CampaignStatus, FuzzCampaign, FuzzResult

__all__ = [
    "FuzzerEngine",
    "FuzzCampaign",
    "FuzzResult",
    "CampaignStatus",
]
