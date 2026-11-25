"""Typed errors for the FMagenticL client.

Added 2026-11-25 (F2) so that "I cannot verify my own data" is a visible, catchable event
instead of a silent fall-through to the network.
"""


class FMagenticLIntegrityError(RuntimeError):
    """Local signed data failed verification and policy forbids reaching the network.

    Raised by ``FMagenticLClient`` when the bundled snapshot is present but does not verify
    against the pinned public key, while air-gap mode is on. Air-gap mode is on by default;
    set ``FMAGENTICL_AIR_GAP=0`` (or pass ``air_gap=False``) to restore edge fallback.
    """


__all__ = ["FMagenticLIntegrityError"]
