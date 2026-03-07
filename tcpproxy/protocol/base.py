"""
Protocol decoder and encoder abstract base classes.

The protocol layer sits above the framing layer:
    raw bytes → [Framer] → Frame → [ProtocolDecoder] → ParsedMessage
    ParsedMessage → [ProtocolEncoder] → bytes → [wire]

Why keep this separate from framing:
    Framing finds message *boundaries* in the byte stream.
    Decoding interprets the *content* of those messages.
    These are independent concerns. You can frame without decoding (capture
    with unknown protocol), and you can swap decoders without changing how
    the stream is split.

Implementing a custom protocol decoder:
    1. Subclass ProtocolDecoder.
    2. Implement protocol_name and decode().
    3. If decoding fails, return a ParsedMessage with an 'error' field rather
       than raising — this keeps the proxy running even on malformed traffic.
    4. Register it in a decoder registry or pass it to the API directly.

Future integration points:
    - A declarative DSL (e.g. YAML/JSON describing field layouts) could
      auto-generate ProtocolDecoder subclasses.
    - Protobuf, Thrift, or Kaitai Struct schemas could be compiled to decoders.
    - A plugin system could load decoders from external Python modules.
    - The UI can call decoder.decode(frame) to get structured fields for display.

Fuzzing:
    A fuzzer can take a ParsedMessage, mutate fields, call encoder.encode(),
    and replay the modified bytes — all without touching the transport layer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Frame, ParsedField, ParsedMessage


class ProtocolDecoder(ABC):
    """
    Decodes a Frame's raw bytes into a structured ParsedMessage.

    Implement one of these per protocol you want to understand.

    Decoder state:
        Most decoders are stateless (decode each frame independently).
        Stateful protocols (e.g. ones with session context in later messages)
        may need to maintain state between calls. Use instance variables for this;
        create one decoder instance per session direction.
    """

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """
        Human-readable protocol identifier.

        Examples: 'HTTP/1.1', 'Redis', 'MQTT', 'DNS', 'MyCustomProtocol'.
        Used in ParsedMessage.protocol_name and UI display.
        """
        ...

    @abstractmethod
    def decode(self, frame: Frame) -> ParsedMessage:
        """
        Decode a Frame into a structured ParsedMessage.

        Contract:
            - Always return a ParsedMessage (never raise on bad input).
            - If parsing fails, return a ParsedMessage with an 'error' key
              in fields and the raw bytes as a fallback.
            - Keep the original Frame in the returned ParsedMessage (always
              accessible via message.frame.raw_bytes).

        Args:
            frame: The Frame to decode. frame.raw_bytes contains the data.

        Returns:
            ParsedMessage with protocol-specific structured fields.
        """
        ...

    def can_decode(self, frame: Frame) -> bool:
        """
        Return True if this decoder can handle the given frame.

        Override to add protocol detection logic (e.g. check magic bytes).
        The default assumes this decoder can handle any frame.

        Used by a decoder registry to auto-select the right decoder.
        """
        return True


class ProtocolEncoder(ABC):
    """
    Encodes a ParsedMessage back to raw bytes.

    The inverse of ProtocolDecoder. Needed for:
        - Intercept+modify: decode, mutate fields, re-encode, forward
        - Replay with modifications
        - Fuzzing: mutate fields, encode, send

    Pairing:
        Decoders and encoders for the same protocol should be paired.
        A decode/encode round-trip should produce equivalent bytes (not
        necessarily byte-identical if there's optional padding, but
        functionally equivalent).
    """

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Protocol this encoder handles."""
        ...

    @abstractmethod
    def encode(self, message: ParsedMessage) -> bytes:
        """
        Encode a ParsedMessage back to bytes.

        Args:
            message: The parsed message to encode. Modify message.fields
                     before calling encode() to produce a modified message.

        Returns:
            Bytes ready to send on the wire.
        """
        ...


class PassthroughDecoder(ProtocolDecoder):
    """
    No-op decoder: returns the raw bytes as-is in a ParsedMessage.

    Useful as a placeholder when you don't yet have a real decoder.
    The parsed view just exposes the hex dump and byte length.
    """

    @property
    def protocol_name(self) -> str:
        return "raw"

    def decode(self, frame: Frame) -> ParsedMessage:
        raw = frame.raw_bytes
        fields = [
            ParsedField(
                name="raw",
                value=raw,
                raw_bytes=raw,
                offset=0,
                size=len(raw),
                display_hint="hex",
                display_value=raw.hex(" ") if raw else "",
            ),
        ]
        return ParsedMessage.from_frame(
            frame=frame,
            protocol_name=self.protocol_name,
            message_type="raw",
            fields=fields,
            display_name=f"[{len(raw)} bytes]",
        )
