"""
Line-based framer.

A convenience framer that splits the byte stream on newline (b'\\n').
Handles both Unix (\\n) and Windows (\\r\\n) line endings transparently:
frames for \\r\\n-terminated lines will include the trailing \\r\\n, and
frames for \\n-terminated lines will include just the \\n.

This is equivalent to using DelimiterFramer with delimiter=b'\\n' but
is available under the name "line" so it can be selected directly in
the UI without having to manually configure framer_kwargs.
"""

from __future__ import annotations

from ..models import Direction
from .delimiter import DelimiterFramer


class LineFramer(DelimiterFramer):
    """
    Splits the byte stream on newline (b'\\n').

    Handles both \\n and \\r\\n line endings.  The delimiter (\\n, or \\r\\n
    for Windows-style lines) is included in the emitted frame by default.

    Args:
        session_id:        Session this framer belongs to.
        direction:         Direction of the stream.
        include_delimiter: If True, the \\n is included at the end of each
                           frame. Default: True.
        max_frame_size:    Safety limit in bytes. Default: 1 MB.
    """

    def __init__(
        self,
        session_id:        str,
        direction:         Direction,
        include_delimiter: bool = True,
        max_frame_size:    int  = 1024 * 1024,
    ) -> None:
        super().__init__(
            session_id=session_id,
            direction=direction,
            delimiter=b'\n',
            include_delimiter=include_delimiter,
            max_frame_size=max_frame_size,
        )

    @property
    def name(self) -> str:
        return "line"
