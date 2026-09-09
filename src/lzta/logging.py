"""One structured JSON record per line; never log credentials or full requests."""
import json
from decimal import Decimal


def emit(event_type, **fields):
    def encode(value):
        if isinstance(value, Decimal):
            return float(value)
        raise TypeError(type(value).__name__)
    print(json.dumps({"eventType": event_type, **fields}, default=encode, separators=(",", ":")))
