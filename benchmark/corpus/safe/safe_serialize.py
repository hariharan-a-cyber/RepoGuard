import json

def deserialize(blob):
    # SAFE: json instead of pickle
    return json.loads(blob)
