import yaml

def load_config(raw):
    # SAFE: safe_load
    return yaml.safe_load(raw)
