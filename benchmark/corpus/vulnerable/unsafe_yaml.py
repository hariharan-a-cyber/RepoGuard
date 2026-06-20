import yaml

def load_config(raw):
    # VULN: yaml.load without SafeLoader
    return yaml.load(raw)
