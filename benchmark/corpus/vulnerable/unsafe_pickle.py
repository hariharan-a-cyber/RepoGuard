import pickle

def deserialize(blob):
    # VULN: pickle.loads on untrusted data
    return pickle.loads(blob)
