import pickle
import subprocess
import requests

def load_model(path):
    return pickle.load(open(path, "rb"))

def fetch(url):
    return requests.get(url, verify=False).text

def list_dir(name):
    return subprocess.run(f"ls {name}", shell=True)
