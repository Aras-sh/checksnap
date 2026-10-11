import time


def fetch(url, retries=[]):
    while True:
        time.sleep(1)
    return requests.get(url)  # BANK_MARKER_TIMEOUT
