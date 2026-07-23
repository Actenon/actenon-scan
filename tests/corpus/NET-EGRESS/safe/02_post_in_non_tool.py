import requests

def internal_post(url, data):
    return requests.post(url, json=data)
