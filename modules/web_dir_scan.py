from utils import validation, runner, formatter
import os
import urllib.request
import urllib.error

def check_dir():
    target = input("Enter target domain or URL").split()
    for url in target:
        try:
            response = urllib.request.urlopen(url)
            print(f"Directory found: {url}")
        except urllib.error.HTTPError as e:
            print(f"Directory not found: {url}")
            