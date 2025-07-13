# blackreaper/utils.py

from rich import print

def print_banner():
    try:
        with open("banner.txt", "r", encoding="utf-8") as f:
            banner = f.read()
    except UnicodeDecodeError:
        with open("banner.txt", "r", encoding="cp1252", errors="ignore") as f:
            banner = f.read()
    print(banner)
