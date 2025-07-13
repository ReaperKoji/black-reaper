#!/usr/bin/env python3
"""
blackreaper_webenum_test.py
Script simples para testar requisição HTTP com requests e exibir headers e status code.
"""

import sys
import requests
from rich import print
from rich.traceback import install

# Ativa traceback mais legível com rich (só para dev)
install()
#!/usr/bin/env python3
"""
blackreaper_webenum_test.py
Script simples para testar requisição HTTP com requests e exibir headers e status code.
"""

import sys
import requests
from rich import print
from rich.traceback import install

# Ativa traceback mais legível com rich (só para dev)
install()

print("Script iniciado")  # DEBUG: confirma execução do script

def fetch_url(url: str) -> None:
    """
    Faz uma requisição GET e exibe status code e headers.
    
    Args:
        url (str): URL para requisitar.
    """
    print(f"[bold cyan]Iniciando requisição para:[/bold cyan] {url}")
    try:
        response = requests.get(url, timeout=10)
        print(f"[bold yellow]Status code:[/bold yellow] {response.status_code}")
        print("[bold yellow]Headers retornados:[/bold yellow]")
        for key, value in response.headers.items():
            print(f"  [green]{key}[/green]: {value}")
    except requests.RequestException as err:
        print(f"[bold red]Erro na requisição HTTP:[/bold red] {err}")

def main() -> None:
    print("Entrou na main")  # DEBUG: confirma entrada na main
    if len(sys.argv) != 2:
        print("[bold red]Uso correto:[/bold red] python blackreaper_webenum_test.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    fetch_url(url)

if __name__ == "__main__":
    main()

def fetch_url(url: str) -> None:
    """
    Faz uma requisição GET e exibe status code e headers.
    
    Args:
        url (str): URL para requisitar.
    """
    print(f"[bold cyan]Iniciando requisição para:[/bold cyan] {url}")
    try:
        response = requests.get(url, timeout=10)
        print(f"[bold yellow]Status code:[/bold yellow] {response.status_code}")
        print("[bold yellow]Headers retornados:[/bold yellow]")
        for key, value in response.headers.items():
            print(f"  [green]{key}[/green]: {value}")
    except requests.RequestException as err:
        print(f"[bold red]Erro na requisição HTTP:[/bold red] {err}")

def main() -> None:
    if len(sys.argv) != 2:
        print("[bold red]Uso correto:[/bold red] python blackreaper_webenum_test.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    fetch_url(url)

if __name__ == "__main__":
    main()
