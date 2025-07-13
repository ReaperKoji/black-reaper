# blackreaper/webenum.py

import requests
from rich import print
from rich.table import Table
from rich.console import Console
import time

console = Console()

DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "config", "backup", "uploads",
    "index.php", "index.html", "robots.txt", "sitemap.xml"
]

def fetch_url(url, headers=None, timeout=5):
    try:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        return response.status_code, response.headers, response.text
    except requests.RequestException as e:
        console.log(f"[red]Erro na requisição {url}: {e}[/red]")
        return None, None, None

def fuzz_directories(base_url, wordlist, headers, timeout):
    results = []
    for path in wordlist:
        url = base_url.rstrip("/") + "/" + path
        console.log(f"Testando: {url}")
        status, hdrs, _ = fetch_url(url, headers=headers, timeout=timeout)
        if status and status in [200, 301, 302, 401, 403]:
            results.append((url, status))
        time.sleep(0.2)  # evitar flood muito rápido
    return results

def fingerprint_tech(headers, content):
    techs = []
    server = headers.get("Server", "") if headers else ""
    powered_by = headers.get("X-Powered-By", "") if headers else ""
    if server:
        techs.append(f"Server: {server}")
    if powered_by:
        techs.append(f"X-Powered-By: {powered_by}")

    # fingerprint simples no conteúdo
    if "wp-content" in content.lower():
        techs.append("WordPress detected")
    if "<script src=\"https://cdn.jsdelivr.net/npm/vue" in content.lower():
        techs.append("Vue.js detected")
    return techs

def run(args):
    console.rule("[bold green]BlackReaper WebEnum[/bold green]")
    url = args.url
    timeout = getattr(args, "timeout", 5)
    user_agent = getattr(args, "user_agent", "BlackReaper/1.0")
    headers = {"User-Agent": user_agent}

    console.log(f"Fazendo requisição para {url}")
    status, hdrs, content = fetch_url(url, headers=headers, timeout=timeout)

    if status is None:
        console.print(f"[red]Falha ao acessar {url}[/red]")
        return

    console.print(f"[bold yellow]Status code:[/bold yellow] {status}")

    # Mostrar headers em tabela
    table = Table(title=f"Headers HTTP - {url}")
    table.add_column("Header")
    table.add_column("Valor")
    for k, v in hdrs.items():
        table.add_row(k, v)
    console.print(table)

    # Fingerprint de tecnologia
    techs = fingerprint_tech(hdrs, content)
    if techs:
        console.print("[bold cyan]Fingerprint de tecnologias detectadas:[/bold cyan]")
        for t in techs:
            console.print(f" - {t}")
    else:
        console.print("[bold cyan]Nenhuma tecnologia detectada.[/bold cyan]")

    # Enumeração de diretórios via wordlist
    console.print("[bold green]Iniciando enumeração de diretórios básica[/bold green]")
    wordlist = DEFAULT_WORDLIST
    results = fuzz_directories(url, wordlist, headers, timeout)

    if results:
        table2 = Table(title="Diretórios encontrados")
        table2.add_column("URL")
        table2.add_column("Status Code")
        for url_found, code in results:
            table2.add_row(url_found, str(code))
        console.print(table2)
    else:
        console.print("[yellow]Nenhum diretório encontrado com os códigos esperados.[/yellow]")
