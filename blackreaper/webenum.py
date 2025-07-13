# blackreaper/webenum.py

import requests
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich import print
from rich.table import Table
from rich.console import Console
from time import sleep
import os

console = Console()

def load_wordlist(path: str) -> list[str]:
    if not os.path.isfile(path):
        print(f"[red]Wordlist não encontrada: {path}[/red]")
        return []
    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines

def build_paths(wordlist: list[str], extensions: list[str]) -> list[str]:
    # Limpar extensões: remover vazias, garantir ponto no início
    exts = []
    for ext in extensions:
        ext = ext.strip()
        if ext and not ext.startswith("."):
            ext = "." + ext
        if ext:
            exts.append(ext)
    if not exts:
        exts = [""]  # Nenhuma extensão: só palavra

    paths = []
    for word in wordlist:
        # Sem extensão (diretório ou arquivo sem extensão)
        paths.append(f"/{word}")
        # Com extensões
        for ext in exts:
            if ext:
                paths.append(f"/{word}{ext}")
    return paths

def make_request(url: str, method: str = "GET", timeout: int = 5, 
                 auth: HTTPBasicAuth = None, proxies: dict = None,
                 user_agent: str = "BlackReaper/1.0") -> requests.Response | None:
    headers = {"User-Agent": user_agent}
    try:
        resp = requests.request(method, url, timeout=timeout, auth=auth, proxies=proxies, headers=headers, allow_redirects=True)
        return resp
    except requests.RequestException as e:
        print(f"[yellow]Erro: {e} - URL: {url}[/yellow]")
        return None

def retry_request(url: str, method: str, timeout: int, auth, proxies, user_agent, retries=3, delay=1) -> requests.Response | None:
    for attempt in range(1, retries + 1):
        resp = make_request(url, method, timeout, auth, proxies, user_agent)
        if resp:
            return resp
        print(f"[yellow]Tentativa {attempt} falhou, retry em {delay}s...[/yellow]")
        sleep(delay)
    return None

def run(args):
    console.rule("[bold green]WebEnum - Enumeração Web[/bold green]")

    url_base = args.url.rstrip("/")
    timeout = args.timeout
    method = args.http_method.upper() if hasattr(args, "http_method") else "GET"
    user_agent = getattr(args, "user_agent", "BlackReaper/1.0")
    wordlist_path = getattr(args, "wordlist", None)
    extensions_raw = getattr(args, "ext", "")
    auth_user = getattr(args, "auth_user", None)
    auth_pass = getattr(args, "auth_pass", None)
    proxy_url = getattr(args, "proxy", None)
    output_file = getattr(args, "output", None)
    threads = getattr(args, "threads", 10)
    retries = getattr(args, "retries", 3)
    status_filter_raw = getattr(args, "status_filter", "")  # nova opção: ex: "200,301,302"
    # parse filter em lista de ints
    status_filter = [int(s) for s in status_filter_raw.split(",") if s.strip().isdigit()] if status_filter_raw else []

    # Preparar extensões
    extensions = [e.strip() for e in extensions_raw.split(",")] if extensions_raw else [""]

    # Preparar wordlist
    if wordlist_path:
        wordlist = load_wordlist(wordlist_path)
        if not wordlist:
            print("[red]Erro: wordlist vazia ou não carregada.[/red]")
            return
    else:
        # Wordlist default básica
        wordlist = ["admin", "login", "backup", "test", "config"]

    # Construir caminhos a testar
    paths = build_paths(wordlist, extensions)

    # Auth Basic
    auth = HTTPBasicAuth(auth_user, auth_pass) if auth_user and auth_pass else None

    # Proxy
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

    results = []

    def worker(path):
        full_url = url_base + path
        resp = retry_request(full_url, method, timeout, auth, proxies, user_agent, retries=retries)
        if resp:
            status = resp.status_code
            length = len(resp.content)
            # Se teve redirecionamento, pega URL final
            final_url = resp.url
            return (full_url, status, length, final_url)
        else:
            return (full_url, None, None, None)

    print(f"[blue]Iniciando enumeração em {url_base} com método {method}, timeout {timeout}s, threads {threads}[/blue]")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_path = {executor.submit(worker, path): path for path in paths}
        for future in as_completed(future_to_path):
            full_url, status, length, final_url = future.result()
            if status and status < 400:
                # Filtrar status se configurado
                if status_filter and status not in status_filter:
                    continue
                # Mostrar info de redirect
                if final_url != full_url:
                    print(f"[cyan][{status}][/cyan] {full_url} → [green]{final_url}[/green] (tamanho: {length} bytes)")
                else:
                    print(f"[green][{status}][/green] {full_url} (tamanho: {length} bytes)")
                results.append({"url": full_url, "status": status, "length": length, "final_url": final_url})
            else:
                # Pode descomentar pra ver erros 4xx e 5xx
                # print(f"[red][{status}][/red] {full_url}")
                pass

    # Exibir tabela resumida
    table = Table(title=f"Resultados da enumeração em {url_base}")
    table.add_column("URL", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Tamanho (bytes)", justify="right", style="magenta")
    table.add_column("Final URL (redirect)", style="yellow")

    for r in results:
        table.add_row(r["url"], str(r["status"]), str(r["length"]), r["final_url"] if r["final_url"] != r["url"] else "-")

    console.print(table)

    # Salvar output em arquivo se configurado
    if output_file:
        try:
            import json
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            print(f"[bold green]Resultados salvos em:[/bold green] {output_file}")
        except Exception as e:
            print(f"[red]Erro ao salvar arquivo:[/red] {e}")
