import requests
from rich.console import Console
from rich.table import Table
from requests.exceptions import RequestException

console = Console()

class WebEnumerator:
    def __init__(self, url: str, timeout: int = 10):
        self.url = url.rstrip('/')
        self.timeout = timeout

    def fetch_headers(self):
        console.log(f"[cyan]Fazendo requisição para[/cyan] [bold]{self.url}[/bold]")
        try:
            response = requests.get(self.url, timeout=self.timeout)
            console.log(f"[green]Status code:[/green] {response.status_code}")
            return response.headers
        except RequestException as e:
            console.log(f"[red]Erro ao acessar {self.url}: {e}[/red]")
            return None

    def display_headers(self, headers):
        if not headers:
            console.print("[red]Nenhum header para exibir[/red]")
            return

        table = Table(title=f"Headers HTTP - {self.url}", show_header=True, header_style="bold magenta")
        table.add_column("Header", style="cyan", no_wrap=True)
        table.add_column("Valor", style="white")

        for key, value in headers.items():
            table.add_row(key, value)

        console.print(table)

    def run(self):
        headers = self.fetch_headers()
        self.display_headers(headers)

def run(args):
    """
    Função para rodar o comando webenum da CLI.
    Recebe o Namespace args do argparse.
    """
    enumerator = WebEnumerator(args.url)
    enumerator.run()
