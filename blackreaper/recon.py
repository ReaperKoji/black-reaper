# blackreaper/recon.py

import subprocess
from rich import print

def run(args):
    domain = args.domain
    print(f"[cyan][*][/cyan] Iniciando reconhecimento em: [bold]{domain}[/bold]")

    try:
        # WHOIS básico
        print("[yellow][~][/yellow] WHOIS:")
        subprocess.run(["whois", domain], check=True)

        # DNS lookup
        print("[yellow][~][/yellow] DNS Lookup:")
        subprocess.run(["dig", domain, "+short"], check=True)

        # Subdomain brute básico (exemplo simples com 'www')
        print("[yellow][~][/yellow] Teste de subdomínio (www):")
        subprocess.run(["dig", f"www.{domain}", "+short"], check=True)

    except subprocess.CalledProcessError as e:
        print(f"[red][!][/red] Erro ao executar: {e}")

