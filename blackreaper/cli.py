import socket
import requests
import dns.resolver
import dns.query
import dns.zone
import whois
import json
import datetime
import argparse
import logging
from typing import Optional, List, Dict, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import os
import sys

console = Console()

# Configuração básica do logger
logger = logging.getLogger("blackreaper.recon")
logger.setLevel(logging.DEBUG)  # DEBUG para máximo detalhe, filtrar em handler se quiser

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)  # Mostra INFO e acima no console
formatter = logging.Formatter('[%(levelname)s] %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

COMMON_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080, 8443
]

SUBDOMAIN_WORDLIST: List[str] = [
    "www", "mail", "ftp", "webmail", "ns1", "ns2",
    "smtp", "vpn", "m", "dev", "test", "portal", "secure"
]


def json_serial(obj: object) -> str:
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError(f"Tipo {type(obj)} não serializável")


def scan_port(host: str, port: int, timeout: int = 1) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            logger.debug(f"Porta {port} aberta em {host}")
            return True
    except Exception:
        logger.debug(f"Porta {port} fechada em {host}")
        return False


def banner_grab(host: str, port: int, timeout: int = 2) -> Optional[str]:
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(b"\r\n")
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner if banner else None
    except Exception:
        return None


def subdomain_enum(domain: str, wordlist: List[str] = SUBDOMAIN_WORDLIST) -> List[str]:
    found: List[str] = []
    console.print(f"[blue]Iniciando enumeração de subdomínios em {domain}[/blue]")
    resolver = dns.resolver.Resolver()
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(subdomain, 'A')
            ips = ", ".join([rdata.to_text() for rdata in answers])
            console.print(f"[green]+ {subdomain} → {ips}[/green]")
            found.append(subdomain)
        except Exception:
            continue
    return found


def try_zone_transfer(domain: str) -> Optional[Dict[str, Union[str, List[str]]]]:
    console.print(f"[blue]Tentando Zone Transfer para {domain}[/blue]")
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
    except Exception as e:
        logger.error(f"Erro ao obter NS records para {domain}: {e}")
        return None

    for ns in ns_records:
        ns_host = ns.to_text()
        console.print(f"[yellow]Tentando transferir zona via {ns_host}[/yellow]")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
            if zone:
                records: List[str] = []
                for name, node in zone.nodes.items():
                    record_name = name.to_text()
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append(f"{record_name} {rdataset.rdtype} {rdata}")
                console.print(f"[green]Zone transfer bem-sucedida! Registros: {len(records)}[/green]")
                return {"ns": ns_host, "records": records}
        except Exception as e:
            logger.warning(f"Zone transfer falhou via {ns_host} para {domain}: {e}")
    return None


def whois_info(domain: str) -> Optional[Dict]:
    console.print(f"[blue]Consultando WHOIS de {domain}[/blue]")
    try:
        w = whois.whois(domain)
        if w is None:
            return None
        if isinstance(w, dict):
            return w
        if hasattr(w, "to_dict") and callable(w.to_dict):
            return w.to_dict()
        return dict(w)
    except Exception as e:
        logger.error(f"Erro WHOIS para {domain}: {e}")
        return None


def web_fingerprint(domain: str) -> Dict[str, Union[str, int]]:
    console.print(f"[blue]Realizando fingerprint HTTP em {domain}[/blue]")
    url = f"http://{domain}"
    headers_info: Dict[str, Union[str, int]] = {}
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        headers_info["status_code"] = resp.status_code
        headers_info["server"] = resp.headers.get("Server", "N/A")
        headers_info["x_powered_by"] = resp.headers.get("X-Powered-By", "N/A")
        headers_info["content_type"] = resp.headers.get("Content-Type", "N/A")
        headers_info["final_url"] = resp.url
    except Exception as e:
        logger.error(f"Erro fingerprint HTTP para {domain}: {e}")
    return headers_info


def recon_domain(domain: str, ports: List[int], timeout: int) -> Dict:
    """
    Recon completo para um domínio, retorna dict com todos os dados.
    """
    console.rule(f"[bold green]Recon - Scan completo para {domain}[/bold green]")

    open_ports: List[Dict[str, Union[int, str]]] = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(scan_port, domain, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                banner = banner_grab(domain, port, timeout)
                open_ports.append({"port": port, "banner": banner or "N/A"})

    table = Table(title=f"Portas abertas em {domain}")
    table.add_column("Porta", style="cyan", no_wrap=True)
    table.add_column("Banner", style="magenta")
    for item in sorted(open_ports, key=lambda x: x["port"]):
        table.add_row(str(item["port"]), item["banner"])
    console.print(table)

    subdomains = subdomain_enum(domain)
    zone_data = try_zone_transfer(domain)
    whois_data = whois_info(domain)
    fp = web_fingerprint(domain)

    if whois_data:
        whois_json = json.dumps(whois_data, indent=2, ensure_ascii=False, default=json_serial)
        console.print(Panel(Text(whois_json, overflow="fold"), title="WHOIS info", subtitle=domain))
    else:
        console.print("[yellow]Nenhuma informação WHOIS disponível[/yellow]")

    fp_table = Table(title="Fingerprint HTTP")
    fp_table.add_column("Campo", style="cyan")
    fp_table.add_column("Valor", style="magenta")
    for k, v in fp.items():
        fp_table.add_row(k, str(v))
    console.print(fp_table)

    return {
        "domain": domain,
        "open_ports": open_ports,
        "subdomains": subdomains,
        "zone_transfer": zone_data,
        "whois": whois_data,
        "http_fingerprint": fp,
    }


def main():
    parser = argparse.ArgumentParser(
        description="BlackReaper Recon: ferramenta profissional de reconhecimento de rede e domínio"
    )
    parser.add_argument(
        "-d", "--domain", help="Domínio alvo para recon", type=str, nargs='*'
    )
    parser.add_argument(
        "-f", "--file", help="Arquivo com lista de domínios (um por linha)", type=str
    )
    parser.add_argument(
        "-o", "--output", help="Arquivo para salvar resultado JSON", type=str, default=None
    )
    parser.add_argument(
        "-t", "--threads", help="Número de threads para scan de portas", type=int, default=30
    )
    parser.add_argument(
        "--timeout", help="Timeout em segundos para conexões", type=int, default=1
    )
    args = parser.parse_args()

    if not args.domain and not args.file:
        console.print("[red]Erro: informe pelo menos um domínio (-d) ou arquivo (-f)[/red]")
        parser.print_help()
        sys.exit(1)

    # Carregar domínios da CLI
    domains: List[str] = []
    if args.domain:
        domains.extend(args.domain)
    if args.file:
        if not os.path.isfile(args.file):
            console.print(f"[red]Arquivo não encontrado: {args.file}[/red]")
            sys.exit(1)
        with open(args.file, 'r', encoding='utf-8') as f:
            file_domains = [line.strip() for line in f if line.strip()]
            domains.extend(file_domains)

    # Remove duplicados e limpa espaços
    domains = list(set([d.strip() for d in domains if d.strip()]))

    results = {}
    # Ajustar máximo threads para escaneamento de portas via argumento
    max_threads = max(1, min(args.threads, 100))

    # Recon em paralelo para múltiplos domínios
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(recon_domain, domain, COMMON_PORTS, args.timeout): domain for domain in domains}
        for future in as_completed(futures):
            domain = futures[future]
            try:
                result = future.result()
                results[domain] = result
            except Exception as e:
                logger.error(f"Erro no recon para {domain}: {e}")

    # Salvar resultados
    output_path = args.output
    if output_path is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"recon_report_{timestamp}.json"
        logger.info(f"Nenhum arquivo de saída informado, salvando como {output_path}")

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=json_serial)
        console.print(f"[bold green]Relatório salvo em {output_path}[/bold green]")
    except Exception as e:
        logger.error(f"Erro ao salvar relatório JSON: {e}")


if __name__ == "__main__":
    main()
