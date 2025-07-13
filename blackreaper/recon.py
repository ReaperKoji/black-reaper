import socket
import requests
import dns.resolver
import dns.query
import dns.zone
import whois
import json
import datetime
import csv
from typing import Optional, List, Dict, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import argparse

console = Console()

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
    """
    JSON serializer para tipos não nativos como datetime.date/datetime.datetime.
    """
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError(f"Tipo {type(obj)} não serializável")

def scan_port(host: str, port: int, timeout: int = 1) -> bool:
    """
    Tenta conexão TCP simples para identificar porta aberta.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def banner_grab(host: str, port: int, timeout: int = 2) -> Optional[str]:
    """
    Tenta receber banner via TCP para identificar serviço.
    """
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
    """
    Enumeração simples de subdomínios via DNS A record.
    """
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
            continue  # Falha na resolução é comum, ignorar silenciosamente
    return found

def try_zone_transfer(domain: str) -> Optional[Dict[str, Union[str, List[str]]]]:
    """
    Tenta zone transfer (AXFR) para descobrir registros DNS.
    """
    console.print(f"[blue]Tentando Zone Transfer para {domain}[/blue]")
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
    except Exception as e:
        console.print(f"[red]Erro ao obter NS records: {e}[/red]")
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
            console.print(f"[red]Zone transfer falhou via {ns_host}: {e}[/red]")
    return None

def whois_info(domain: str) -> Optional[Dict]:
    """
    Consulta dados WHOIS do domínio, com normalização para dict.
    """
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
        console.print(f"[red]Erro WHOIS: {e}[/red]")
        return None

def web_fingerprint(domain: str) -> Dict[str, Union[str, int]]:
    """
    Detecta tecnologias web via headers HTTP.
    """
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
        console.print(f"[red]Erro fingerprint HTTP: {e}[/red]")
    return headers_info

def save_csv(results: Dict, filename: str) -> None:
    """
    Salva os dados do relatório em CSV.
    """
    try:
        with open(filename, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            
            writer.writerow(["Open Ports"])
            writer.writerow(["Port", "Banner"])
            for port in results.get("open_ports", []):
                writer.writerow([port["port"], port["banner"]])
            
            writer.writerow([])
            writer.writerow(["Subdomains"])
            for sub in results.get("subdomains", []):
                writer.writerow([sub])
            
            writer.writerow([])
            writer.writerow(["Zone Transfer"])
            zone = results.get("zone_transfer")
            if zone:
                writer.writerow([f"NS: {zone.get('ns', '')}"])
                writer.writerow(["Records"])
                for record in zone.get("records", []):
                    writer.writerow([record])
            else:
                writer.writerow(["No zone transfer data"])
            
            writer.writerow([])
            writer.writerow(["WHOIS Data"])
            whois_data = results.get("whois")
            if whois_data:
                for key, value in whois_data.items():
                    writer.writerow([key, value])
            else:
                writer.writerow(["No WHOIS data"])
            
            writer.writerow([])
            writer.writerow(["HTTP Fingerprint"])
            fp = results.get("http_fingerprint", {})
            for key, value in fp.items():
                writer.writerow([key, value])
        console.print(f"[bold green]Relatório CSV salvo em {filename}[/bold green]")
    except Exception as e:
        console.print(f"[red]Erro ao salvar CSV: {e}[/red]")

def run(args) -> None:
    domain = args.domain.strip()
    console.rule(f"[bold green]Recon - Scan completo para {domain}[/bold green]")

    console.print(f"[bold]Escaneando portas comuns em {domain}...[/bold]")
    open_ports: List[Dict[str, Union[int, str]]] = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(scan_port, domain, port): port for port in COMMON_PORTS}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                banner = banner_grab(domain, port)
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

    output_path_json: Optional[str] = getattr(args, "output", None)
    if output_path_json:
        results = {
            "domain": domain,
            "open_ports": open_ports,
            "subdomains": subdomains,
            "zone_transfer": zone_data,
            "whois": whois_data,
            "http_fingerprint": fp,
        }
        try:
            with open(output_path_json, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=json_serial)
            console.print(f"[bold green]Relatório JSON salvo em {output_path_json}[/bold green]")
        except Exception as e:
            console.print(f"[red]Erro ao salvar relatório JSON: {e}[/red]")

        # Também salva CSV automático com o mesmo nome, só extensão diferente
        csv_path = output_path_json.rsplit(".", 1)[0] + ".csv"
        save_csv(results, csv_path)


def main():
    parser = argparse.ArgumentParser(description="Recon Tool - scanner completo de domínio")
    parser.add_argument("-d", "--domain", required=True, help="Domínio para escanear")
    parser.add_argument("-o", "--output", help="Caminho para salvar relatório JSON/CSV (opcional, extensão JSON)")
    args = parser.parse_args()
    run(args)

if __name__ == "__main__":
    main()
