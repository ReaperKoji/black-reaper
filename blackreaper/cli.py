# blackreaper/cli.py

import argparse
from rich import print
from blackreaper import recon, webenum, rsh, privesc, utils

def main():
    utils.print_banner()

    parser = argparse.ArgumentParser(
        prog="blackreaper",
        description="BlackReaper CLI - Suite Hacker Terminal"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando: Recon
    recon_parser = subparsers.add_parser(
        "recon",
        help="Reconhecimento de domínio e serviços"
    )
    recon_parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Domínio alvo"
    )
    recon_parser.set_defaults(func=recon.run)

    # Subcomando: WebEnum
    web_parser = subparsers.add_parser(
        "webenum",
        help="Enumeração de diretórios e tecnologias web"
    )
    web_parser.add_argument(
        "-u", "--url",
        required=True,
        help="URL alvo"
    )
    web_parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout da requisição HTTP"
    )
    web_parser.add_argument(
        "--user-agent",
        default="BlackReaper/1.0",
        help="User-Agent customizado"
    )
    web_parser.add_argument(
        "--wordlist",
        help="Arquivo de wordlist para fuzzing"
    )
    web_parser.add_argument(
        "--ext",
        default="",
        help="Extensões a testar, separadas por vírgula, ex: php,html,bak"
    )
    web_parser.add_argument(
        "--auth-user",
        help="Usuário para Basic Auth"
    )
    web_parser.add_argument(
        "--auth-pass",
        help="Senha para Basic Auth"
    )
    web_parser.add_argument(
        "--proxy",
        help="Proxy HTTP/HTTPS para usar, ex: http://127.0.0.1:8080"
    )
    web_parser.add_argument(
        "--output",
        help="Arquivo para salvar resultados (JSON)"
    )
    web_parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Número de threads para fuzzing paralelo"
    )
    web_parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Número de tentativas em caso de falha"
    )
    web_parser.add_argument(
        "--http-method",
        default="GET",
        help="Método HTTP a usar (GET, HEAD, OPTIONS, etc.)"
    )
    web_parser.add_argument(
        "--status-filter",
        default="",
        help="Filtrar status HTTP separados por vírgula, ex: 200,301,302"
    )
    web_parser.set_defaults(func=webenum.run)

    # Subcomando: Reverse Shell
    rsh_parser = subparsers.add_parser(
        "rsh",
        help="Gerador de payloads e handler de reverse shell"
    )
    rsh_parser.add_argument(
        "--payload",
        choices=["php", "bash", "python"],
        required=True
    )
    rsh_parser.add_argument(
        "--lhost",
        required=True
    )
    rsh_parser.add_argument(
        "--lport",
        required=True
    )
    rsh_parser.set_defaults(func=rsh.run)

    # Subcomando: PrivEsc
    privesc_parser = subparsers.add_parser(
        "privesc",
        help="Pós-exploração e escalada de privilégios"
    )
    privesc_parser.set_defaults(func=privesc.run)

    # Parse e execução
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
