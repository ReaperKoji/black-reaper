# blackreaper/cli.py

import argparse
from rich import print
from blackreaper import recon, webenum, rsh, privesc, utils

def main():
    utils.print_banner()

    parser = argparse.ArgumentParser(prog="blackreaper", description="BlackReaper CLI - Suite Hacker Terminal")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando: Recon
    recon_parser = subparsers.add_parser("recon", help="Reconhecimento de domínio e serviços")
    recon_parser.add_argument("-d", "--domain", required=True, help="Domínio alvo")
    recon_parser.set_defaults(func=recon.run)

    # Subcomando: WebEnum
    web_parser = subparsers.add_parser("webenum", help="Enumeração de diretórios e tecnologias web")
    web_parser.add_argument("-u", "--url", required=True, help="URL alvo")
    web_parser.set_defaults(func=webenum.run)

    # Subcomando: Reverse Shell
    rsh_parser = subparsers.add_parser("rsh", help="Gerador de payloads e handler de reverse shell")
    rsh_parser.add_argument("--payload", choices=["php", "bash", "python"], required=True)
    rsh_parser.add_argument("--lhost", required=True)
    rsh_parser.add_argument("--lport", required=True)
    rsh_parser.set_defaults(func=rsh.run)

    # Subcomando: PrivEsc
    privesc_parser = subparsers.add_parser("privesc", help="Pós-exploração e escalada de privilégios")
    privesc_parser.set_defaults(func=privesc.run)

    # Parse e execução
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
