#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import datetime
from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich.rule import Rule
import argparse
import shutil

console = Console()

def json_serial(obj: object) -> str:
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError(f"Tipo {type(obj)} não serializável")

def run_cmd(cmd: List[str], timeout: int = 5) -> str:
    """Executa comando e retorna stdout limpo, ou vazio se erro."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.stdout.strip()
    except Exception as e:
        return ""

def section(title: str):
    console.print(Rule(title, style="bold cyan"))

def user_info() -> Dict[str, Any]:
    section("Informações do Usuário Atual")
    info = {}
    info['user'] = run_cmd(["whoami"])
    info['id'] = run_cmd(["id"])
    info['groups'] = run_cmd(["groups"])
    sudo_l = run_cmd(["sudo", "-l"])
    info['sudo_permissions'] = sudo_l if sudo_l else "Nenhuma permissão sudo detectada ou não permitido."
    console.print(f"[bold]Usuário:[/bold] {info['user']}")
    console.print(f"[bold]ID:[/bold] {info['id']}")
    console.print(f"[bold]Grupos:[/bold] {info['groups']}")
    console.print("[bold]Permissões sudo:[/bold]")
    console.print(Panel(Text(info['sudo_permissions'], overflow="fold"), style="yellow"))
    return info

def kernel_info() -> Dict[str, str]:
    section("Informações do Kernel e Sistema")
    info = {}
    info['uname'] = run_cmd(["uname", "-a"])
    os_release = ""
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", "r") as f:
                os_release = f.read().strip()
        except:
            pass
    info['os_release'] = os_release
    console.print(f"[bold]uname -a:[/bold] {info['uname']}")
    if os_release:
        console.print(Panel(Syntax(os_release, "ini"), title="/etc/os-release", style="green"))
    else:
        console.print("[yellow]/etc/os-release não encontrado ou não acessível[/yellow]")
    return info

def suid_sgid_files() -> List[str]:
    section("Arquivos SUID e SGID")
    files = []
    # Usar find, pode ser lento, mas efetivo
    cmd = ["find", "/", "-perm", "-4000", "-o", "-perm", "-2000", "-type", "f", "-exec", "ls", "-ld", "{}", ";"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        output = proc.stdout.strip()
        if output:
            files = output.splitlines()
    except Exception as e:
        console.print(f"[red]Erro ao buscar arquivos SUID/SGID: {e}[/red]")
    if files:
        table = Table(title="Arquivos SUID/SGID encontrados", show_lines=True)
        table.add_column("Permissões", style="cyan")
        table.add_column("Usuário", style="magenta")
        table.add_column("Grupo", style="magenta")
        table.add_column("Arquivo", style="green")
        for line in files:
            parts = line.split(None, 8)
            if len(parts) >= 9:
                perms, _, user, group, _, _, _, _, filename = parts
                table.add_row(perms, user, group, filename)
        console.print(table)
    else:
        console.print("[green]Nenhum arquivo SUID ou SGID encontrado[/green]")
    return files

def check_sensitive_files() -> Dict[str, str]:
    section("Permissões Sensíveis em Arquivos Importantes")
    sensitive_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/group",
        "/root/.bash_history",
        "/var/log/auth.log",
        "/var/log/secure"
    ]
    results = {}
    for f in sensitive_files:
        perm = ""
        owner = ""
        readable = False
        try:
            st = os.stat(f)
            perm = oct(st.st_mode & 0o777)
            owner = run_cmd(["stat", "-c", "%U:%G", f])
            readable = os.access(f, os.R_OK)
        except Exception:
            perm = "Arquivo não acessível"
            owner = "-"
            readable = False
        results[f] = f"Permissões: {perm}, Dono: {owner}, Legível: {'Sim' if readable else 'Não'}"
        console.print(f"{f}: [bold]{results[f]}[/bold]")
    return results

def running_root_processes() -> List[str]:
    section("Processos rodando como root")
    procs = []
    cmd = ["ps", "axo", "pid,user,comm"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        for line in proc.stdout.strip().splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) == 3:
                pid, user, comm = parts
                if user == "root":
                    procs.append(line)
    except Exception as e:
        console.print(f"[red]Erro ao listar processos: {e}[/red]")
    if procs:
        table = Table(title="Processos rodando como root")
        table.add_column("PID", style="cyan")
        table.add_column("Usuário", style="magenta")
        table.add_column("Comando", style="green")
        for p in procs:
            pid, user, comm = p.split(None, 2)
            table.add_row(pid, user, comm)
        console.print(table)
    else:
        console.print("[yellow]Nenhum processo rodando como root encontrado[/yellow]")
    return procs

def env_vars() -> Dict[str, str]:
    section("Variáveis de Ambiente Sensíveis")
    keys_to_check = [
        "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PERL5LIB",
        "IFS", "HOME", "SHELL", "USER"
    ]
    env_info = {}
    for k in keys_to_check:
        val = os.environ.get(k, "")
        env_info[k] = val if val else "Não definida"
        console.print(f"{k}: [bold]{env_info[k]}[/bold]")
    return env_info

def linux_capabilities() -> List[str]:
    section("Arquivos com Capabilities Linux (getcap)")
    files = []
    if shutil.which("getcap") is None:
        console.print("[yellow]getcap não está instalado ou não disponível no PATH[/yellow]")
        return files
    try:
        out = run_cmd(["getcap", "-r", "/"], timeout=30)
        if out:
            files = out.splitlines()
            table = Table(title="Arquivos com capabilities")
            table.add_column("File / Capability", style="green")
            for line in files:
                table.add_row(line)
            console.print(table)
        else:
            console.print("[green]Nenhum arquivo com capabilities encontrado[/green]")
    except Exception as e:
        console.print(f"[red]Erro ao executar getcap: {e}[/red]")
    return files

def cron_jobs() -> Dict[str, Any]:
    section("Cron Jobs e Scripts Executáveis")
    cron_info = {}

    # Crontab do usuário
    user_cron = run_cmd(["crontab", "-l"])
    cron_info['user_cron'] = user_cron if user_cron else "Nenhum crontab para o usuário ou não permitido."
    console.print("[bold]Crontab do usuário:[/bold]")
    console.print(Panel(Text(cron_info['user_cron'], overflow="fold"), style="yellow"))

    # Crontabs do sistema
    cron_dirs = ["/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
    for d in cron_dirs:
        if os.path.isdir(d):
            try:
                files = os.listdir(d)
                cron_info[d] = files
                console.print(f"[bold]{d}[/bold]: {', '.join(files) if files else 'Nenhum script'}")
            except Exception as e:
                console.print(f"[red]Erro ao listar {d}: {e}[/red]")
        else:
            cron_info[d] = "Diretório não existe"
            console.print(f"[yellow]{d} não existe[/yellow]")
    return cron_info

def writable_mounts() -> List[str]:
    section("Sistemas de Arquivos Montados com Permissão de Escrita")
    mounts = []
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    device, mountpoint, fstype, options = parts[:4]
                    if "rw" in options.split(","):
                        # Verifica se usuário tem permissão de escrita no mountpoint
                        if os.access(mountpoint, os.W_OK):
                            mounts.append(f"{device} montado em {mountpoint} com opções {options}")
    except Exception as e:
        console.print(f"[red]Erro ao ler /proc/mounts: {e}[/red]")
    if mounts:
        for m in mounts:
            console.print(f"[green]{m}[/green]")
    else:
        console.print("[yellow]Nenhum sistema de arquivos com permissão de escrita encontrado[/yellow]")
    return mounts

def backup_files() -> List[str]:
    section("Arquivos de Backup Sensíveis (.bak, .old, ~)")
    sensitive_dirs = ["/etc", "/root", "/home"]
    found = []
    patterns = [".bak", ".old", "~"]
    for base_dir in sensitive_dirs:
        if not os.path.exists(base_dir):
            continue
        for root, dirs, files in os.walk(base_dir):
            for f in files:
                if any(f.endswith(pat) or f.startswith(".") for pat in patterns):
                    filepath = os.path.join(root, f)
                    found.append(filepath)
                    if len(found) >= 50:  # Limite para não travar
                        return found
    if found:
        for f in found:
            console.print(f"[red]{f}[/red]")
    else:
        console.print("[green]Nenhum arquivo de backup sensível encontrado[/green]")
    return found

def dangerous_binaries() -> List[str]:
    """
    Busca binários comuns que podem ser usados para privesc via abuse, como python, bash, vi, etc,
    que estejam disponíveis no PATH.
    """
    section("Comandos Potencialmente Vulneráveis para Privesc")
    candidates = [
        "bash", "sh", "python", "python3", "perl", "ruby",
        "nc", "netcat", "nmap", "vim", "vi", "less", "more",
        "find", "telnet", "ftp", "curl", "wget", "tcpdump",
        "strace", "gdb"
    ]
    found = []
    for cmd in candidates:
        path = shutil.which(cmd)
        if path:
            found.append(f"{cmd} → {path}")
    if found:
        table = Table(title="Comandos no PATH para possível abuso")
        table.add_column("Comando", style="cyan")
        table.add_column("Caminho", style="green")
        for f in found:
            cmd_name, cmd_path = f.split(" → ")
            table.add_row(cmd_name, cmd_path)
        console.print(table)
    else:
        console.print("[yellow]Nenhum comando vulnerável encontrado no PATH[/yellow]")
    return found

def run_all(args) -> None:
    console.print("[bold magenta]--- Iniciando Privesc Scan ---[/bold magenta]\n")
    result = {}

    result["user_info"] = user_info()
    result["kernel_info"] = kernel_info()
    result["suid_sgid"] = suid_sgid_files()
    result["sensitive_files"] = check_sensitive_files()
    result["root_processes"] = running_root_processes()
    result["env_vars"] = env_vars()
    result["linux_capabilities"] = linux_capabilities()
    result["cron_jobs"] = cron_jobs()
    result["writable_mounts"] = writable_mounts()
    result["backup_files"] = backup_files()
    result["dangerous_binaries"] = dangerous_binaries()

    # Salvar em JSON se solicitado
    output_path: Optional[str] = getattr(args, "output", None)
    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False, default=json_serial)
            console.print(f"\n[bold green]Relatório salvo em {output_path}[/bold green]")
        except Exception as e:
            console.print(f"[red]Erro ao salvar relatório JSON: {e}[/red]")

def main():
    parser = argparse.ArgumentParser(description="Privesc Scanner - Escalada de Privilégio Linux")
    parser.add_argument("-o", "--output", help="Salvar relatório JSON em arquivo")
    args = parser.parse_args()
    run_all(args)

if __name__ == "__main__":
    main()
