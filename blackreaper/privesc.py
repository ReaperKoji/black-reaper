#!/usr/bin/env python3
import pwd
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

def check_dangerous_env_vars() -> List[Dict[str, str]]:
    """
    Analisa variáveis de ambiente em busca de configurações perigosas.
    Ex: diretórios world-writable no PATH, uso de LD_PRELOAD, etc.
    """
    section("Análise de Variáveis de Ambiente Perigosas")

    dangerous_vars = ["PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH"]
    findings = []

    for var in dangerous_vars:
        value = os.environ.get(var)
        if not value:
            continue

        # Dividir por ":" se for um caminho (exceto LD_PRELOAD)
        paths = value.split(":") if ":" in value else [value]

        for p in paths:
            p = p.strip()

            # PATHs world-writable
            if os.path.isdir(p):
                try:
                    mode = os.stat(p).st_mode
                    if bool(mode & 0o002):  # World-writable
                        findings.append({
                            "variable": var,
                            "value": p,
                            "issue": "Diretório world-writable"
                        })
                except Exception:
                    continue

            # Diretórios potencialmente perigosos
            if p in [".", "/tmp", "/var/tmp"]:
                findings.append({
                    "variable": var,
                    "value": p,
                    "issue": "Diretório potencialmente inseguro"
                })

            # Bibliotecas/carregadores suspeitos
            if var == "LD_PRELOAD" and p:
                findings.append({
                    "variable": var,
                    "value": p,
                    "issue": "Uso de LD_PRELOAD pode indicar injeção de biblioteca"
                })

    # Exibir resultados
    if findings:
        table = Table(title="Variáveis de Ambiente Potencialmente Perigosas")
        table.add_column("Variável", style="cyan")
        table.add_column("Valor", style="green")
        table.add_column("Problema", style="red")
        for item in findings:
            table.add_row(item["variable"], item["value"], item["issue"])
        console.print(table)
    else:
        console.print("[green]Nenhuma variável de ambiente perigosa encontrada[/green]")

    return findings

def dangerous_binaries_gtfobins() -> List[Dict[str, str]]:
    """
    Lista comandos comuns que podem ser abusados para escalada de privilégio
    e mostra os caminhos e os links diretos para GTFOBins.
    """
    section("Comandos Potencialmente Abusáveis (GTFOBins)")
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
            gtfobins_link = f"https://gtfobins.github.io/gtfobins/{cmd}/"
            found.append({
                "cmd": cmd,
                "path": path,
                "gtfobins": gtfobins_link
            })
    
    if found:
        table = Table(title="Possíveis binários de escalada com link GTFOBins")
        table.add_column("Comando", style="cyan")
        table.add_column("Caminho", style="green")
        table.add_column("GTFOBins", style="magenta")
        for item in found:
            table.add_row(item["cmd"], item["path"], item["gtfobins"])
        console.print(table)
    else:
        console.print("[yellow]Nenhum comando potencialmente abusável encontrado no PATH[/yellow]")
    
    return found
def check_unusual_binaries_permissions() -> List[Dict[str, str]]:
    """
    Verifica binários nos diretórios do PATH com permissões incomuns:
    - Permissões world-writable
    - Dono diferente de root
    """
    section("Verificando Permissões Incomuns em Binários do PATH")

    suspicious = []
    paths = os.environ.get("PATH", "").split(":")
    checked = set()

    for directory in paths:
        if not os.path.isdir(directory):
            continue
        try:
            for fname in os.listdir(directory):
                full_path = os.path.join(directory, fname)
                if full_path in checked or not os.path.isfile(full_path):
                    continue
                checked.add(full_path)
                stat_info = os.stat(full_path)
                perms = oct(stat_info.st_mode)[-3:]
                uid = stat_info.st_uid
                user = pwd.getpwuid(uid).pw_name

                # World-writable ou dono não root
                if perms.endswith("7") or user != "root":
                    suspicious.append({
                        "file": full_path,
                        "perms": perms,
                        "owner": user
                    })
        except Exception:
            continue

    if suspicious:
        table = Table(title="Binários com Permissões Incomuns")
        table.add_column("Arquivo", style="cyan")
        table.add_column("Permissões", style="yellow")
        table.add_column("Dono", style="red")
        for entry in suspicious:
            table.add_row(entry["file"], entry["perms"], entry["owner"])
        console.print(table)
    else:
        console.print("[green]Nenhum binário com permissões incomuns encontrado nos diretórios do PATH[/green]")

    return suspicious


def scan_dangerous_commands_in_scripts() -> List[Dict[str, str]]:
    """
    Procura por comandos potencialmente perigosos em scripts comuns do sistema.
    Verifica arquivos como crontabs, init.d, systemd, etc., buscando por binários perigosos.
    """
    section("Comandos Perigosos em Scripts do Sistema")

    search_paths = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.hourly/",
        "/etc/cron.monthly/",
        "/etc/cron.weekly/",
        "/etc/init.d/",
        "/etc/systemd/",
        "/opt/",
        "/home/"
    ]

    keywords = ["chmod", "chown", "cp", "mv", "tar", "awk", "dd", "python", "bash", "sh", "wget", "curl"]
    findings = []

    for path in search_paths:
        if os.path.isfile(path):
            files = [path]
        elif os.path.isdir(path):
            try:
                files = [os.path.join(path, f) for f in os.listdir(path)]
            except Exception:
                continue
        else:
            continue

        for file in files:
            try:
                with open(file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for kw in keywords:
                        if re.search(rf"\b{kw}\b", content):
                            findings.append({"file": file, "command": kw})
            except Exception:
                continue

    if findings:
        table = Table(title="Comandos Perigosos Encontrados em Scripts")
        table.add_column("Arquivo", style="cyan")
        table.add_column("Comando", style="red")
        for item in findings:
            table.add_row(item["file"], item["command"])
        console.print(table)
    else:
        console.print("[green]Nenhum comando perigoso encontrado nos scripts verificados[/green]")

    return findings


# Esse bloco deve ficar na função principal, tipo run_all(args):

def run_all(args) -> None:
    console.print("[bold magenta]--- Iniciando Privesc Scan ---[/bold magenta]\n")
    result = {}

    # Definir output_path no início
    output_path = getattr(args, "output", None)

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
    result["dangerous_binaries"] = dangerous_binaries_gtfobins()
    result["dangerous_commands_in_scripts"] = scan_dangerous_commands_in_scripts()
    result["unusual_bin_permissions"] = check_unusual_binaries_permissions()
    result["dangerous_env_vars"] = check_dangerous_env_vars()
    result["uid_discrepancies"] = check_uid_discrepancies()

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False, default=json_serial)
            console.print(f"[green]Relatório salvo em {output_path}[/green]")
        except Exception as e:
            console.print(f"[red]Erro ao salvar relatório JSON: {e}[/red]")

def check_uid_discrepancies() -> Dict[str, str]:
    """
    Verifica UID real e efetivo do processo atual.
    Se forem diferentes, pode indicar uso de SUID ou privilege escalation.
    """
    section("Verificação de UID Real vs Efetivo")

    try:
        real_uid = os.getuid()
        effective_uid = os.geteuid()
        username = pwd.getpwuid(real_uid).pw_name
        e_username = pwd.getpwuid(effective_uid).pw_name

        table = Table(title="UIDs do Processo Atual")
        table.add_column("Tipo", style="cyan")
        table.add_column("UID", style="yellow")
        table.add_column("Usuário", style="magenta")

        table.add_row("UID Real", str(real_uid), username)
        table.add_row("UID Efetivo", str(effective_uid), e_username)

        if real_uid != effective_uid:
            console.print("[bold red]Atenção: UID real e efetivo são diferentes! Pode indicar privilege escalation.[/bold red]")
        else:
            console.print("[green]UIDs iguais - sem anomalias aparentes[/green]")

        console.print(table)

        return {
            "real_uid": str(real_uid),
            "real_user": username,
            "effective_uid": str(effective_uid),
            "effective_user": e_username
        }

    except AttributeError:
        console.print("[yellow]Este sistema não suporta verificação de UID (ex: Windows)[/yellow]")
        return {"real_uid": "N/A", "effective_uid": "N/A"}
    except Exception as e:
        console.print(f"[red]Erro ao verificar UIDs: {e}[/red]")
        return {"real_uid": "Erro", "effective_uid": "Erro"}

def main():
    parser = argparse.ArgumentParser(description="Privesc Scanner - Escalada de Privilégio Linux")
    parser.add_argument("-o", "--output", help="Salvar relatório JSON em arquivo")
    args = parser.parse_args()
    run_all(args)

if __name__ == "__main__":
    main()
