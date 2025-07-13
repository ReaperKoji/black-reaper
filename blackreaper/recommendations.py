# recommendations.py

def generate_recommendations(scan_results: dict) -> list[str]:
    recommendations = []

    # SUID/SGID
    if scan_results.get("suid_sgid"):
        recommendations.append("🔧 SUID/SGID encontrados — Verifique os binários com permissões elevadas. Use ferramentas como GTFOBins ou linpeas.")

    # Root processes
    if scan_results.get("root_processes"):
        recommendations.append("🧩 Processos rodando como root — Analise se algum processo pode ser explorado para escalonamento.")

    # Variáveis de ambiente perigosas
    for var in scan_results.get("env_vars_dangerous", []):
        recommendations.append(f"⚠️ Variável de ambiente `{var['var']}` com diretório world-writable: Risco de path hijacking.")

    # GTFOBins
    if scan_results.get("dangerous_binaries"):
        recommendations.append("🚩 Binários exploráveis detectados — Consulte os links do GTFOBins incluídos.")

    # Comandos perigosos
    if scan_results.get("dangerous_commands_in_scripts"):
        recommendations.append("⚙️ Comandos perigosos encontrados em scripts — Verifique scripts por execuções maliciosas.")

    # UID efetivo ≠ UID real
    if scan_results.get("uid_mismatch"):
        recommendations.append("🔓 UID efetivo é diferente do real — Possível exploração via binário SUID ou comportamento anômalo.")

    # Backup files
    if scan_results.get("backup_files"):
        recommendations.append("🗃️ Arquivos de backup encontrados — Verifique se contêm credenciais ou configurações sensíveis.")

    # Cronjobs vazios
    if not scan_results.get("cron_jobs"):
        recommendations.append("⏰ Nenhum cron job encontrado — Pode ser limpo, mas revise permissões dos diretórios `/etc/cron.*`.")

    if not recommendations:
        recommendations.append("✅ Nenhuma anomalia crítica identificada — Mas continue analisando manualmente.")

    return recommendations
