# BlackReaper

## Descrição

BlackReaper é uma suíte modular de automação para pentests e CTFs focada em reconhecimento, enumeração, fuzzing e pós-exploração em ambientes Linux. Desenvolvida para rodar via terminal, com estilo hacker, visual atrativo e sem interface gráfica.

---

## Funcionalidades implementadas até agora

- Enumeração de informações do sistema e usuário
- Busca por arquivos SUID e SGID
- Verificação de permissões sensíveis em arquivos importantes
- Listagem de processos rodando como root
- Exposição de variáveis de ambiente sensíveis
- Detecção de arquivos de backup sensíveis
- Detecção automática de comandos potencialmente abusáveis para escalada de privilégios, com links diretos para [GTFOBins](https://gtfobins.github.io/)

---

## Como usar

### Requisitos

- Python 3.12+
- Dependências Python (veja abaixo)

### Instalando dependências

Recomendamos criar um ambiente virtual para evitar conflitos:

python3 -m venv venv
source venv/bin/activate
pip install --break-system-packages -r requirements.txt
Caso encontre erro de ambiente “externally managed”, use a flag --break-system-packages conforme acima.

Dependências instaladas
rich

requests

python-whois

Executando o scanner de escalada de privilégio

python privesc.py
Para salvar o relatório em JSON:

-> 
python privesc.py -o relatorio.json
Estrutura do código principal
privesc.py contém a lógica para coletar informações, listar binários perigosos e detectar possíveis vetores de escalada com links do GTFOBins.

A função dangerous_binaries_gtfobins() faz o scan dos binários presentes no sistema e imprime uma tabela estilizada no console.

O script usa rich para saída visual no terminal.

Exemplo de saída

--- Iniciando Privesc Scan ---

──────────────────────────── Informações do Usuário Atual ─────────────────────────────
Usuário: reaperkoji
UID: 1000
...

─────────────────── Comandos Potencialmente Abusáveis (GTFOBins) ────────────────────
┏────────┳────────────────────────┳────────────────────────────────────────────────────────────┓
┃ Comando┃ Caminho                ┃ GTFOBins                                                  ┃
┡────────╇────────────────────────╇────────────────────────────────────────────────────────────┩
│ bash   │ /bin/bash              │ https://gtfobins.github.io/gtfobins/bash/                │
│ python │ /usr/bin/python3       │ https://gtfobins.github.io/gtfobins/python/              │
│ vim    │ /usr/bin/vim           │ https://gtfobins.github.io/gtfobins/vim/                 │
└────────┴────────────────────────┴────────────────────────────────────────────────────────────┘

Próximos upgrade ->
Implementar mais módulos para enumeração e pós-exploração

Melhorar detecção e análise automatizada

Adicionar proteção contra comandos perigosos via sugestões do GTFOBins

Integrar com ferramentas externas e automações

Autor
Pedro Galvão (ReaperKoji)
Área: Hacking Ético / Cibersegurança
