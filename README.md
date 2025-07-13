# BlackReaper

BlackReaper é uma suite hacker via terminal, modular e estilosa, focada em automação de reconhecimento, enumeração, fuzzing e pós-exploração para pentests, bug bounty e CTFs.

## Funcionalidades atuais

- Enumeração Web com headers e fingerprint básico

## Como usar

### Setup

```bash
python -m venv venv
source venv/Scripts/activate  # Windows PowerShell
# ou
source venv/bin/activate      # Linux/Mac

pip install -r requirements.txt

python -m blackreaper.cli webenum -u http://example.com
gi