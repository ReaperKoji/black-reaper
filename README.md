# BlackReaper

![BlackReaper Banner](https://user-images.githubusercontent.com/ReaperKoji/blackreaper-banner.png)  
*Uma suite CLI modular para automação de reconhecimento, enumeração web e pós-exploração focada em CTFs, Bug Bounty e pentests.*

---

## Descrição

O **BlackReaper** é uma ferramenta CLI 100% terminal, estilosa, modular e eficiente, desenvolvida para hackers éticos, estudantes de cibersegurança e entusiastas de CTFs. Seu foco está na automação de tarefas essenciais como reconhecimento, enumeração web (webenum) e pós-exploração (privesc), tudo com uma interface rica em cores e informações.

---

## Funcionalidades

- Reconhecimento automatizado de alvos
- Enumeração Web detalhada com fuzzing e análise
- Pós-exploração com análise de comandos perigosos, permissões e variáveis de ambiente
- Geração de relatórios JSON para integração ou análise posterior
- Interface colorida e amigável usando Rich
- Recomendação automática baseada em achados críticos
- Suporte a múltiplos módulos para extensibilidade futura

---

## Instalação

1. Clone o repositório:

```bash
git clone https://github.com/seuusuario/black-reaper.git
cd black-reaper/blackreaper

Crie e ative um ambiente virtual Python:

python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

Instale as dependências:

pip install -r requirements.txt


Uso
Execute o script principal:

python blackreaper.py --help

Exemplo de execução para reconhecimento:

python blackreaper.py --recon -t alvo.com

Para enumeração web:

python blackreaper.py --webenum -u http://alvo.com

Para pós-exploração:

python blackreaper.py --privesc -f resultado_scan.json

Estrutura do Projeto:

- blackreaper.py - Script principal com CLI e gerenciamento de módulos
- modules/recon.py - Módulo de reconhecimento
- modules/webenum.py - Enumeração web avançada
- modules/privesc.py - Pós-exploração e análise de segurança
- requirements.txt - Dependências do projeto
- README.md - Documentação (este arquivo)

Contribuição
Contribuições são bem-vindas!
Sinta-se à vontade para abrir issues ou enviar pull requests.

Licença  
Este projeto está licenciado sob a licença MIT — veja o arquivo LICENSE para detalhes.

Contato
Pedro Galvão (ReaperKoji)
GitHub | LinkedIn | reaperkoji@gmail.com