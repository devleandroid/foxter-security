Foxter Security - Antivírus Multiplataforma
Bem-vindo ao Foxter Security, um antivírus leve e moderno projetado para proteger seu sistema contra ameaças digitais. Com uma interface gráfica intuitiva e um tema escuro futurista, o Foxter Security oferece ferramentas essenciais para escanear arquivos, monitorar firewall, portas, processos e usuários. Desenvolvido em Python com PyQt5, o aplicativo é compatível com Linux, Windows e macOS.
Este projeto foi criado para ser uma solução de segurança acessível e de código aberto, permitindo que usuários e desenvolvedores testem, utilizem e contribuam para seu desenvolvimento.
Visão Geral
O Foxter Security possui cinco módulos principais, acessíveis através de uma barra de navegação na interface principal:

Scanner de Arquivos: Detecta arquivos suspeitos por assinaturas de conteúdo e SHA-256. A varredura percorre o diretório uma vez e lê os arquivos em blocos para reduzir o uso de memória.
Firewall: Verifica e corrige o status do firewall do sistema.
Portas: Monitora portas abertas e permite fechá-las.
Processos: Identifica processos suspeitos e permite encerrá-los.
Usuários: Lista usuários do sistema e remove usuários não autorizados.

A interface é projetada para ser intuitiva, com botões estilizados e feedback claro sobre o status das operações.
Requisitos
Para Usuários

Linux: pacote x64; `ufw` é necessário apenas para a integração de firewall.
Windows: pacote x64; algumas operações do sistema requerem privilégios de administrador.
macOS: escolha o pacote Intel ou Apple Silicon de acordo com o processador; algumas operações do sistema requerem privilégios elevados.

Para Desenvolvedores

Python 3.11 ou superior. Instale as dependências com `python -m pip install -r requirements.txt`. O PyInstaller é necessário apenas para gerar os pacotes.





Instalação

Baixe o Executável:

Os pacotes não ficam na branch `main` nem em uma pasta do código-fonte. Eles são publicados como **assets de uma GitHub Release**. Acesse a página [Releases do Foxter Security](https://github.com/devleandroid/foxter-security/releases) e, na versão mais recente, baixe o ZIP do seu sistema:

- `FoxterSecurity-linux-x64.zip` — Linux 64 bits
- `FoxterSecurity-windows-x64.zip` — Windows 64 bits
- `FoxterSecurity-macos-x64.zip` — macOS com processador Intel
- `FoxterSecurity-macos-arm64.zip` — macOS com Apple Silicon (M1/M2/M3/M4)

Na página da release, os arquivos ficam na seção **Assets**. Extraia o ZIP e execute o aplicativo dentro da pasta extraída (`FoxterSecurity` no Linux, `FoxterSecurity.exe` no Windows ou `Foxter Security.app` no macOS). Python não precisa estar instalado.

Para ver os builds temporários de uma execução manual do workflow, acesse a aba [Actions](https://github.com/devleandroid/foxter-security/actions), abra a execução concluída e baixe o artefato no final da página. Artefatos de Actions ficam disponíveis por 14 dias; para uma versão permanente, use uma Release.


Permissões (Linux e macOS):

No Linux, se necessário, dê permissão de execução: `chmod +x FoxterSecurity/FoxterSecurity`. Para funcionalidades que requerem privilégios, execute com sudo: `sudo ./FoxterSecurity/FoxterSecurity`.


No macOS, abra `Foxter Security.app`. Se o Gatekeeper bloquear um pacote não assinado, autorize-o nas configurações de Segurança e Privacidade. A distribuição não é assinada nem notarizada.

Windows:

Execute `FoxterSecurity.exe`. Para operações do sistema que exigem privilégios, execute como administrador.





Como Usar o Foxter Security
Interface Principal
Ao abrir o Foxter Security, você verá a interface principal com uma barra de navegação contendo cinco abas: Scanner, Firewall, Portas, Processos e Usuários.
Imagem 1: Interface principal do Foxter Security com tema escuro futurista.
1. Scanner de Arquivos

Função: Escaneia diretórios em busca de arquivos suspeitos com base em assinaturas.
Como Usar:
Clique em "Selecionar Diretório" para escolher uma pasta.
Clique em "Iniciar Escaneamento" para começar a análise.
Os resultados aparecem na tabela à direita:
Arquivo: Caminho do arquivo.
Status: "Suspicious" (suspeito) ou "Safe" (seguro).
Ação: Clique com o botão direito para "Mover para Quarentena" ou "Excluir".


Clique em "Salvar Relatório" para exportar os resultados como arquivo .txt.



Imagem 2: Aba Scanner mostrando um escaneamento em progresso.
2. Firewall

Função: Verifica o status do firewall e permite ativá-lo.
Como Usar:
Clique em "Verificar Firewall" para checar o status.
Status: "Active" (ativo) ou "Inactive" (inativo).
Ameaças: Lista possíveis vulnerabilidades (ex.: portas abertas ou firewall desativado).


Clique em "Corrigir Firewall" para ativar o firewall (requer permissões elevadas).



Imagem 3: Aba Firewall mostrando o status e ameaças detectadas.
3. Portas

Função: Monitora portas abertas e permite fechá-las.
Como Usar:
Clique em "Checar Portas" para listar portas comuns (ex.: 80, 8080).
Porta: Número da porta.
Status: "Open" (aberta) ou "Closed" (fechada).
Risco: Descrição do risco associado.
Ação: Clique com o botão direito em uma porta aberta e selecione "Fechar Porta".


O fechamento de portas requer permissões elevadas.



Imagem 4: Aba Portas com uma porta aberta e a opção de fechá-la.
4. Processos

Função: Detecta processos suspeitos e permite encerrá-los.
Como Usar:
Clique em "Detectar Processos" para listar processos suspeitos.
PID: Identificador do processo.
Nome: Nome do processo.
Usuário: Usuário que executa o processo.
Solução: Clique com o botão direito e selecione "Encerrar Processo".


Ajuste o intervalo de monitoramento com o slider (em segundos).



Imagem 5: Aba Processos mostrando processos suspeitos e o slider de intervalo.
5. Usuários

Função: Lista usuários do sistema e remove usuários não autorizados.
Como Usar:
Clique em "Verificar Usuários" para listar usuários.
Usuário: Nome do usuário.
Status: "Authorized" (autorizado) ou "Unauthorized" (não autorizado).
Ação: Clique com o botão direito em um usuário não autorizado e selecione "Remover Usuário".


A remoção de usuários requer permissões elevadas.



Imagem 6: Aba Usuários mostrando a lista de usuários e opções de remoção.
Logs

Os logs e os arquivos em quarentena são armazenados em uma pasta de dados do usuário: `%LOCALAPPDATA%/Foxter Security` no Windows, `~/Library/Application Support/Foxter Security` no macOS e `~/.local/share/foxter-security` no Linux (ou em `$XDG_DATA_HOME/foxter-security` quando definido).



Contribuindo

Clone o Repositório:git clone https://github.com/seu-usuario/foxter-security.git
cd foxter-security


Configure o Ambiente:
Crie um ambiente virtual e instale dependências:python3 -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install PyQt5 psutil pyinstaller


No Windows:pip install pywin32






Execute o Aplicativo: `python gui_main.py`


Empacote o aplicativo localmente (o build deve ser feito no sistema de destino):

```sh
python -m pip install -r requirements.txt
python -m pip install "pyinstaller>=6.14,<7"
python -m PyInstaller --noconfirm --clean Antivirus.spec
```

O resultado fica em `dist/FoxterSecurity` (ou `dist/Foxter Security.app` no macOS). O GitHub Actions gera pacotes nativos para Linux x64, Windows x64, macOS Intel e Apple Silicon. Para publicar uma versão, crie e envie uma tag de versão:

```sh
git tag v1.0.0
git push origin v1.0.0
```

Isso inicia o workflow **Build desktop apps**. Depois que os quatro builds e os testes terminarem, o workflow cria a GitHub Release dessa tag e anexa os ZIPs automaticamente. A release aparecerá em [Releases](https://github.com/devleandroid/foxter-security/releases), não na lista de arquivos da branch. Também é possível iniciar um build manual pela aba [Actions](https://github.com/devleandroid/foxter-security/actions) usando **Run workflow**; esse modo publica artefatos temporários, não uma release. Os builds são feitos no sistema de destino: o PyInstaller não gera executáveis de Windows ou macOS a partir do Linux, nem vice-versa.



Problemas Conhecidos

Permissões: Algumas funcionalidades (ex.: fechar portas, remover usuários) requerem execução com privilégios elevados.
Tamanho do Aplicativo: O pacote inclui Python, Qt e as dependências para funcionar sem instalação. O formato em pasta inicializa mais rápido do que um executável único; o ZIP reduz o tamanho do download.



Licença
Este projeto é licenciado sob a MIT License. Sinta-se à vontade para usar, modificar e distribuir.
Contato
Para dúvidas ou sugestões, abra uma issue no repositório ou entre em contato com o autor.

Desenvolvido com 💜 por LebronX.
