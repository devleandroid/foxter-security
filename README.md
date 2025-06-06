Foxter Security - Antivírus Multiplataforma
Bem-vindo ao Foxter Security, um antivírus leve e moderno projetado para proteger seu sistema contra ameaças digitais. Com uma interface gráfica intuitiva e um tema escuro futurista, o Foxter Security oferece ferramentas essenciais para escanear arquivos, monitorar firewall, portas, processos e usuários. Desenvolvido em Python com PyQt5, o aplicativo é compatível com Linux, Windows e macOS.
Este projeto foi criado para ser uma solução de segurança acessível e de código aberto, permitindo que usuários e desenvolvedores testem, utilizem e contribuam para seu desenvolvimento.
Visão Geral
O Foxter Security possui cinco módulos principais, acessíveis através de uma barra de navegação na interface principal:

Scanner de Arquivos: Detecta arquivos suspeitos com base em assinaturas conhecidas.
Firewall: Verifica e corrige o status do firewall do sistema.
Portas: Monitora portas abertas e permite fechá-las.
Processos: Identifica processos suspeitos e permite encerrá-los.
Usuários: Lista usuários do sistema e remove usuários não autorizados.

A interface é projetada para ser intuitiva, com botões estilizados e feedback claro sobre o status das operações.
Requisitos
Para Usuários

Linux: ufw instalado (sudo apt-get install ufw).
Windows: Execute como administrador para funcionalidades que requerem privilégios.
macOS: Execute com sudo para funcionalidades que requerem privilégios.
Sistema operacional: Linux (distribuições baseadas em Debian/Ubuntu testadas), Windows 7 ou superior, macOS 10.14 ou superior.

Para Desenvolvedores

Python 3.7 ou superior.
Dependências Python:pip install PyQt5 psutil pyinstaller


No Windows, instale também:pip install pywin32





Instalação

Baixe o Executável:

Acesse a seção de Releases e baixe o executável correspondente ao seu sistema operacional:
Antivirus para Linux.
Antivirus.exe para Windows.
Antivirus.app ou Antivirus para macOS.


Link direto para download: Baixar Foxter Security.


Permissões (Linux e macOS):

No Linux, dê permissão de execução:chmod +x Antivirus


Para funcionalidades que requerem privilégios, execute com sudo:sudo ./Antivirus


No macOS, se usar o executável diretamente:chmod +x Antivirus
sudo ./Antivirus

Ou abra o Antivirus.app normalmente.


Windows:

Execute o Antivirus.exe como administrador para garantir o funcionamento de todas as funcionalidades:runas /user:Administrator Antivirus.exe





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

Todas as operações são registradas no arquivo antivirus.log no diretório onde o executável está localizado.
Para verificar os logs:cat antivirus.log



Contribuindo

Clone o Repositório:git clone https://github.com/seu-usuario/foxter-security.git
cd foxter-security


Configure o Ambiente:
Crie um ambiente virtual e instale dependências:python3 -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install PyQt5 psutil pyinstaller


No Windows:pip install pywin32






Execute o Aplicativo:python gui/main_window.py


Empacote o Executável:
Use o Antivirus.spec fornecido:pyinstaller Antivirus.spec


Ajuste o pathex no Antivirus.spec conforme seu sistema operacional.



Problemas Conhecidos

Permissões: Algumas funcionalidades (ex.: fechar portas, remover usuários) requerem execução com privilégios elevados.
Ícone: Certifique-se de que o arquivo icon.png está no diretório raiz para exibir o ícone do aplicativo.
Tamanho do Executável: O executável pode ser grande; instale o UPX para reduzir o tamanho:sudo apt-get install upx-ucl  # Linux
brew install upx  # macOS



Licença
Este projeto é licenciado sob a MIT License. Sinta-se à vontade para usar, modificar e distribuir.
Contato
Para dúvidas ou sugestões, abra uma issue no repositório ou entre em contato com o autor.

Desenvolvido com 💜 por LebronX.
