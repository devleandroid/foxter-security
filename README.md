Foxter Security - Antivírus Multiplataforma
Bem-vindo ao Foxter Security, um antivírus leve e moderno projetado para proteger seu sistema contra ameaças digitais. Com uma interface gráfica intuitiva e um tema escuro futurista, o Foxter Security oferece ferramentas essenciais para escanear arquivos, monitorar firewall, portas, processos e usuários. Desenvolvido em Python com PyQt5, o aplicativo é compatível com Linux, Windows e macOS.
Este projeto foi criado para ser uma solução de segurança acessível e de código aberto, permitindo que usuários e desenvolvedores testem, utilizem e contribuam para seu desenvolvimento.
Visão Geral
O Foxter Security possui cinco módulos principais, acessíveis através de uma barra de navegação na interface principal:

Scanner e monitoramento: verifica arquivos por assinaturas locais e SHA-256, com leitura em blocos. Permite escanear uma pasta manualmente ou monitorar uma pasta selecionada enquanto o aplicativo estiver aberto; alterações em massa e extensões comuns de ransomware geram alertas heurísticos.
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

Python 3.11 ou superior. Instale as dependências do aplicativo com `python -m pip install -r requirements.txt`. Para compilar os binários, instale também `python -m pip install -r requirements-build.txt` e um compilador C compatível com seu sistema.





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

Função: Escaneia diretórios sob demanda ou monitora uma pasta selecionada para verificar arquivos novos e alterados e alertar sobre comportamentos que podem indicar ransomware.
Como Usar:
Clique em "Selecionar Diretório" para escolher uma pasta.
Clique em "Iniciar Escaneamento" para começar a análise.
Para monitoramento contínuo, clique em "Ativar proteção em tempo real"; ele permanece ativo enquanto o aplicativo estiver aberto. Use "Parar proteção em tempo real" para interromper.
Os resultados aparecem na tabela à direita:
Arquivo: Caminho do arquivo.
Status: "Suspicious" (suspeito), "Clean" (não corresponde às assinaturas locais) ou um erro de leitura.
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

Limitações de proteção: o monitoramento cobre somente a pasta selecionada e apenas enquanto o aplicativo está aberto. Os alertas comportamentais não interrompem processos nem impedem criptografia. A base local atual contém apenas as palavras `malware`, `virus` e `trojan` e hashes configurados pelo projeto; não há reputação na nuvem nem atualização automática. O programa é experimental, pode gerar falsos positivos e não substitui uma suíte antivírus comercial.

Segurança do executável: as releases são compiladas com Nuitka para dificultar a extração do bytecode Python. Isso aumenta o esforço de engenharia reversa, mas não a torna impossível; não armazene segredos no binário.

Versão: cada melhoria preparada para distribuição deve atualizar `VERSION` e `RELEASE_NOTES.md`. O workflow valida que a tag da release corresponde ao valor de `VERSION`.

## Apoie o projeto

### Ajude a fortalecer o Foxter Security

Segurança digital melhor se constrói com dedicação, transparência e apoio da comunidade. Se este projeto é útil para você, sua contribuição voluntária ajuda a manter e aprimorar o Foxter Security: financiar desenvolvimento, testes e correções de segurança, compatibilidade com Linux, Windows e macOS, e a infraestrutura necessária para compilar e publicar novas versões.

Qualquer valor faz diferença — e contribuir não é obrigatório. O Foxter Security ainda é experimental: a doação apoia o desenvolvimento, mas não compra um serviço nem substitui um antivírus profissional.

**Pix (CPF):** `803.185.680-04`

O Foxter Security está em desenvolvimento contínuo. As contribuições ajudam a manter o projeto ativo e acelerar testes, correções e melhorias. Publicamos atualizações e explicamos com transparência o que cada versão oferece, para que você possa acompanhar a evolução do projeto e decidir com confiança.



Contribuindo

Clone o Repositório: `git clone https://github.com/devleandroid/foxter-security.git`
cd foxter-security


Configure o Ambiente:
Crie um ambiente virtual e instale dependências:python3 -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
python -m pip install -r requirements.txt -r requirements-build.txt






Execute o Aplicativo: `python gui_main.py`


Empacote o aplicativo localmente (o build deve ser feito no sistema de destino):

```sh
python -m pip install -r requirements.txt -r requirements-build.txt
python scripts/build_app.py
python scripts/package_app.py
```

O Nuitka compila o código Python em binários nativos no modo standalone e remove docstrings do executável para dificultar a inspeção direta; os diretórios intermediários de build dependem do nome do script, e o empacotador os identifica automaticamente. No macOS, o modo app gera o pacote `.app`. Isso não impede engenharia reversa. O script identifica automaticamente a plataforma local. Se necessário, defina `BUILD_TARGET` como `linux-x64`, `windows-x64`, `macos-x64` ou `macos-arm64` antes de executar `scripts/package_app.py`. O GitHub Actions gera pacotes nativos para as quatro plataformas. Antes de publicar uma melhoria, atualize `VERSION` e `RELEASE_NOTES.md`. Para publicar, crie e envie uma tag igual a `v` mais o valor de `VERSION`:

```sh
git tag v1.0.5
git push origin v1.0.5
```

Isso inicia o workflow **Build desktop apps**. Ele executa testes, auditoria de dependências e análise estática antes dos builds; também roda em pull requests e alterações nas branches principais. Depois que os quatro builds terminarem, o workflow cria a GitHub Release dessa tag e anexa os ZIPs e `SHA256SUMS.txt`. Os hashes detectam corrupção/alteração dos arquivos, mas não autenticam o publicador. A release aparecerá em [Releases](https://github.com/devleandroid/foxter-security/releases), não na lista de arquivos da branch. Também é possível iniciar um build manual pela aba [Actions](https://github.com/devleandroid/foxter-security/actions) usando **Run workflow**; esse modo publica artefatos temporários, não uma release. Os builds são feitos no sistema de destino: o Nuitka não gera executáveis de Windows ou macOS a partir do Linux, nem vice-versa.



Problemas Conhecidos

Permissões: Algumas funcionalidades (ex.: fechar portas, remover usuários) requerem execução com privilégios elevados.
Segurança do binário: Nuitka compila o código em binários nativos em vez de distribuir bytecode Python fácil de extrair, o que aumenta o esforço de engenharia reversa. Isso não torna a engenharia reversa impossível; dados usados pelo programa ainda podem ser observados em execução. Não coloque chaves privadas, senhas ou segredos no código ou no pacote. Os pacotes ainda não têm assinatura digital de editor; no macOS, também não são notarizados.
Tamanho do Aplicativo: O pacote inclui Python, Qt e as dependências para funcionar sem instalação. O formato em pasta inicia mais rápido do que um executável único; o ZIP reduz o tamanho do download.



Licença
Este projeto é licenciado sob a MIT License. Sinta-se à vontade para usar, modificar e distribuir.
Contato
Para dúvidas ou sugestões, abra uma issue no repositório ou entre em contato com o autor.

Desenvolvido com 💜 por LebronX.
