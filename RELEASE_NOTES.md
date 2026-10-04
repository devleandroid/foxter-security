## O que é o Foxter Security

O Foxter Security é uma ferramenta de segurança para desktop com scanner manual de arquivos e painéis de consulta do sistema. Os pacotes desta release incluem o aplicativo e suas dependências: não é necessário instalar Python.

## Como baixar e iniciar

Baixe o ZIP correspondente ao seu sistema na seção **Assets** abaixo e extraia a pasta inteira:

- `FoxterSecurity-linux-x64.zip` — Linux x64
- `FoxterSecurity-windows-x64.zip` — Windows x64
- `FoxterSecurity-macos-x64.zip` — macOS Intel
- `FoxterSecurity-macos-arm64.zip` — macOS Apple Silicon

Inicie `FoxterSecurity` no Linux, `FoxterSecurity.exe` no Windows ou abra `Foxter Security.app` no macOS. No Linux, se necessário, permita a execução com `chmod +x FoxterSecurity/FoxterSecurity`. No macOS, o sistema pode solicitar autorização porque o aplicativo não está assinado nem notarizado.

## Como usar

1. **Scanner:** abra a aba Scanner, selecione uma pasta e clique em **Iniciar Escaneamento**. Os resultados aparecem durante a verificação. Se um arquivo for marcado como suspeito, use o menu de contexto para movê-lo à quarentena ou excluí-lo. Essas ações alteram arquivos; confira o caminho antes de confirmar.
2. **Firewall:** use **Verificar Firewall** para consultar o status e **Corrigir Firewall** para tentar ativá-lo. Essa operação altera a configuração do sistema e pode exigir privilégios de administrador. No Linux, o verificador depende do `ufw`.
3. **Portas:** **Checar Portas** verifica conexões locais nas portas 80, 443 e 8080. O menu de contexto permite adicionar uma regra de bloqueio para uma porta indicada como aberta; isso pode interromper serviços que você utiliza.
4. **Processos:** **Detectar Processos** lista processos que correspondem às heurísticas do aplicativo. O menu de contexto permite tentar encerrá-los. Ajuste o intervalo de monitoramento com o controle deslizante.
5. **Usuários:** **Verificar Usuários** lista contas e sinaliza diretórios pessoais cujos metadados foram alterados nas últimas 24 horas. Confira a conta antes de removê-la: a remoção é uma ação destrutiva e requer privilégios elevados.

Logs e arquivos em quarentena ficam na pasta de dados do usuário: `%LOCALAPPDATA%/Foxter Security` no Windows, `~/Library/Application Support/Foxter Security` no macOS e `~/.local/share/foxter-security` no Linux (ou `$XDG_DATA_HOME/foxter-security` quando `XDG_DATA_HOME` estiver definido).

## Limitações importantes

Este projeto é uma ferramenta experimental e não substitui um antivírus com proteção em tempo real. O scanner examina apenas a pasta escolhida, procurando as assinaturas locais definidas pelo projeto (atualmente as palavras `malware`, `virus` e `trojan`) e hashes SHA-256 adicionados à base. Ele não consulta um serviço de inteligência de ameaças, não atualiza essa base pela rede e não garante detectar malware desconhecido. Outros painéis usam heurísticas simples e podem produzir falsos positivos; confira os resultados antes de bloquear, encerrar ou remover qualquer coisa.
