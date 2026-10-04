Versão desta melhoria: **1.0.3**.

## O que é o Foxter Security

O Foxter Security é uma ferramenta de segurança experimental para desktop. Esta versão inclui escaneamento manual, monitoramento opcional de uma pasta em tempo real e alertas comportamentais de possíveis atividades de ransomware. Os pacotes incluem o aplicativo e suas dependências: não é necessário instalar Python.

## Como baixar e iniciar

Baixe o ZIP correspondente ao seu sistema na seção **Assets** abaixo e extraia a pasta inteira:

O arquivo `SHA256SUMS.txt` contém os hashes SHA-256 dos ZIPs para conferir a integridade do download. Os hashes não provam a identidade do publicador porque os pacotes ainda não têm assinatura digital.

- `FoxterSecurity-linux-x64.zip` — Linux x64
- `FoxterSecurity-windows-x64.zip` — Windows x64
- `FoxterSecurity-macos-x64.zip` — macOS Intel
- `FoxterSecurity-macos-arm64.zip` — macOS Apple Silicon

Inicie `FoxterSecurity` no Linux, `FoxterSecurity.exe` no Windows ou abra `Foxter Security.app` no macOS. No Linux, se necessário, permita a execução com `chmod +x FoxterSecurity/FoxterSecurity`. No macOS, o sistema pode solicitar autorização porque o aplicativo não está assinado nem notarizado.

## Como usar

1. **Scanner manual:** abra a aba Scanner, selecione uma pasta e clique em **Iniciar Escaneamento**. A leitura é feita em blocos e os resultados aparecem durante a verificação.
2. **Monitoramento em tempo real:** selecione a pasta que deseja acompanhar e clique em **Ativar proteção em tempo real**. Arquivos criados ou alterados são verificados após uma breve pausa para permitir que a gravação termine. O monitoramento fica ativo enquanto o aplicativo estiver aberto; clique em **Parar proteção em tempo real** para desativá-lo.
3. **Ameaças e ransomware:** arquivos que correspondem às assinaturas locais aparecem como suspeitos na tabela. Eventos de alteração em massa ou renomeação para extensões conhecidas de ransomware geram alertas. O programa não bloqueia nem remove arquivos ou encerra processos automaticamente. Analise os alertas e use o menu de contexto da tabela para mover um arquivo suspeito à quarentena ou excluí-lo; confira o caminho antes, pois essas ações alteram arquivos.
4. **Firewall:** use **Verificar Firewall** para consultar o status e **Corrigir Firewall** para tentar ativá-lo. Essa operação altera a configuração do sistema e pode exigir privilégios de administrador. No Linux, o verificador depende do `ufw`.
5. **Portas:** **Checar Portas** verifica conexões locais nas portas 80, 443 e 8080. O menu de contexto permite adicionar uma regra de bloqueio para uma porta indicada como aberta; isso pode interromper serviços que você utiliza.
6. **Processos:** **Detectar Processos** lista processos que correspondem às heurísticas do aplicativo. O menu de contexto permite tentar encerrá-los. Ajuste o intervalo de monitoramento com o controle deslizante.
7. **Usuários:** **Verificar Usuários** lista contas e sinaliza diretórios pessoais cujos metadados foram alterados nas últimas 24 horas. Confira a conta antes de removê-la: a remoção é uma ação destrutiva e requer privilégios elevados.

Logs e arquivos em quarentena ficam na pasta de dados do usuário: `%LOCALAPPDATA%/Foxter Security` no Windows, `~/Library/Application Support/Foxter Security` no macOS e `~/.local/share/foxter-security` no Linux (ou `$XDG_DATA_HOME/foxter-security` quando `XDG_DATA_HOME` estiver definido).

## Limitações importantes

Este projeto é uma ferramenta experimental e não substitui uma suíte antivírus comercial. O scanner examina apenas a pasta escolhida, procurando as assinaturas locais definidas pelo projeto (atualmente as palavras `malware`, `virus` e `trojan`) e hashes SHA-256 adicionados à base. O monitoramento em tempo real também cobre somente a pasta escolhida e só funciona enquanto o programa estiver aberto. Nenhum conteúdo ou hash é enviado a terceiros; não há consulta de reputação na nuvem nem atualização automática das assinaturas. A detecção comportamental de ransomware é heurística, não impede criptografia e pode produzir falsos positivos durante operações legítimas com muitos arquivos. Outros painéis também usam heurísticas simples; confira os resultados antes de bloquear, encerrar ou remover qualquer coisa.
