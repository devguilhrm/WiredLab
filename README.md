# Network

Projeto em C++ para estudo e teste de protocolos de rede em Linux. O codigo constroi, envia, recebe e interpreta pacotes de baixo nivel usando sockets `AF_PACKET`, filtros BPF e consultas Netlink/RTNETLINK.

O foco atual do dashboard web e inventario e monitoramento: varredura IPv4 com ARP, varredura IPv6 com ICMPv6, monitoramento DNS em tempo real e visualizacao de rotas de rede.

> Use somente em redes proprias, laboratorios ou ambientes onde voce tem autorizacao explicita. Algumas ferramentas podem causar indisponibilidade, alterar tabelas ARP/NDP ou liberar leases DHCP.

## Para que serve

Este projeto serve como um laboratorio de redes em C++ para:

- Descobrir hosts IPv4 na rede local com ARP.
- Descobrir hosts IPv6 no link local com ICMPv6 multicast.
- Observar consultas DNS visiveis na interface em tempo real.
- Filtrar eventos DNS por IP, MAC, dominio ou informacao do dispositivo.
- Consultar informacoes do kernel Linux via Netlink.

## Estrutura

```text
.
|-- Include/              # Headers de pacotes, filtros, utilitarios e DHCP starvation
|-- Source/               # Implementacoes compartilhadas
|-- Bin/                  # Binarios Linux ja gerados e arquivos de clientes DHCP
|-- scripts/              # Scripts de permissao/operacao no Linux
|-- tools/                # Interface grafica e utilitarios de operacao
|-- web/                  # Dashboard web para Ubuntu Server sem interface grafica
|-- CMakeLists.txt        # Build centralizado do projeto
|-- *_scan.cpp            # Ferramentas de varredura/captura
|-- *_spoofing.cpp        # Demonstracoes de spoofing ARP/NDP
|-- dhcp*.cpp             # Demonstracoes DHCP/DHCPv6
|-- dns*.cpp              # Ferramentas DNS
`-- netlink.cpp           # Inspecao RTNETLINK
```

## Ferramentas

| Arquivo | Funcao |
| --- | --- |
| `arp_scan.cpp` | Varre a sub-rede IPv4 da interface usando requisicoes ARP. Mostra IP, MAC, hostname via reverse DNS/PTR quando disponivel e fabricante via `api.macvendors.com`. |
| `icmp6_scan.cpp` | Envia ICMPv6 Echo Request para `ff02::1` e lista hosts IPv6 que respondem. Tambem tenta identificar fabricante pelo MAC. |
| `dns_monitor.cpp` | Monitora consultas DNS visiveis na interface e imprime IP/MAC de origem, transporte e dominio consultado. |
| `netlink.cpp` | Consulta e imprime informacoes de rotas, interfaces e enderecos via Netlink/RTNETLINK. |

As ferramentas abaixo continuam no repositorio como laboratorio/experimentos, mas nao aparecem no dashboard web funcional por padrao:

| Arquivo | Funcao |
| --- | --- |
| `dns_scan.cpp` | Captura trafego DNS de um MAC informado e imprime os nomes consultados. Suporta DNS sobre UDP e TCP em IPv4/IPv6. |
| `arp_spoofing.cpp` | Faz ARP spoofing entre gateway e host informados. Ao parar, tenta restaurar as entradas ARP corretas. |
| `ndp_spoofing.cpp` | Faz spoofing NDP/Neighbor Advertisement em IPv6 entre gateway e host. Ao parar, tenta restaurar as entradas corretas. |
| `dhcp.cpp` | Executa DHCP starvation com clientes falsos. Aceita `--interface` e salva listas em `./Clients/*.cli`. |
| `release_fclients.cpp` | Envia DHCP RELEASE para os clientes falsos salvos em `./Clients/fclients.cli`. Aceita `--interface`. |
| `release_aclients.cpp` | Lista clientes ativos salvos em `./Clients/aclients.cli` e envia DHCP RELEASE para o cliente selecionado. Aceita `--interface`. |
| `dhcpv6.cpp` | Demonstra a montagem de um DHCPv6 Information Request. Aceita `--interface`, mas ainda contem enderecos IPv6 fixos no codigo. |
| `dhcp_server.cpp` | Teste minimo de bind na porta de servidor DHCP. Aceita `--interface`. |
| `dns_rr.cpp` | Demonstra consulta DNS via TCP/IPv6 para root server, consultando `www.gov.br`. Possui valores fixos no codigo. |

## Arquitetura atual

O projeto agora esta organizado em tres camadas:

- Nucleo C++: `Include/Packet.h`, `Source/Packet.cpp`, `Include/Utils.h` e `Source/Utils.cpp` concentram montagem, leitura, formatacao de pacotes e descoberta de interfaces.
- Ferramentas: cada arquivo `*.cpp` na raiz e um executavel pequeno que usa o nucleo para uma tarefa especifica.
- Orquestracao: `CMakeLists.txt` compila todos os executaveis, `tools/network_gui.py` fornece uma interface Tkinter para ambientes com desktop e `web/server.py` fornece um dashboard web para Ubuntu Server sem interface grafica.

O header `Include/CLI.h` centraliza leitura de argumentos como `--interface`, `--gateway`, `--host` e `--mac`. Com isso, as ferramentas continuam funcionando em modo interativo, mas tambem podem ser chamadas por scripts ou pela GUI. A GUI tambem possui um dashboard que transforma parte da saida textual dos binarios em indicadores e eventos tabulares.

## Requisitos

- Linux. Os headers e chamadas usadas sao especificos de Linux (`linux/if_packet.h`, `linux/filter.h`, `linux/rtnetlink.h`).
- Permissao de root, `sudo` ou capabilities equivalentes para sockets raw/packet.
- `g++` com suporte a C++17.
- `libcurl` para `arp_scan` e `icmp6_scan`.
- `libcap2-bin` para configurar execucao por grupo sem login direto como root.

Exemplo em Debian/Ubuntu:

```bash
sudo apt update
sudo apt install g++ cmake libcurl4-openssl-dev libcap2-bin
```

No Windows, use uma maquina Linux, VM ou ambiente equivalente. WSL pode ter limitacoes para trafego raw/packet em interfaces fisicas.

## Ambiente testado

O projeto foi testado em um home server fisico rodando Linux, conectado diretamente a uma rede local real. Esse tipo de ambiente e o mais indicado para validar as ferramentas, porque permite acesso direto a interface de rede, trafego de camada 2, ARP, NDP, DHCP e sockets raw/packet.

O teste em hardware fisico e importante porque maquinas virtuais, WSL e ambientes conteinerizados podem limitar ou alterar o comportamento de pacotes Ethernet, broadcast, multicast IPv6 e filtros BPF.

## Compilacao

Use CMake a partir da raiz do repositorio:

```bash
cmake -S . -B build
cmake --build build
```

Os binarios sao gerados em `Bin/`.

Tambem e possivel compilar manualmente. Exemplos:

```bash
mkdir -p Bin Bin/Clients

g++ -std=c++17 -Wall -Wextra -IInclude arp_scan.cpp Source/Utils.cpp Source/Packet.cpp -lcurl -pthread -o Bin/arp_scan
g++ -std=c++17 -Wall -Wextra -IInclude icmp6_scan.cpp Source/Utils.cpp Source/Packet.cpp -lcurl -o Bin/icmp6_scan
g++ -std=c++17 -Wall -Wextra -IInclude dns_scan.cpp Source/Utils.cpp Source/Packet.cpp -o Bin/dns_scan
g++ -std=c++17 -Wall -Wextra -IInclude arp_spoofing.cpp Source/Utils.cpp Source/Packet.cpp -pthread -o Bin/arp_spoofing
g++ -std=c++17 -Wall -Wextra -IInclude ndp_spoofing.cpp Source/Utils.cpp Source/Packet.cpp -pthread -o Bin/ndp_spoofing
g++ -std=c++17 -Wall -Wextra -IInclude dhcp.cpp Source/Utils.cpp Source/Packet.cpp Source/DHCP_Starvation.cpp -pthread -o Bin/dhcp
```

Para os demais programas, use o mesmo padrao:

```bash
g++ -std=c++17 -Wall -Wextra -IInclude <arquivo>.cpp Source/Utils.cpp Source/Packet.cpp -o Bin/<nome>
```

Quando o arquivo usa `DHCP_Starvation.h`, adicione `Source/DHCP_Starvation.cpp` e `-pthread`.

## Uso

A maioria das ferramentas precisa de privilegios de rede. Existem duas formas recomendadas:

1. Executar com `sudo`, para usuarios que tenham permissao no `sudoers`, por exemplo `admin ALL=(ALL:ALL) ALL`.
2. Configurar os binarios uma vez com capabilities, permitindo que usuarios de um grupo autorizado executem sem abrir sessao como `root`.

Com `sudo`:

```bash
sudo ./Bin/arp_scan --interface eth0
sudo ./Bin/icmp6_scan --interface eth0
sudo ./Bin/dns_scan --interface eth0 --mac aa-bb-cc-dd-ee-ff
sudo ./Bin/arp_spoofing --interface eth0 --gateway 192.168.1.1 --host 192.168.1.20
```

Com grupo autorizado e capabilities:

```bash
sudo bash ./scripts/install_privileges.sh admin
./Bin/arp_scan --interface eth0
```

Se a sua distribuicao usa o grupo `sudo` ou `wheel`, troque o argumento:

```bash
sudo bash ./scripts/install_privileges.sh sudo
sudo bash ./scripts/install_privileges.sh wheel
```

O script aplica `cap_net_raw`, `cap_net_admin` e `cap_net_bind_service` aos binarios em `Bin/`, restringe a execucao ao grupo escolhido e deixa `Bin/Clients` gravavel pelo grupo. Se um usuario acabou de entrar no grupo, ele precisa sair e entrar novamente na sessao.

As ferramentas interativas pedem dados como nome da interface, IP do gateway, IP do host ou MAC alvo. Para descobrir o nome da interface:

```bash
ip link
ip addr
```

## Interface grafica

A GUI fica em `tools/network_gui.py` e usa Tkinter, que normalmente ja acompanha o Python em distribuicoes Linux.

Execute a partir da raiz:

```bash
python3 tools/network_gui.py
```

Na interface grafica voce pode:

- Rodar o build CMake.
- Informar a interface de rede.
- Executar ARP scan, ICMPv6 scan, DNS scan e Netlink.
- Acompanhar dashboard com contadores de hosts, consultas DNS, execucoes e alertas.
- Ver tabela de eventos com IP/dominio, MAC, fabricante/informacao, fonte e horario.
- Preencher gateway/host para ARP spoofing ou NDP spoofing.
- Executar demonstracoes DHCP/DHCPv6.
- Acompanhar a saida em tempo real e parar processos longos.

Para comandos que exigem privilegio, ha duas opcoes:

- Rodar `sudo bash ./scripts/install_privileges.sh admin` antes e deixar a opcao `Elevar via pkexec` desmarcada.
- Marcar `Elevar via pkexec` para a GUI pedir autenticacao grafica antes de executar os binarios.

Se `pkexec` nao estiver disponivel, execute os binarios manualmente com `sudo` ou configure capabilities com o script acima.

## Dashboard web para Ubuntu Server

Em servidores sem interface grafica, use o dashboard web em vez da GUI Tkinter. Ele usa apenas a biblioteca padrao do Python e executa os binarios em `Bin/` com argumentos controlados.

Depois de compilar:

```bash
cmake -S . -B build
cmake --build build
sudo bash ./scripts/install_privileges.sh sudo
```

Execute localmente no servidor:

```bash
python3 web/server.py
```

Para acessar de outro computador na mesma rede, por exemplo pelo navegador do Windows:

```bash
python3 web/server.py --host 0.0.0.0 --port 8080
```

Depois abra:

```text
http://IP_DO_SERVIDOR:8080
```

O dashboard web oferece:

- selecao de interface e ferramenta;
- execucao de ARP Scan, ICMPv6 Scan, DNS Monitor All Devices e Network Routes;
- monitor DNS em tempo real para todos os dispositivos visiveis na interface;
- filtro de eventos por IP, MAC, dominio ou informacao do dispositivo;
- controles para parar ou terminar o processo atual;
- console ao vivo via Server-Sent Events;
- cards de hosts, DNS, execucoes e alertas;
- tabela de eventos extraida da saida dos binarios.

Por seguranca, o servidor web nao e um terminal remoto generico: ele aceita apenas ferramentas conhecidas do projeto e argumentos esperados. Ainda assim, exponha `--host 0.0.0.0` apenas em rede confiavel.

## Arquivos de clientes DHCP

O fluxo de DHCP starvation gera arquivos binarios em `Clients/`:

- `fclients.cli`: clientes falsos que receberam lease.
- `tclients.cli`: possiveis clientes reais inferidos a partir das lacunas.
- `aclients.cli`: clientes ativos encontrados via ARP.

Os binarios existentes estao em `Bin/`, mas o codigo usa caminhos relativos como `./Clients/fclients.cli`. Portanto, ao executar a partir de `Bin`, os arquivos devem ficar em `Bin/Clients`. Ao executar a partir da raiz, crie uma pasta `Clients` na raiz.

## Observacoes importantes

- `arp_scan.cpp` e `icmp6_scan.cpp` fazem consulta externa para identificar fabricantes de MAC. Isso exige internet e pode ser limitado pela API.
- `arp_scan.cpp` tenta resolver hostname por reverse DNS/PTR. O nome so aparece se o roteador, DNS local ou arquivo de hosts tiver essa informacao.
- `dns_monitor.cpp` mostra requisicoes DNS em tempo real, mas apenas do trafego visivel para a interface do servidor. Em rede com switch comum, para observar todos os dispositivos pode ser necessario usar o servidor como gateway/DNS, configurar espelhamento de porta, bridge/AP ou capturar no ponto por onde o trafego passa.
- `arp_spoofing.cpp` e `ndp_spoofing.cpp` alteram temporariamente a percepcao de vizinhanca dos hosts envolvidos.
- `dhcp.cpp` pode consumir leases do servidor DHCP e causar indisponibilidade para novos clientes.
- `release_aclients.cpp` pode liberar o lease DHCP de um cliente real selecionado.
- O projeto e mais um laboratorio tecnico do que uma CLI pronta: varios parametros ainda estao fixos diretamente nos arquivos `.cpp`.

## Componentes internos

- `Include/Packet.h` e `Source/Packet.cpp`: classes para montar, ler e imprimir pacotes/protocolos.
- `Include/Filter.h`: offsets e macros para filtros BPF.
- `Include/Utils.h` e `Source/Utils.cpp`: descoberta de interface via Netlink, formatacao de IP/MAC e utilitarios de console.
- `Include/DHCP_Starvation.h` e `Source/DHCP_Starvation.cpp`: logica de DHCP Discover/Offer/Request/Ack e persistencia de clientes.
