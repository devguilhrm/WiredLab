# Network

Projeto em C++ para estudo e teste de protocolos de rede em Linux. O codigo constroi, envia, recebe e interpreta pacotes de baixo nivel usando sockets `AF_PACKET`, filtros BPF e consultas Netlink/RTNETLINK.

Ele cobre principalmente Ethernet, ARP, IPv4, IPv6, ICMPv6, UDP, TCP, DNS, DHCP e NDP. Algumas ferramentas sao defensivas ou de inventario, como varredura ARP/ICMPv6 e captura de consultas DNS. Outras sao ofensivas ou disruptivas, como ARP spoofing, NDP spoofing e DHCP starvation.

> Use somente em redes proprias, laboratorios ou ambientes onde voce tem autorizacao explicita. Algumas ferramentas podem causar indisponibilidade, alterar tabelas ARP/NDP ou liberar leases DHCP.

## Para que serve

Este projeto serve como um laboratorio de redes em C++ para:

- Descobrir hosts IPv4 na rede local com ARP.
- Descobrir hosts IPv6 no link local com ICMPv6 multicast.
- Observar consultas DNS feitas por um dispositivo especifico.
- Demonstrar ARP spoofing e NDP spoofing entre um host e o gateway.
- Demonstrar DHCP starvation e gerenciamento/liberacao dos leases gerados.
- Montar e imprimir pacotes DNS/DHCP/DHCPv6 manualmente.
- Consultar informacoes do kernel Linux via Netlink.

## Estrutura

```text
.
|-- Include/              # Headers de pacotes, filtros, utilitarios e DHCP starvation
|-- Source/               # Implementacoes compartilhadas
|-- Bin/                  # Binarios Linux ja gerados e arquivos de clientes DHCP
|-- tools/                # Interface grafica e utilitarios de operacao
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
| `arp_scan.cpp` | Varre a sub-rede IPv4 da interface usando requisicoes ARP. Mostra IP, MAC e, quando possivel, fabricante via `api.macvendors.com`. |
| `icmp6_scan.cpp` | Envia ICMPv6 Echo Request para `ff02::1` e lista hosts IPv6 que respondem. Tambem tenta identificar fabricante pelo MAC. |
| `dns_scan.cpp` | Captura trafego DNS de um MAC informado e imprime os nomes consultados. Suporta DNS sobre UDP e TCP em IPv4/IPv6. |
| `arp_spoofing.cpp` | Faz ARP spoofing entre gateway e host informados. Ao parar, tenta restaurar as entradas ARP corretas. |
| `ndp_spoofing.cpp` | Faz spoofing NDP/Neighbor Advertisement em IPv6 entre gateway e host. Ao parar, tenta restaurar as entradas corretas. |
| `dhcp.cpp` | Executa DHCP starvation com clientes falsos. Aceita `--interface` e salva listas em `./Clients/*.cli`. |
| `release_fclients.cpp` | Envia DHCP RELEASE para os clientes falsos salvos em `./Clients/fclients.cli`. Aceita `--interface`. |
| `release_aclients.cpp` | Lista clientes ativos salvos em `./Clients/aclients.cli` e envia DHCP RELEASE para o cliente selecionado. Aceita `--interface`. |
| `dhcpv6.cpp` | Demonstra a montagem de um DHCPv6 Information Request. Aceita `--interface`, mas ainda contem enderecos IPv6 fixos no codigo. |
| `dhcp_server.cpp` | Teste minimo de bind na porta de servidor DHCP. Aceita `--interface`. |
| `dns_rr.cpp` | Demonstra consulta DNS via TCP/IPv6 para root server, consultando `www.gov.br`. Possui valores fixos no codigo. |
| `netlink.cpp` | Consulta e imprime informacoes de rotas, interfaces e enderecos via Netlink/RTNETLINK. |

## Arquitetura atual

O projeto agora esta organizado em tres camadas:

- Nucleo C++: `Include/Packet.h`, `Source/Packet.cpp`, `Include/Utils.h` e `Source/Utils.cpp` concentram montagem, leitura, formatacao de pacotes e descoberta de interfaces.
- Ferramentas: cada arquivo `*.cpp` na raiz e um executavel pequeno que usa o nucleo para uma tarefa especifica.
- Orquestracao: `CMakeLists.txt` compila todos os executaveis e `tools/network_gui.py` fornece uma interface grafica para configurar parametros, executar binarios e acompanhar a saida.

O header `Include/CLI.h` centraliza leitura de argumentos como `--interface`, `--gateway`, `--host` e `--mac`. Com isso, as ferramentas continuam funcionando em modo interativo, mas tambem podem ser chamadas por scripts ou pela GUI.

## Requisitos

- Linux. Os headers e chamadas usadas sao especificos de Linux (`linux/if_packet.h`, `linux/filter.h`, `linux/rtnetlink.h`).
- Permissao de root ou capacidades equivalentes para sockets raw/packet.
- `g++` com suporte a C++17.
- `libcurl` para `arp_scan` e `icmp6_scan`.

Exemplo em Debian/Ubuntu:

```bash
sudo apt update
sudo apt install g++ libcurl4-openssl-dev
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

A maioria das ferramentas precisa ser executada como root:

```bash
sudo ./Bin/arp_scan --interface eth0
sudo ./Bin/icmp6_scan --interface eth0
sudo ./Bin/dns_scan --interface eth0 --mac aa-bb-cc-dd-ee-ff
sudo ./Bin/arp_spoofing --interface eth0 --gateway 192.168.1.1 --host 192.168.1.20
```

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
- Preencher gateway/host para ARP spoofing ou NDP spoofing.
- Executar demonstracoes DHCP/DHCPv6.
- Acompanhar a saida em tempo real e parar processos longos.

Para comandos que exigem privilegio, a GUI tenta usar `pkexec` quando a opcao de autenticacao esta ativa. Se `pkexec` nao estiver disponivel, execute os binarios manualmente com `sudo` ou rode a GUI em um ambiente com permissao adequada.

## Arquivos de clientes DHCP

O fluxo de DHCP starvation gera arquivos binarios em `Clients/`:

- `fclients.cli`: clientes falsos que receberam lease.
- `tclients.cli`: possiveis clientes reais inferidos a partir das lacunas.
- `aclients.cli`: clientes ativos encontrados via ARP.

Os binarios existentes estao em `Bin/`, mas o codigo usa caminhos relativos como `./Clients/fclients.cli`. Portanto, ao executar a partir de `Bin`, os arquivos devem ficar em `Bin/Clients`. Ao executar a partir da raiz, crie uma pasta `Clients` na raiz.

## Observacoes importantes

- `arp_scan.cpp` e `icmp6_scan.cpp` fazem consulta externa para identificar fabricantes de MAC. Isso exige internet e pode ser limitado pela API.
- `arp_spoofing.cpp` e `ndp_spoofing.cpp` alteram temporariamente a percepcao de vizinhanca dos hosts envolvidos.
- `dhcp.cpp` pode consumir leases do servidor DHCP e causar indisponibilidade para novos clientes.
- `release_aclients.cpp` pode liberar o lease DHCP de um cliente real selecionado.
- O projeto e mais um laboratorio tecnico do que uma CLI pronta: varios parametros ainda estao fixos diretamente nos arquivos `.cpp`.

## Componentes internos

- `Include/Packet.h` e `Source/Packet.cpp`: classes para montar, ler e imprimir pacotes/protocolos.
- `Include/Filter.h`: offsets e macros para filtros BPF.
- `Include/Utils.h` e `Source/Utils.cpp`: descoberta de interface via Netlink, formatacao de IP/MAC e utilitarios de console.
- `Include/DHCP_Starvation.h` e `Source/DHCP_Starvation.cpp`: logica de DHCP Discover/Offer/Request/Ack e persistencia de clientes.
# WiredLab
