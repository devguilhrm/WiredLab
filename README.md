# WiredLab

WiredLab e um projeto de monitoramento de rede para Linux/Ubuntu Server. Ele foi pensado para rodar em um home server fisico e mostrar, pelo navegador, dispositivos IPv4/IPv6 encontrados na rede e requisicoes DNS visiveis em tempo real.

O foco atual do sistema e simples:

- descobrir hosts IPv4 com ARP;
- descobrir hosts IPv6 com ICMPv6;
- acompanhar requisicoes DNS em tempo real;
- filtrar eventos por dispositivo, IP, MAC, dominio ou texto;
- consultar rotas e interfaces pelo Netlink do Linux.

> Use somente em redes proprias, laboratorios ou ambientes onde voce tem autorizacao. Nao exponha o dashboard diretamente para a internet.

## Status do projeto

Este repositorio foi ajustado para manter no dashboard web apenas as funcoes funcionais:

| Funcao no web app | Binario | O que faz |
| --- | --- | --- |
| ARP Scan | `arp_scan` | Varre a rede IPv4 local e mostra IP, MAC, hostname/PTR quando disponivel e fabricante do MAC. |
| ICMPv6 Scan | `icmp6_scan` | Descobre hosts IPv6 no link local usando ICMPv6 multicast. |
| DNS Monitor All Devices | `dns_monitor` | Captura requisicoes DNS visiveis na interface e mostra origem, MAC, transporte e dominio. |
| Network Routes | `netlink` | Lista informacoes de rede, rotas, interfaces e enderecos pelo kernel Linux. |

Existem outros arquivos C++ no repositorio como codigo de estudo/laboratorio, mas eles nao sao expostos no dashboard principal.

## Importante sobre o DNS Monitor

O monitor DNS so enxerga trafego que passa pela interface do servidor.

Para ver requisicoes DNS de todos os dispositivos da rede, o servidor precisa estar em um ponto onde esse trafego seja visivel, por exemplo:

- o servidor e o DNS usado pelos clientes;
- o servidor e o gateway/roteador;
- a interface esta em bridge/AP;
- o switch/roteador envia uma copia do trafego por port mirror;
- os clientes nao estao usando DNS criptografado como DoH/DoT fora do caminho monitorado.

Se o dashboard abrir mas o DNS Monitor ficar vazio, normalmente o problema nao e o codigo: o trafego DNS provavelmente nao esta passando pela interface monitorada.

## Requisitos

- Ubuntu Server ou outra distribuicao Linux.
- `git`
- `g++`
- `cmake`
- `python3`
- `libcurl4-openssl-dev`
- `libcap2-bin`
- Acesso `sudo` para configurar capabilities dos binarios.

Instalacao dos pacotes no Ubuntu:

```bash
sudo apt update
sudo apt install -y git g++ cmake python3 libcurl4-openssl-dev libcap2-bin
```

## Instalacao

Clone o projeto:

```bash
git clone https://github.com/devguilhrm/WiredLab.git
cd WiredLab
```

Compile os binarios:

```bash
cmake -S . -B build
cmake --build build
```

Os executaveis sao gerados em `Bin/`.

Configure as permissoes para executar os binarios sem precisar logar como `root`:

```bash
sudo bash ./scripts/install_privileges.sh sudo
```

O script aplica capabilities nos binarios funcionais para permitir captura e envio de pacotes de rede.

## Executando o dashboard web

Em servidor sem interface grafica, use o dashboard web:

```bash
nohup python3 web/server.py --host 0.0.0.0 --port 8080 > wiredlab-web.log 2>&1 &
```

Depois acesse no navegador de outro computador da mesma rede:

```text
http://IP_DO_SERVIDOR:8080
```

Exemplo:

```text
http://192.168.1.222:8080
```

Para conferir o IP do servidor:

```bash
ip addr
```

Para conferir se o servidor web esta ouvindo na porta 8080:

```bash
ss -ltnp | grep 8080
```

Se o firewall UFW estiver ativo:

```bash
sudo ufw allow 8080/tcp
sudo ufw status
```

## Como usar

1. Abra o dashboard web.
2. Escolha a interface de rede correta, por exemplo `wlp1s0`, `enp2s0`, `eth0` ou outra mostrada por `ip addr`.
3. Clique em `ARP Scan` para listar dispositivos IPv4 conectados na rede local.
4. Clique em `ICMPv6 Scan` para procurar dispositivos IPv6 no link local.
5. Clique em `DNS Monitor All Devices` para acompanhar requisicoes DNS em tempo real.
6. Use o campo de filtro para procurar por IP, MAC, hostname, dominio ou fabricante.
7. Clique em `Network Routes` para ver informacoes de rotas e interfaces.

## Execucao manual dos binarios

Tambem e possivel executar as ferramentas diretamente pelo terminal:

```bash
sudo ./Bin/arp_scan --interface wlp1s0
sudo ./Bin/icmp6_scan --interface wlp1s0
sudo ./Bin/dns_monitor --interface wlp1s0
./Bin/netlink
```

Substitua `wlp1s0` pela interface real do seu servidor.

## Estrutura do projeto

```text
.
|-- Include/              # Headers compartilhados
|-- Source/               # Implementacoes compartilhadas
|-- scripts/              # Scripts de permissao e suporte
|-- web/                  # Dashboard web
|   |-- server.py         # Servidor HTTP/API
|   |-- index.html        # Interface principal
|   `-- static/           # JS e CSS
|-- tools/                # Ferramentas auxiliares
|-- CMakeLists.txt        # Build CMake
|-- arp_scan.cpp          # Scan IPv4 por ARP
|-- icmp6_scan.cpp        # Scan IPv6 por ICMPv6
|-- dns_monitor.cpp       # Monitor DNS em tempo real
`-- netlink.cpp           # Diagnostico Netlink
```

## Solucao de problemas

### O dashboard nao abre

Verifique se o servidor esta rodando:

```bash
ss -ltnp | grep 8080
```

Verifique o log:

```bash
tail -f wiredlab-web.log
```

Libere a porta no UFW:

```bash
sudo ufw allow 8080/tcp
```

Use o IP real do servidor, nao `127.0.0.1`, quando estiver acessando de outro computador.

### Porta 8080 ja esta em uso

Veja o processo:

```bash
ss -ltnp | grep 8080
```

Finalize o servidor antigo:

```bash
pkill -f 'web/server.py'
```

Inicie novamente:

```bash
nohup python3 web/server.py --host 0.0.0.0 --port 8080 > wiredlab-web.log 2>&1 &
```

### Erro "Operation not permitted"

Recompile e aplique as capabilities novamente:

```bash
cmake --build build
sudo bash ./scripts/install_privileges.sh sudo
```

### Interface invalida

Liste as interfaces:

```bash
ip addr
```

Use uma interface ativa, com `UP` e endereco IP. Exemplo:

```bash
sudo ./Bin/arp_scan --interface wlp1s0
```

### Hostname nao aparece

O hostname depende de DNS reverso/PTR, cache local, roteador ou registros da rede. Muitos dispositivos nao publicam esse nome, entao e normal aparecer somente IP e MAC.

### DNS Monitor nao mostra todos os dispositivos

Confirme que o servidor consegue enxergar o trafego DNS dos clientes. Em uma rede comum, um computador conectado como cliente normal geralmente so ve o proprio trafego e broadcast/multicast. Para monitorar todos os dispositivos, coloque o servidor como DNS/gateway, use bridge/AP ou configure port mirroring no switch/roteador.

## Seguranca

O dashboard executa ferramentas de baixo nivel e deve ficar restrito a rede local confiavel.

Recomendacoes:

- nao publicar a porta 8080 na internet;
- usar firewall permitindo acesso apenas da LAN;
- executar somente em redes autorizadas;
- preferir um usuario administrativo controlado no servidor;
- revisar os logs depois dos testes.

## Ambiente testado

O projeto foi testado em um home server fisico com Ubuntu Server, acessando o dashboard por outro computador na mesma rede local.
