# WiredLab

WiredLab e um dashboard Python para monitoramento de rede em Linux/Ubuntu Server. Ele mostra dispositivos IPv4/IPv6 encontrados na rede e requisicoes DNS visiveis em tempo real pelo navegador.

O projeto agora e Python-only: nao usa C++, CMake nem binarios em `Bin/`.

## Funcoes

| Funcao no web app | Modulo Python | O que faz |
| --- | --- | --- |
| ARP Scan | `wiredlab.scanners.arp` | Varre a rede IPv4 local e mostra IP, MAC, hostname/PTR quando disponivel e fabricante do MAC. |
| ICMPv6 Scan | `wiredlab.scanners.icmp6` | Descobre hosts IPv6 no link local usando ICMPv6 multicast. |
| DNS Monitor All Devices | `wiredlab.scanners.dns` | Captura requisicoes DNS visiveis na interface e mostra origem, MAC, transporte e dominio. |
| Network Routes | `wiredlab.scanners.routes` | Lista interfaces, enderecos e rotas usando os comandos `ip`. |

> Use somente em redes proprias, laboratorios ou ambientes onde voce tem autorizacao. Nao exponha o dashboard diretamente para a internet.

## Limite importante do DNS Monitor

O monitor DNS so enxerga trafego que passa pela interface do servidor.

Para ver requisicoes DNS de todos os dispositivos da rede, o servidor precisa estar em um ponto onde esse trafego seja visivel, por exemplo:

- o servidor e o DNS usado pelos clientes;
- o servidor e o gateway/roteador;
- a interface esta em bridge/AP;
- o switch/roteador envia uma copia do trafego por port mirror;
- os clientes nao estao usando DNS criptografado como DoH/DoT fora do caminho monitorado.

Se o dashboard abrir mas o DNS Monitor ficar vazio, normalmente o trafego DNS nao esta passando pela interface monitorada.

## Requisitos

- Ubuntu Server ou outra distribuicao Linux.
- Python 3.10 ou superior.
- `python3-venv`
- `python3-pip`
- `iproute2`
- Acesso `sudo` para captura raw de pacotes.

Instale os pacotes base:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip iproute2
```

## Instalacao

Clone o projeto:

```bash
git clone https://github.com/devguilhrm/WiredLab.git
cd WiredLab
```

Crie o ambiente Python:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Executando o dashboard web

Como ARP, ICMPv6 e DNS monitor usam pacotes raw, rode o servidor com `sudo`:

```bash
sudo .venv/bin/python web/server.py --host 0.0.0.0 --port 8080
```

Para deixar rodando em segundo plano:

```bash
nohup sudo .venv/bin/python web/server.py --host 0.0.0.0 --port 8080 > wiredlab-web.log 2>&1 &
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

Se o firewall UFW estiver ativo:

```bash
sudo ufw allow 8080/tcp
sudo ufw status
```

## Como usar

1. Abra o dashboard web.
2. Escolha a interface correta, por exemplo `wlp1s0`, `enp2s0`, `eth0` ou outra mostrada por `ip addr`.
3. Clique em `ARP Scan` para listar dispositivos IPv4 conectados na rede local.
4. Clique em `ICMPv6 Scan` para procurar dispositivos IPv6 no link local.
5. Clique em `DNS Monitor All Devices` para acompanhar requisicoes DNS em tempo real.
6. Use o campo de filtro para procurar por IP, MAC, hostname, dominio ou fabricante.
7. Clique em `Network Routes` para ver interfaces e rotas.

## Execucao manual

Tambem e possivel usar a CLI Python diretamente:

```bash
sudo .venv/bin/python -m wiredlab.cli arp-scan --interface wlp1s0
sudo .venv/bin/python -m wiredlab.cli icmp6-scan --interface wlp1s0
sudo .venv/bin/python -m wiredlab.cli dns-monitor --interface wlp1s0
.venv/bin/python -m wiredlab.cli routes
```

Substitua `wlp1s0` pela interface real do seu servidor.

## Estrutura

```text
.
|-- requirements.txt
|-- wiredlab/
|   |-- cli.py
|   |-- hostname.py
|   |-- interfaces.py
|   |-- vendor.py
|   `-- scanners/
|       |-- arp.py
|       |-- dns.py
|       |-- icmp6.py
|       `-- routes.py
`-- web/
    |-- server.py
    |-- index.html
    `-- static/
        |-- app.js
        `-- styles.css
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

### Erro de permissao

Se aparecer erro de permissao, execute com `sudo`:

```bash
sudo .venv/bin/python web/server.py --host 0.0.0.0 --port 8080
```

### Interface invalida

Liste as interfaces:

```bash
ip addr
```

Use uma interface ativa, com `UP` e endereco IP.

### Hostname nao aparece

O hostname depende de DNS reverso/PTR, cache local, roteador ou registros da rede. Muitos dispositivos nao publicam esse nome, entao e normal aparecer somente IP e MAC.

### DNS Monitor nao mostra todos os dispositivos

Confirme que o servidor consegue enxergar o trafego DNS dos clientes. Em uma rede comum, um computador conectado como cliente normal geralmente so ve o proprio trafego e broadcast/multicast. Para monitorar todos os dispositivos, coloque o servidor como DNS/gateway, use bridge/AP ou configure port mirroring no switch/roteador.

## Seguranca

O dashboard executa captura de rede e deve ficar restrito a rede local confiavel.

Recomendacoes:

- nao publicar a porta 8080 na internet;
- usar firewall permitindo acesso apenas da LAN;
- executar somente em redes autorizadas;
- preferir um usuario administrativo controlado no servidor;
- revisar os logs depois dos testes.

## Ambiente testado

O projeto foi testado em um home server fisico com Ubuntu Server, acessando o dashboard por outro computador na mesma rede local.
