# Docker stacks

Each stack runs a Neurai node, electrs-neurai (`tcp://`, `ssl://`, `wss://`) and a
`letsencrypt` service that gets a free certificate through the Cloudflare API
when a domain is configured.

| Stack      | Node                                      | electrs ports (tcp / ssl / wss) | Node P2P / RPC |
|------------|-------------------------------------------|---------------------------------|----------------|
| `mainnet/` | official `neuraiproject/neurai-node:v1.0.7` | 50001 / 50002 / 50004           | 19000 / 19001  |
| `testnet/` | built from the `DePIN-Test` branch         | 60001 / 60002 / 60004           | 19100 / 19101  |

The default ports differ, so both stacks can run on the same host. Node RPC and
P2P are published on `127.0.0.1` only (see below to let other nodes connect in).

## Start

```bash
cd docker/mainnet            # or docker/testnet
cp .env.example .env         # .env is not committed
# edit .env: NEURAI_RPC_PASSWORD (required), DOMAIN (optional)
docker compose up -d --build
docker compose logs -f electrs
```

electrs starts once the node answers RPC, and indexes while the node syncs.

## Configuration

Everything is set in `.env`; its comments describe each setting.

* **RPC credentials** (`NEURAI_RPC_USER`, `NEURAI_RPC_PASSWORD`) are used by both
  the node and electrs, and apply on every start. On mainnet,
  [node-entrypoint.sh](node-entrypoint.sh) updates them in the node's
  `neurai.conf`, which the official image only writes on its first start.
* **Other mainnet node settings** (indexes, `dbcache`, ...) apply on the node's
  first start only; later, edit `neurai.conf` in the `neurai_mainnet_data`
  volume. The testnet node rewrites its `neurai.conf` on every start.
* **electrs options** can be set as `ELECTRS_<OPTION>` in the `environment` of
  the `electrs` service (see `electrs-neurai --help`). Empty values keep
  electrs' default.

## Several stacks on one host

Each stack is named after its directory (`mainnet`, `testnet`), or after
`COMPOSE_PROJECT_NAME` in its `.env`: its containers are `<name>-node`,
`<name>-electrs` and `<name>-letsencrypt`, and its volumes and network are
prefixed with `<name>`. A copy of a directory is therefore another stack:

```bash
cp -r docker/mainnet docker/mainnet-b
cd docker/mainnet-b && cp .env.example .env
# edit .env: other ports (ELECTRUM_*_PORT, NODE_P2P_PORT, NODE_RPC_PORT)
docker compose up -d --build
```

Only the ports published on the host can collide, never the nodes or electrs
inside their containers (the node must keep `listen=1`: electrs downloads
blocks over P2P inside the stack). Each stack needs its own ports, or its own
address of the host: `ELECTRUM_LISTEN` publishes the Electrum ports on one
address only (e.g. `203.0.113.5`, `[2001:db8::5]` or `127.0.0.1`) instead of
every address. An empty `NODE_P2P_PORT` or `NODE_RPC_PORT` lets Docker pick a
free port.

The node's P2P port is published on `127.0.0.1` only (`NODE_P2P_LISTEN`):
the node connects out to its peers, but other nodes can't connect in. Set
`NODE_P2P_LISTEN=0.0.0.0` (or a public address of the host) to accept them.
Docker's published ports are not filtered by the host's firewall (ufw), so
this setting is what keeps the port closed.

Setting `COMPOSE_PROJECT_NAME` on an existing stack starts it with new, empty
volumes: the node syncs again. The containers used to be named
`neurai-electrs-mainnet-node`, `neurai-mainnet-electrs`, ...; the next
`docker compose up -d` replaces them with the new names, keeping the volumes.

Several electrs can also share one node (each with its own DB volume and
ports), pointing `--daemon-rpc-addr` and `--daemon-p2p-addr` at it.

## Domain and certificate

Without `DOMAIN`, electrs creates a self-signed certificate. electrum-neurai
accepts it on first use; browsers and most WebSocket clients do not.

With `DOMAIN=electrum.example.org` and `CLOUDFLARE_API_TOKEN`, the
`letsencrypt` service gets a Let's Encrypt certificate through the Cloudflare
API: certbot proves control of the domain with a TXT record (DNS-01), so no
port needs to be open, and a web server already on port 80 is left alone.

1. The domain must be in your Cloudflare account. Point its `A` record (and
   `AAAA`, if any) at the server, set to **DNS only** (grey cloud): `ssl://`
   cannot go through Cloudflare's proxy.
2. Create the token: dash.cloudflare.com → My Profile → API Tokens → Create
   Token → template **Edit zone DNS** → Zone Resources: Include, Specific
   zone, the zone of `DOMAIN`. Put it in `CLOUDFLARE_API_TOKEN`.
3. Optionally, test with `LETSENCRYPT_STAGING=1` first (untrusted
   certificates, no rate limits), then set it back to `0`.
4. `docker compose up -d`, then check `docker compose logs letsencrypt`.

Before each request the service checks, with the token, that `DOMAIN` is in a
Cloudflare zone the token can see; if not, it says so and asks Let's Encrypt
for nothing. It also warns when the domain has no `A`/`AAAA`/`CNAME` record, or
when the record is proxied.

The service checks the certificate twice a day and renews it when it is due.
electrs reloads the certificate files when they change, without restarting:
connections opened after that use the new certificate.

electrs also reports `tcp://`, `ssl://` and `wss://` on the domain in
`server.features`, unless `ELECTRS_REPORT_SERVICES` says otherwise.

Clients:

```bash
electrum --oneserver --server electrum.example.org:50002:s   # electrum-neurai
```

and `wss://electrum.example.org:50004` from web clients, or
`wss://electrum.example.org` with `ELECTRUM_WSS_PORT=443`.

## Files

* [electrs-entrypoint.sh](electrs-entrypoint.sh): entrypoint of the electrs
  image. It writes the RPC credentials to electrs' config file, derives the
  reported services from `DOMAIN`, and creates the self-signed certificate.
* [letsencrypt.sh](letsencrypt.sh): the `letsencrypt` service, run in the
  `certbot/dns-cloudflare` image.
* [node-entrypoint.sh](node-entrypoint.sh): keeps the mainnet node's RPC
  credentials in step with `.env`.
* `mainnet/electrs/Dockerfile`, `testnet/electrs/Dockerfile`: build electrs from
  a GitHub ref instead of the local tree (see the build modes in the compose
  files).
* `testnet/node/`: builds the testnet node from source.
