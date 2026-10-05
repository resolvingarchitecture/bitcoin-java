[![Build Status](https://travis-ci.com/resolvingarchitecture/bitcoin-java.svg?branch=master)](https://travis-ci.com/resolvingarchitecture/bitcoin-java)

# Resolving Architecture - Bitcoin Client - Java
Bitcoin Client as a Service

Provides a higher-layer API as a Service for a local Bitcoin Core node via its RPC API.
No support is provided for remote nodes nor SPV clients, neither are they expected to be in the future.

## Authors / Developers
* objectorange (Brian Taylor) - [GitHub](https://github.com/objectorange) | [LinkedIn](https://www.linkedin.com/in/decentralizationarchitect/) | brian@resolvingarchitecture.io PGP: 2FA3 9B12 DA50 BD7C E43C 3031 A15D FABB 2579 77DC

## Licensing
MIT License - see [LICENSE](LICENSE).

## Motivation
With plenty of BTC wallets on the market and Decentralized Exchanges, why build another Bitcoin Client?

Most wallets are questionably decentralized, the best arguably being Samourai Wallet.
Samourai Wallet is an SPV wallet not using a full local node and the local Bitcoin Core wallet
is difficult for the average internet user to use. In addition, current wallets are not very censorship-resistance
through supporting proxies that can be used to route around network blocks.
The ability to use other network protocols, e.g. Tor, I2P, Bluetooth, 1M5, LiFi needs to be supported.

## Design
BitcoinService is designed to work with the RA Service Bus. It sends and expects to receive messages using it.
It currently depends on the ra.http.HTTPService running as a client only (for local Bitcoin node RPC).

[BitcoinJ](https://bitcoinj.org/) was evaluated to be embedded in the service. It creates an SPV Bitcoin node implemented in Java
on your machine and connects out using DNS (TCP), HTTP, and Tor on its own terms. This is undesirable with this Bitcoin Client
as a service as this should be the integrator's choice while also supporting a full/pruned node locally. The initial
decision was to forego this library only connecting to a local Bitcoin Core node using its HTTP RPC interface. But this
doesn't allow supporting end users where Bitcoin Core can not be installed very easily. Thus, this library is used
when a local Bitcoin Core node is not detected yet extends the library to route all communications through the RA
Network Manager Service so that multiple network protocols can be used to connect to remote Bitcoin Core nodes
through supported network protocols.

Bitcoin JSON-RPC interface is used for all communications to the local Bitcoin node.

Local Bitcoin node can be a full node or a pruned node but when pruned, functionality will become limited.
Open payment channels that will be de-referenced upon pruning will be lost due to de-referencing.
It's recommended to keep the pruning to a minimum by supporting the largest bitcoin node size possible while minimizing how long payment channels are left open.
Future versions of this component will provide auto notifications of payments channels that would be affected by a prune when registered with this service.

## Local Bitcoin Core

### Configuration
Ensure contents of bitcoin.conf provided in project config folder are in the bitcoin.conf file located in the .bitcoin
directory within your home directory, e.g. ~/.bitcoin/bitcoin.conf. This enables the JSON RPC - the ability for communications
between the local Bitcoin node and this service.

* If your bitcoin node is not located in the following directory: /home/[username here]/snap/bitcoin-core/common/.bitcoin/
then set the bitcoin home directory by passing it in as the parameter: ra.btc.directory
* In bitcoin.conf, set the following:
  * server=1
  * rest=1
  * rpcuser={username}
  * rpcpassword={passphrase}

### Implementation
RPC operations implemented using the following API documentation: https://developer.bitcoin.org/reference/rpc/index.html

## Remote Bitcoin Core

### Configuration

### Implementation

## Release Notes

### 1.0 - Local Bitcoin Core Node integration
* Send and Receive Bitcoins via the local Bitcoin Core node verified.

### 2.0 - Remote Bitcoin Core Node Integration via BitcoinJ networking
* In progress

### 3.0 - Remote Bitcoin Core Node Integration via RA Network Manager
* Uses a modified BitcoinJ version where its network stack is replaced with the RA Network Manager
* TBD
