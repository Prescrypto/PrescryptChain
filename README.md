
# CrytoVault - a Python - SQL based lightweight, cryptographically enabled, centralised blockchain implementation – Originally forked from NaiveChain and ported into Python, but no original code remains.

### Motivation
All the current implementations of blockchains are tightly coupled with the larger context and problems they (e.g. Bitcoin or Ethereum) are trying to solve. This leaves little room to implement different solutions. Especially source-code-wisely. This project is an attempt to provide a lightweight concise and simple implementation of a blockchain as possible, completely designed around electronic medical prescriptions.


### What is blockchain
[From Wikipedia](https://en.wikipedia.org/wiki/Blockchain_(database)) : Blockchain is a new database technology that maintains a continuously-growing list of records called blocks secured from tampering and revision. I encourage the reader to thoroughly understand the different key aspects of Blockchain technology form this article: https://medium.com/@sbmeunier/blockchain-technology-a-very-special-kind-of-distributed-database-e63d00781118


### Key concepts of CrytoVault
 *CrytoVault* is focused on the specifics of cryptography (which can be linked to electronic identities) and immutability, achieved by Blocks that couple prescription's merkle trees and can verify integrity easily.
* HTTP interface to control the node
* At the moment it is a centralised chain of blocks, the block's merkle root can be anchored with Proof of Existence to any particular distributed Blockchain (in a similar way to Factom's white paper) (https://github.com/FactomProject/FactomDocs/blob/master/whitepaper.md)
* At the moment data is persisted in an SQL implementation
* Access to the database is enabled by Asymetric Cryptography
* Proof-of-work or proof-of-stake: This is the next step, a proof of work is a useful way to stop fake data from being created
* After proof of work has been developed, a distributed version can be built

### Quick start
(set up node and mine 1 block)
```
vagrant up
get server running and start creating stuff
vagrant ssh

$ cd /vagrant/prescryptchain
$ python manage.py migrate
$ python manage.py loaddata ./fixtures/initial_data.json
$ python manage.py runserver [::]:8000

# Run this in another console
$ python manage.py rqworker high default low
```


### HTTP API

##### Get blockchain
```
curl http://127.0.0.1:8000/api/v1/block
```
