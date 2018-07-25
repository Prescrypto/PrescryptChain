
# rxchain - a Python - SQL based lightweight, cryptographically enabled, centralised blockchain implementation – Originally forked from NaiveChain and ported into Python, but no original code remains.

### Motivation
All the current implementations of blockchains are tightly coupled with the larger context and problems they (e.g. Bitcoin or Ethereum) are trying to solve. This leaves little room to implement different solutions. Especially source-code-wisely. This project is an attempt to provide a lightweight concise and simple implementation of a blockchain as possible, completely designed around electronic medical prescriptions.


### What is blockchain
[From Wikipedia](https://en.wikipedia.org/wiki/Blockchain_(database)) : Blockchain is a new database technology that maintains a continuously-growing list of records called blocks secured from tampering and revision. I encourage the reader to thoroughly understand the different key aspects of Blockchain technology form this article: https://medium.com/@sbmeunier/blockchain-technology-a-very-special-kind-of-distributed-database-e63d00781118


### Key concepts of rxchain
 *rxchain* is focused on the specifics of cryptography (which can be linked to electronic identities) and immutability, achieved by Blocks that couple prescription's merkle trees and can verify integrity easily.
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
```


### HTTP API
##### Get blockchain
```
curl http://localhost:8080/api/v1/block
```
##### Create block
```
# Public Key is an binari exadecimal representation  of publick_key made by rsa python library
curl -X POST \
  http://127.0.0.1:8000/api/v1/rx-endpoint/ \
  -H 'Content-Type: application/json' \
  -d '{
  "diagnosis": "Diagnostico de Ojo Irritado",
  "location": "México, CDMX",
  "medic_cedula": "465713",
  "medic_hospital": "Privado",
  "medic_name": "Juan Alberto Torres García",
  "medications": [
    {
      "instructions": "Artelac RDules",
      "presentation": "DUSTALOX (KETOROLACO TROMETAMINA  5 mg / ml 1 SOL 5 ml)"
    }
  ],
  "patient_age": 29,
  "patient_name": "Jesus",
  "public_key": "63636f70795f7265670a5f7265636f6e7374727563746f720a70310a28637273612e6b65790a5075626c69634b65790a70320a635f5f6275696c74696e5f5f0a6f626a6563740a70330a4e745270340a284c373435313530383630343332393237323237393336343532383430323735313630383337373839333331383033363932383838383034323630323635393130383336383335353931353533323533343238353732343832333830373537333939343637313337383133363633313537303432363933373330313136353533373433333638333830333634393839383937363238373033343934394c0a4936353533370a74622e",
  "timestamp": "2018-02-01T21:59:19.454752"
}'

```

##### See the navigator
```
GO to  http://127.0.0.1:8000/
```
