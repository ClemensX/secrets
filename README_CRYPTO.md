# Crypto
Java implementation of various cryptographic algorithms

## Dependencies
We tried to keep dependencies to a minimum. This is what we need:
 * JSON implementation of JSR 374. We use javax.json. You should be able to easily change to whatever JSON processor you prefer.
 * JUnit 5 for test cases
 * log4j for logging

## Build
 * First build the crypto project with a regular `mvn clean install`
 * fix linux extremely slow tests during build: mvn clean install -Dtest=Base64Test
 * Then add dependency to the crypto lib in the pom.xml of the project where you want to use crypto functions:
```
		<dependency>
			<groupId>de.fehrprice</groupId>
			<artifactId>crypto</artifactId>
			<version>0.0.1-SNAPSHOT</version>
		</dependency>

```

## Procedures

### Secure Communication
You can use the low-level crypto classes to do whatever crypto functionality you want. But we also provide higher level functions to securely communicate with another party. If this fits your requirements you may use or adapt this for your own projects. Some things we do different from what you may be used to - you need to check if you agree with our mindset.

All communication is based on HTTP, not HTTPS. We do not believe in the security of HTTPS and found it more rewarding to accept an unprotected environment and build secure communication on top of it.

#### Crypto Algorithms Overview

Overview of the algorithms used for end-to-end encrypted communication:

 * Base Communication Protocol: HTTP
 * Key length for private / public keys: 256 bits / 32 bytes
 * Key Agreement: ECDH / ECDSA (x25519 / Ed25519)
 * Message Exchange: AES-256

#### Private / Public Key Generation

**Permanent Keys**: Used to identify, sign and verify involved parties and their messages. Public keys must be exchanged before any communication can take place. Public Key Exchange is not part of this toolset. Usually this is something that is transmitted via email or published on a web site (for a server public key) or entered by you during registration (client public key).
 * Private Key: 32 random bytes produced by AES based PRNG (pseudo randum number generator)
 * Public Key: 32 bytes computed from private key by Ed25519

**Session Keys**: For each session a new key pair is generated in the backgound. Then the ECDH protocol (Elliptic Curve Diffie Hellman) is applied to exchange the AES session key.
 * Private Key: 32 random bytes produced by AES based PRNG (pseudo randum number generator)
 * Public Key: 32 bytes computed from private key by x25519

#### Key Agreement Details
Goal: Agree on a secret AES-256 session key that will be used to encrypt all further communication in this session. The Key agreement messages are openly transmitted and could be read by anyone.

| **AES Session Key Exchange**  | Server | Client |
| -------------             | ------ | ------ |
| Preparation (outside this protocol)              | has Client Public Key PUBc | has Server Public Key PUBs
| Initiate | | ECDH: prepare key exchange message<br> ` InitClient : name : client session public key `|
|   | | ECDSA: Sign ECDH message with private key and append to message<br> ` InitClient : name : client session public key : signature ` |
| Verify Client | receive message and verify client with PUBc
|   | Generate AES session key from client session public key and server session private key
|   | ECDH: prepare answer message<br> ` InitServer : name : server session public key `|
|   | ECDSA: Sign ECDH message with private key and append to message<br> ` InitServer : name : server session public key : signature `|
| Verify Server | | receive message and verify server with PUBs
|   | | Generate (the same) AES session key from server session public key and client session private key

#### Message Exchange with AES-256

Any message can be securely exchanged after key agreement via open channels. The AES-256 protocol prevents anyone in the outside world from reading the messages. However, DOS attacks (denial of service) are still possible. It is up to the receiver of any AES encrypted message to reject messages:
 * Message too large: Depending on scenario messages exceeding a certain size may be rejected *before* decrypting.
 * Invalid content: Third parties can send garbage messages, but without the AES session key they cannot produce meaningful messages. Any message not having the expected format should be rejected.
 
AES-256 is only defined for complete blocks of 16 bytes. To exchange arbitrary length messages these modifications have been made:
 * The very last byte of the last decrypted block always contains the number of bytes that should be discarded from the last 16-byte block. A ten byte message will have the value 6 in the last byte so that the receiver can cut the message to the exact size of ten.
 * When encrypting multiple blocks the same input block would result in the same output block. This would allow an attacker to gain some knowledge of the unencrypted input: He would know where in the input are the same blocks of 16 specific bytes. An attacker should not be able to gain such knowledge, so for every block its sequential number within the message will be added to the first half of the message before encrypting. This is reversed on the receiving side.

The above modifications are done transparently in the background by our AES implementation.