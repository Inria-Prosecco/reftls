# RefTLS
## Symbolic Verification with ProVerif

[Download ProVerif from the ProVerif website](http://proverif.inria.fr).

The `.pv` files corresponding to various combinations of the protocol should be run by the command:

    proverif -lib tls-lib <filename>

They use the library `tls-lib.pvl` provided below.

### Generic Library with Threat Model and Protocol Processes

* [tls-lib.pvl](pv/tls-lib.pvl)


### ProVerif Models for TLS 1.2 and TLS 1.3

*   TLS 1.2 only: [tls12.pv](pv/tls12.pv)
*   TLS 1.3 (draft 18) DHE+PSK 0-RTT+1-RTT: [tls13-draft18-only.pv](pv/tls13-draft18-only.pv)
*   TLS 1.2 + TLS 1.3 (draft 18): [tls12-tls13-draft18.pv](pv/tls12-tls13-draft18.pv)


### Understanding the results

ProVerif generates a large amount of input, so you may want to run:
    proverif -lib tls-lib <filename> | tee results.txt | grep ^RESULT
which will put all the results in a file results.txt and summarize the success or failure of various security queries.
(Warning: verifying this model takes a long time and a significant amount of RAM even on powerful workstations.)

To understand the results, look at the comments above the queries in
the PV file.  Roughly, the "true" queries correspond to security goals
like (Forward) Secrecy, Authenticity, Replay Prevention, and Unique
Channel Identifiers for the session keys and for the various data
fragments.  The "false" queries correspond to queries that we expect
to fail; they show that our verification is tight, disabling some of
the conditions in our "true" queries would cause them to be false.

## Computational Verification with CryptoVerif

[Download CryptoVerif from the CryptoVerif website](http://cryptoverif.inria.fr).

The `.cv` files corresponding to the lemmas on the key schedule and to the protocol should be run by the command:

    cryptoverif -lib tls-lib <filename>

They use the library `tls-lib.cvl` provided below.

### Library with assumptions on TLS cryptographic primitives.

* [tls-lib.cvl](cv/tls-lib.cvl)
* [tls-primitives.cvl](cv/tls-primitives.cvl)

The library `tls-lib.cvl` has been obtained by adding the following primitives `tls-primitives.cvl` to the standard CryptoVerif library.

### Lemmas on the key schedule (Section 6.3)

* [KeySchedule1.cv](cv/KeySchedule1.cv)
* [KeySchedule2.cv](cv/KeySchedule2.cv)
* [KeySchedule3.cv](cv/KeySchedule3.cv)
* [HKDFexpand.cv](cv/HKDFexpand.cv)

### The protocol

#### Initial handshake (Section 6.4)

* [tls13-core-InitialHandshake.cv](cv/tls13-core-InitialHandshake.cv)
* [tls13-core-InitialHandshake-1RTT-only.cv](cv/tls13-core-InitialHandshake-1RTT-only.cv)

The first file deals with 0.5-RTT and 1-RTT messages. The second one supports only 1-RTT (but proves stronger properties from server to client messages).

#### Handshake with pre-shared key (Section 6.5)

* tls13-core-PSKandPSKDHE-NoCorruption.cv

#### Record Protocol (Section 6.6)

* [tls13-core-RecordProtocol.cv](cv/tls13-core-RecordProtocol.cv)
* [tls13-core-RecordProtocol-0RTT.cv](cv/tls13-core-RecordProtocol-0RTT.cv)
* [tls13-core-RecordProtocol-0RTT-badkey.cv](cv/tls13-core-RecordProtocol-0RTT-badkey.cv)

The first file is the normal record protocol. The last two are variants for 0-RTT messages: one with a replicated receiver, and one with no sender.
	
### Summary of obtained results:

    HKDFexpand
    All queries proved.
    0.024s (user 0.020s + system 0.004s), max rss 29424K
    KeySchedule1
    All queries proved.
    0.036s (user 0.028s + system 0.008s), max rss 36752K
    KeySchedule2
    All queries proved.
    0.028s (user 0.024s + system 0.004s), max rss 33808K
    KeySchedule3
    All queries proved.
    0.480s (user 0.472s + system 0.008s), max rss 53424K
    tls13-core-InitialHandshake
    All queries proved.
    115.935s (user 115.751s + system 0.184s), max rss 2171776K
    tls13-core-InitialHandshake-1RTTonly
    All queries proved.
    121.572s (user 121.412s + system 0.160s), max rss 2199040K
    tls13-core-PSKandPSKDHE-NoCorruption
    All queries proved.
    482.898s (user 482.646s + system 0.252s), max rss 1711360K
    tls13-core-RecordProtocol
    All queries proved.
    0.044s (user 0.044s + system 0.000s), max rss 31312K
    tls13-core-RecordProtocol-0RTT
    All queries proved.
    0.044s (user 0.044s + system 0.000s), max rss 31408K
    tls13-core-RecordProtocol-0RTT-badkey
    All queries proved.
    0.036s (user 0.028s + system 0.008s), max rss 30032K
