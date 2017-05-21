# RefTLS

## Symbolic Verification with ProVerif

[Download ProVerif from the ProVerif website](http://proverif.inria.fr).

    tls13-draft18.pv

A full model of TLS 1.3 Draft-18 with PSK-based 0-RTT, 0.5-RTT, and 1-RTT.

This model can be analyzed by running the command:
    proverif tls13-draft18.pv | tee results.txt | grep ^RESULT
which will put all the results in a file results.txt and summarize the success or failure of various security queries.
(Warning: verifying this model takes a long time and a significant amount of RAM even on powerful workstations.)

To understand the results, look in the PV file.
Roughly, the "true" queries correspond to security goals like (Forward) Secrecy, Authenticity, Replay Prevention, and Unique Channel Identifiers for the session keys and for the various data fragments.  The "false" queries correspond to queries that we expect to fail;
they show that our verification is tight, disabling some of the conditions in our "true" queries would cause them to be false.


## Computational Verification with CryptoVerif

[Download CryptoVerif from the CryptoVerif website](http://cryptoverif.inria.fr).

The `.cv` files corresponding to the lemmas on the key schedule and to the protocol should be run by the command:

    cryptoverif -lib tls-lib <filename>

They use the library `tls-lib.cvl` provided below.

### Library with assumptions on TLS cryptographic primitives.

* tls-lib.cvl
* tls-primitives.cvl

The library `tls-lib.cvl` has been obtained by adding the following primitives `tls-primitives.cvl` to the standard CryptoVerif library.

### Lemmas on the key schedule (Section 6.3)

* KeySchedule1.cv
* KeySchedule2.cv
* KeySchedule3.cv
* HKDFexpand.cv

### The protocol

#### Initial handshake (Section 6.4)

* tls13-core-InitialHandshake.cv
* tls13-core-InitialHandshake-1RTT-only.cv

The first file deals with 0.5-RTT and 1-RTT messages. The second one supports only 1-RTT (but proves stronger properties from server to client messages).

#### Handshake with pre-shared key (Section 6.5)

* tls13-core-PSKandPSKDHE-NoCorruption.cv

#### Record Protocol (Section 6.6)

* tls13-core-RecordProtocol.cv
* tls13-core-RecordProtocol-0RTT.cv
* tls13-core-RecordProtocol-0RTT-badkey.cv

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
