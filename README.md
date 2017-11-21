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
    0.024s (user 0.020s + system 0.004s), max rss 40944K
    KeySchedule1
    All queries proved.
    0.072s (user 0.072s + system 0.000s), max rss 42544K
    KeySchedule2
    All queries proved.
    0.060s (user 0.060s + system 0.000s), max rss 39600K
    KeySchedule3
    All queries proved.
    0.544s (user 0.540s + system 0.004s), max rss 58672K
    tls13-core-InitialHandshake
    All queries proved.
    115.692s (user 115.572s + system 0.120s), max rss 2293248K
    tls13-core-InitialHandshake-1RTTonly
    All queries proved.
    119.500s (user 119.400s + system 0.100s), max rss 2278192K
    tls13-core-PSKandPSKDHE-NoCorruption
    All queries proved.
    380.880s (user 380.772s + system 0.108s), max rss 1587888K
    tls13-core-RecordProtocol
    All queries proved.
    0.040s (user 0.036s + system 0.004s), max rss 37632K
    tls13-core-RecordProtocol-0RTT
    All queries proved.
    0.036s (user 0.036s + system 0.000s), max rss 40864K
    tls13-core-RecordProtocol-0RTT-badkey
    All queries proved.
    0.024s (user 0.024s + system 0.000s), max rss 38656K
