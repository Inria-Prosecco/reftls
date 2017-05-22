# ProVerif Models for TLS 1.3

[Download ProVerif from the ProVerif website](http://proverif.inria.fr).

The `.pv` files corresponding to various combinations of the protocol should be run by the command:

    proverif -lib tls-lib <filename>

They use the library `tls-lib.pvl` provided below.

### Generic Library with Threat Model and Protocol Processes

* [tls-lib.pvl](tls-lib.pvl)


### ProVerif Models for TLS 1.2 and TLS 1.3

*   TLS 1.2 only: [tls12.pv][tls12.pv] 
*   TLS 1.3 (draft 18) DHE+PSK 0-RTT+1-RTT: [tls13-draft18-only.pv](tls13-draft18-only.pv)
*   TLS 1.2 + TLS 1.3 (draft 18): [tls12-tls13-draft18.pv](tls12-tls13-draft18.pv)


### Understanding the results

ProVerif generates a large amount of input, so you may want to run:
    proverif -lib tls-lib <filename> | tee results.txt | grep ^RESULT
which will put all the results in a file results.txt and summarize the success or failure of various security queries.
(Warning: verifying this model takes a long time and a significant amount of RAM even on powerful workstations.)

To understand the results, look in the PV file. Roughly, the "true"
queries correspond to security goals like (Forward) Secrecy,
Authenticity, Replay Prevention, and Unique Channel Identifiers for
the session keys and for the various data fragments.  The "false"
queries correspond to queries that we expect to fail; they show that
our verification is tight, disabling some of the conditions in our
"true" queries would cause them to be false.

