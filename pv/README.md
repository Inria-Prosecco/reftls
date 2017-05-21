# ProVerif Models for TLS 1.3

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

