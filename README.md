
SPL-SPT
Sequence of Payload Lengths/Sequence of Payload Times
=================================

## Purpose
This Zeek plugin will save the following fields to _spl.log_ in the logging directory.

* uid - The related SSL session's unique identifier.
* orig_spl - A vector of configurable length (default 20), containing the lengths of encrypted payloads from the session originator
* resp_spl - A vector of configurable length (default 20), containing the lengths of encrypted payloads from the session responder
* orig_spt - A vector of configurable length (default 20), containing the time interval between encrypted payloads from the session originator
* resp_spt - A vector of configurable length (default 20), containing the time interval between encrypted payloads from the session responder

## Rationale

Cisco researchers performed a study with the goal of identifying malicious network traffic when it uses TLS. 
In this study, they showed that a random-forest model, as implemented by SciKit-Learn, can be made up to 30% more accurate by including data on per-payload sizes and per-payload intervals. Other research has supported this claim.

By creating a log containing this data, I hope to enable the creation of new and interesting analytics to detect malware using TLS to communicate.

## Installation

If cloned from source:
```
$ zkg install .
```

Alternatively, you could copy _spl-spt.zeek_ into _/opt/zeek/share/zeek/site/spl-spt/_, then add the following to _local.zeek_
```
@load ./spl-spt
```

If using Zeek > 3.0 or a Zeek-product, like Corelight:
```
zkg install spl-spt
```

For what it's worth, I highly recommend enabling JSON logging by adding the following to _local.zeek_
```
@load tuning/json-logs.zeek 
```

## Configuration

If you want the vectors to be larger (or smaller) in length, edit the following values inside _local.zeek_ after the package is loaded.

* SPL::spl_length - The length of the two payload-length vectors 
* SPL::spt_length - The length of the two payload-time vectors

## Errata
As Anthony Kaza points out, the generated data is not actually the length/interval of packets, it is the interval between TLS encrypted records. This oversight was because my original implementation generated this data using the _tcp\_packet_ event, where the length parameter is actually the length of the packet. Due to performance considerations, I elected to generate the data only when DPD identifies a SSL/TLS session, and then only for the encrypted data transfer, by using the _ssl\_encrypted\_data_ event. 

Unfortunately, at that point I was already committed to the "SPL-SPT" acronym. As such, I renamed this package to "Sequence of Payload Lengths," which, while still not wholly correct, is at least closer to correct.


## References
https://blogs.cisco.com/security/detecting-encrypted-malware-traffic-without-decryption 

http://ccr.sigcomm.org/online/files/p7-williams.pdf 

https://dl.acm.org/doi/pdf/10.1145/3097983.3098163
