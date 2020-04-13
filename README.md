
SPL-SPT
Sequence of Packet Lengths/Sequence of Packet Times
=================================

## Purpose
This Zeek plugin will save the following fields to _spl.log_ in the logging directory.

* uid - The related SSL session's unique identifier.
* orig_spl - A vector of configurable length (default 20), containing the lengths of encrypted packets from the session originator
* resp_spl - A vector of configurable length (default 20), containing the lengths of encrypted packets from the session responder
* orig_spt - A vector of configurable length (default 20), containing the time interval between encrypted packets from the session originator
* resp_spt - A vector of configurable length (default 20), containing the time interval between encrypted packets from the session responder

## Rationale

Cisco researchers performed a study with the goal of identifying malicious network traffic when it uses TLS. 
In this study, they showed that a random-forest model, as implemented by SciKit-Learn, can be made up to 30% more accurate by including data on per-packet sizes and per-packet intervals. Other research has supported this claim.

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

* SPL::spl_length - The length of the two packet-length vectors 
* SPL::spt_length - The length of the two packet-time vectors





## References
https://blogs.cisco.com/security/detecting-encrypted-malware-traffic-without-decryption 

http://ccr.sigcomm.org/online/files/p7-williams.pdf 

https://dl.acm.org/doi/pdf/10.1145/3097983.3098163
