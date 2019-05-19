# DNSSEC Checker

**WIP, not complete!**

Simple validation of DNSSEC for a domain directly from the authoritative NS

Optional flag, `--icinga` to output in a format suitable for Icinga checks

Validation is done roughly like this:

** Authoritative only check with `-a`. **

Only perform shorter authoritative check; check SOA + DNSKEY validation.This will allow confirmation that signing works at the Authoritative DNS server level before actually publishing the DS record and making DNSSEC 'public'
* Grab SOA record and RRSIGs, direct from authoritative NS
* Grab DNSKEY for domain, direct from authoritative NS
* Validate the above
* *Further validation beyond the authority is not required here*

** Full check (default, without `-a`) **

*(not implemented)* Performs full DNSSEC chain validation starting from the root
* *(not implemented)* current_domain=. (root)
* *(not implemented)* Loop1: while current_domain != checked_domain;
* *(not implemented)* Using NS of current_domain, grab DS record of child zone
* *(not implemented)* Grab DNSKEY assosicated with the DS record's RRSIG's
* *(not implemented)* Validate DNSKEY(child)
* *(not implemented)* Validate DS and DNSKEY(child)
* *(not implemented)* current_domain = child, child = new_child(current_domain)
* *(not implemented)* If: current_domain = child; break
* *(not implemented)* Perform check similar to authoratative (`-a`), above

### Requirements
`pip3 install -r requirements.txt`

* python3
* python3:dnspython
* python3:pycryptodome(x)
* python3:ecdsa

### Usage Examples
#### Standard CSV output
```
# python3 dnssec_check.py clueless.engineer
clueless.engineer,OK,0,DNSSEC successfully validates

# python3 dnssec_check.py dnssec.fail
dnssec.fail,CRITICAL,2,NS query fail for dnssec.fail; NoNameservers - All nameservers failed to answer the query dnssec.fail.
```

#### Icinga output
Use `--icinga`/`-i` option flag, Requires to select domain with `--domain`/`-d` option
```
# python3 dnssec_check.py --icinga --domain dnssec-failed.org
CRITICAL: NS query fail for dnssec-failed.org; NoNameservers - All nameservers failed to answer the query dnssec-failed.org. 
]$ echo $?
2

# python3 dnssec_check.py -i -d not_a_real.domain
CRITICAL: NS query fail for not_a_real.domain; NXDOMAIN - The DNS query name does not exist: not_a_real.domain.
# echo $?
3
```
