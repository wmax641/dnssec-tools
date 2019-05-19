# Vanity DNSSEC Miner
Simple script to repeatedly genearte KSK until a desired keytag substring is found

To find exact matches of a keytag with less than 5 digits (as opposed to substring), search for the keytag with leading zeroes, eg:
```
DESIRED_KEYTAG="01337"
```
