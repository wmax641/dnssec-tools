# Vanity DNSSEC Miner

Simple script to repeatedly generate KSK until a desired keytag substring is found

Modify the "ZONE" variable in script.

To find exact matches of a keytag with less than 5 digits (as opposed to substring), search for the keytag with leading zeroes, eg:
```
ZONE="domain.name"
DESIRED_KEYTAG="1337"
```


### Requirements
Need `bind-dnssec-utils` to generate DNSSEC keys

Use a computer/VM with high clock rate CPU. Number of cores is not relevant as this simple script is single threaded.

### Increasing Entropy
This may help, particularly when trying to generate RSA keys. 

Also consider this if the machine's entropy is below 2000, which is common for VMs
```
$ cat /proc/sys/kernel/random/entropy_avail
887
```

```
$ dnf install rng-tools
$ systemctl start rngd
$ cat /proc/sys/kernel/random/entropy_avail
4035
```
