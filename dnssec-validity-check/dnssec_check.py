#!/usr/bin/python3

# direct-dnssec-checker 
#
# Simple validation of DNSSEC for a domain directly from the authoritative NS
#

import dns
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.exception
import dns.rcode
import dns.flags
import random
import sys
import argparse
import re

# Only perform shorter authoritative check; check SOA + DNSKEY validation
# This will allow you to check that signing works at the Authoritative DNS server level
# before actually publishing the DS record and making DNSSEC 'public'

# Global flag to trigger icinga style output, off by default and will output CSV

# Icinga status codes
_ICINGA_RETURN = { "OK" : 0, "WARNING" : 1, "CRITICAL" : 2, "UNKNOWN" : 3}
# Regex to check for valid 'looking' hostname
_DOMAIN_REGEX = re.compile("^([\w_-]+\.)+?[\w_-]+\.?$")

# Option Help
_OPT_ICINGA = "Display output in Icinga format. Requires -d/--domain option"
_OPT_DOMAIN = "Domain to check. Only required when using -i/--icinga option"
_OPT_AUTHORITY = "Only perform validation on authoritative level"

# Helper class to print stuff
class FormatedPrinter:
    def __init__(self, icinga, domain, authoritative):
        self.icinga_format = icinga 
        self.domain = domain
        self.authoritative = authoritative
    def get_ret_msg(self, err_msg, ret_val):
        if self.authoritative:
            err_msg = "(Authority Only) " + err_msg
        if self.icinga_format:
            ret_msg = "{}: {}".format(ret_val, err_msg)
        else:
            ret_msg = "{},{},{},{}".format(self.domain, ret_val, _ICINGA_RETURN[ret_val], 
                                                                                err_msg)
        return(ret_msg)
        

## Returns a string to print. Output depends on whether or not _ICINGA_RETURN is set
#def _get_ret_msg(err_msg, ret_val, domain, icinga=False):
#    if icinga:
#        ret_msg = "{}: {}".format(ret_val, err_msg)
#    else:
#        ret_msg = "{},{},{},{}".format(domain, ret_val, _ICINGA_RETURN[ret_val], err_msg)
#    return(ret_msg)


# Makes a lookup for hostname and query type (dns.rdatatype.*; eg. NS, A, SOA...)
# Does not catch critical exceptions
def validated_lookup(domain, query_type, full=None):
    
    # turn stirng into dns.name object
    name = dns.name.from_text(domain)
    pass


# domain = domain name str, icinga = bool icinga format, full = bool full dns validation
def check_domain(domain, icinga=False, authoritative=False):
    name = dns.name.from_text(domain)
    printer = FormatedPrinter(icinga=icinga, domain=domain, authoritative=authoritative)

    # Try to get NS servers of domain, and choose a random one
    try:
        r = dns.resolver.query(name, dns.rdatatype.NS)
        ns = random.choice(r).to_text()
        if len(r) < 1 or not _DOMAIN_REGEX.match(ns):
            err_msg = "NS query fail for {}; Returned hostname invalid".format(domain)
            ret_val = "UNKNOWN"
            return(_ICINGA_RETURN[ret_val], printer.get_ret_msg(err_msg, ret_val))
    except Exception as e:
        err_msg = "NS query fail for {}; {} - {}".format(domain,type(e).__name__,e.msg)
        ret_val = "CRITICAL"
        return(_ICINGA_RETURN[ret_val], printer.get_ret_msg(err_msg, ret_val))

    # Try to get ipv4 address of domain's NS. If fail, then try ipv6
    try:
        r = dns.resolver.query(ns, dns.rdatatype.A)
    except:
        try:
            r = dns.resolver.query(ns, dns.rdatatype.AAAA)
        except Exception as e:
            err_msg = "A/AAAA query fail for {}; {} {}".format(ns, type(e).__name__,e.msg)
            ret_val = "WARNING"
            return(_ICINGA_RETURN[ret_val], printer.get_ret_msg(err_msg, ret_val))

    # Pick random ip.addr from A/AAAA lookup
    ns_ipaddr = random.choice(r).to_text()

    # Look up SOA, and the DNSKEY to validate it, directly from authoritative NS
    msg     = dns.message.make_query(name, dns.rdatatype.SOA, want_dnssec=True)
    msg_key = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True)
    r     = dns.query.udp(msg, ns_ipaddr)
    r_key = dns.query.udp(msg_key, ns_ipaddr)

    # Sometimes using UDP, the response will be too large for a signle UDP packet, and
    # the nameserver will return a "Truncated Response" (TC). This is particularly common
    # for larger DNSSEC queries containing multiple signatures
    # If so, then try tcp
    if r.flags & dns.flags.TC:
        r = dns.query.tcp(msg, ns_ipaddr)
    if r_key.flags & dns.flags.TC:
        r_key  = dns.query.tcp(msg_key, ns_ipaddr)

    # Assert that query return is okay
    if r.rcode() != 0:
        err_msg = "SOA query fail for {}; rcode {} - {}".format(str(name),
                                                         r.rocde(),
                                                         dns.rcode.to_text(r.rcode()))
        ret_val = "CRITICAL"
        return(_ICINGA_RETURN[ret_val], printer.get_ret_msg(err_msg, ret_val))
    if r_key.rcode() != 0:
        err_msg = "DNSKEY query fail for {}; rcode {} - {}".format(str(name), 
                                                         r_key.rocde(), 
                                                         dns.rcode.to_text(r_key.rcode()))
        ret_val = "CRITICAL"
        return(_ICINGA_RETURN[ret_val], printer.get_ret_msg(err_msg, ret_val))

    # answer should contain two records RRSET: DNSKEY and RRSIG
    answer_qry = r.answer
    answer_key = r_key.answer
    if len(answer_qry) < 2:
        err_msg = "SOA query fail for {}; didn't reutrn RRSET and RRSIG".format(domain)
        ret_val = "CRITICAL"
        return(_ICINGA_RETURN[ret_val], printer.get_ret_msg(err_msg, ret_val))
    if len(answer_key) < 2:
        err_msg = "DNSKEY query fail for {}; didn't reutrn RRSET and RRSIG".format(domain)
        ret_val = "CRITICAL"
        return(_ICINGA_RETURN[ret_val], printer.get_ret_msg(err_msg, ret_val))

    # Try validation of SOA-RRSIG using DNSKEY (KSK)
    try:
        dns.dnssec.validate(answer_qry[0], answer_qry[1], {name : answer_key[0]}) 
    except Exception as e:
        if type(e) == NotImplementedError:
            ret_val = "UNKNOWN"
        else:
            ret_val = "CRITICAL"
        err_msg = "SOA record validation fail for {}; ".format(domain, 
                                                        type(e).__name__,
                                                        e.msg)
        return(_ICINGA_RETURN[ret_val], printer.get_ret_msg(err_msg, ret_val))

    # Finally if we make it here and we're only checking Authoritative, then exit 
    if authoritative:
        err_msg = "DNSSEC validation success for {}".format(domain)
        ret_val = "OK"
        return(_ICINGA_RETURN[ret_val], printer.get_ret_msg(err_msg, ret_val))
    else:
        err_msg = "DNSSEC validation success for {}".format(domain)
        ret_val = "OK"
        return(_ICINGA_RETURN[ret_val], printer.get_ret_msg(err_msg, ret_val))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("domainname", nargs='?',type=str, help="domain to check")
    parser.add_argument("-d", "--domain", type=str, help=_OPT_DOMAIN)
    parser.add_argument("-i", "--icinga", action="store_true", help=_OPT_ICINGA)
    parser.add_argument("-a", "--authority", action="store_true", help=_OPT_AUTHORITY)
    args = parser.parse_args() 

    # domain to check
    domain = ""

    # Activate Icinga format output
    if args.icinga:
        _ICINGA_FORMAT = True
        # If using icinga mode, must have -d/--domain
        if args.domain:
            domain = args.domain
        else:
            print("No domain via -d/--domain option")
            sys.exit(_ICINGA_RETURN["UNKNOWN"])
    # Regular mode
    else:
        # If using regular mode, require the positional arugment 'domainname'
        if args.domainname:
            domain = args.domainname
        else:
            print("No domain name provided")
            print("Usage: ./dns_checker.py <domain name>")
            sys.exit(_ICINGA_RETURN["UNKNOWN"])

    # Only do shorter, authoritative check (not used right now)
    if args.authority:
        _AUTHORITATIVE_CHECK = True

    # Check input
    if not _DOMAIN_REGEX.match(domain) or len(domain) > 64:
        print("Invalid domain arguement")
        sys.exit(_ICINGA_RETURN["UNKNOWN"])

    # Do check
    ret,msg = check_domain(domain, icinga=args.icinga, authoritative=args.authority)
    print(msg)
    sys.exit(ret)

