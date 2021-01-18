"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from dns.exception import DNSException, Timeout

FORMATS = (('CNAME', '{alias} is an alias for {name}'), ('A',
           '{name} has address {address}'), ('AAAA',
           '{name} has IPv6 address {address}'), ('MX',
           '{name} mail is handled by {preference} {exchange}'))
# current as of 19 October 2020
ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

# Cache Helper


class my_dictionary(dict):
    def __init__(self):
        self = dict()

    def add(self, key, value):
        self[key] = value


def collect_results(name: str, domaincache) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)

    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME, domaincache)
    cnames = []
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": name})
    # lookup A
    response = lookup(target_name, dns.rdatatype.A, domaincache)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA, domaincache)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX, domaincache)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords
    domaincache.key = name
    domaincache.value = full_response
    domaincache.add(domaincache.key, domaincache.value)
    return full_response


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata,
           dc) -> dns.message.Message:
    """
    Find relevant root server that
    contains the name server ip referral needed to recurse
    """
    found = False
    i = 0
    for server in ROOT_SERVERS:

        response, found = lookup_iter(target_name,
                                      qtype, server, found, dc)
        if response.answer:
            cname = dns.rdatatype.CNAME
            # change answer type based on referral
            top_resp = response.answer[0].rdtype
            if top_resp == cname and qtype != cname:
                found = False
                first_resp = str(response.answer[0][0])
                target_name = dns.name.from_text(first_resp)
                response = lookup(target_name, qtype, dc)
            return response
        elif response.authority:
            # start of authority record. irrelevant
            if response.authority[0].rdtype == dns.rdatatype.SOA:
                break
    return response


def lookup_iter(target_name: dns.name.Name,
                qtype: dns.rdata.Rdata, server, found, dc):
    """
    Retrieves end answer from referral queries that we find
    by recursing down the server tree
    """
    outbound_query = dns.message.make_query(target_name, qtype)
    try:
        response = dns.query.udp(outbound_query, server, 3)
        if response.rcode() != dns.rcode.NOERROR:
            response = dns.rcode.NXDOMAIN

        if response.answer:
            found = True
            return response, found
        elif response.additional:
            # parse through additional section
            for add in response.additional:
                # each ip response listed
                for addx in add:
                    if addx.rdtype == dns.rdatatype.A:
                        response, found = lookup_iter(target_name,
                                                      qtype, str(addx),
                                                      found, dc)
                    if found:
                        break
                if found:
                    break
        elif response.authority and not found:
            # parse through authority section
            for auth in response.authority:
                # each response listed
                for authx in auth:
                    if authx.rdtype == dns.rdatatype.NS:
                        ns_response = lookup(str(authx), dns.rdatatype.A, dc)
                        ns_addr = str(ns_response.answer[0][0])
                        response, found = lookup_iter(target_name,
                                                      qtype, ns_addr,
                                                      found, dc)
                    elif authx.rdtype == dns.rdatatype.SOA:
                        found = True
                        break
                if found:
                    break

        return response, found
    except Timeout:
        print("Search longer than 3 seconds...waiting...")
        return dns.message.Message(), False
    except DNSException:
        print("Invalid query...")
        return dns.message.Message(), False


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    dict_obj = my_dictionary()
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        cache = dict_obj.get(a_domain_name)
        if cache:
            print_results(cache)
        else:
            print_results(collect_results(a_domain_name, dict_obj))


if __name__ == "__main__":
    main()
