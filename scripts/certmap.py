#!/usr/bin/python

#
#
#
#
#
#
#
#
#

'''
usage: certmap.py [-h] [--username USERNAME] [--apikey API_KEY]
                  [--region REGION]
                  {add,list,delete} ...

Manage certificate mappings for cloud load balancer.

positional arguments:
    {add,list,delete}
    list               list current mappings
    add                add certificate mapping
    delete             delete certificate mapping

optional arguments:
    -h, --help           show this help message and exit
    --username USERNAME  The username for the account (or use the OS_USERNAME
                         environment variable or the ~/raxcreds file).
    --apikey API_KEY     The username for the account (or use the OS_PASSWORD
                         environment variable or the ~/.raxcreds file).
    --region REGION      The region for the loadbalancer (or use the
                         OS_REGION_NAME environment variable or the ~/.raxcreds
                         file).


usage: certmap.py list [-h] [--query] LB-ID

positional arguments:
    LB-ID       The id of the load balancer.

optional arguments:
    -h, --help  show this help message and exit
    --query     Query the certificates for the valid domains.

usage: certmap.py add [-h] [--ssl] --key PRIVATE-KEY-FILE --crt
                      CERTIFICATE-FILE [--cacrt INTERMEDIATE-CERTIFICATE-FILE]
                      LB-ID DOMAIN

positional arguments:
    LB-ID                 The id of the load balancer.
    DOMAIN                The domain or hostname of the certificate.environment
                          variable).argparse
optional arguments:
    -h, --help            show this help message and exit
    --ssl                 enable SSL Termination and set this as default
                          certificate.
    --key PRIVATE-KEY-FILE
                          The filename containing the private key.
    --crt CERTIFICATE-FILE
                          The filename containing the certificate.
    --cacrt INTERMEDIATE-CERTIFICATE-FILE
                          The filename containing the intermediate
                          certificate(s).

'''

import os
import json
import requests
import argparse
import sys


def pprint_dict(item):
    print json.dumps(item,
                     sort_keys=True,
                     indent=4,
                     separators=(',', ': '))


def lst_maps(lbd, cmapd, query_certs=False):
    try:
        if lbd["sslTermination"]["enabled"]:
            lbipv4 = [ip["address"] for ip in lbd['virtualIps']
                      if ip['ipVersion'] == 'IPV4' and
                      ip['type'] == 'PUBLIC'][0]
            lbport = lbd["sslTermination"]["securePort"]
            if query_certs:
                lbd["sslTermination"]["certificateDomains"] =\
                    enumerate_cert_domains(lbipv4, lbport)
            if cmapd["certificateMappings"]:
                if query_certs:
                    for item in cmapd["certificateMappings"]:
                        sname = item["certificateMapping"]["hostName"]
                        item["certificateMapping"]["certificateDomains"] =\
                            enumerate_cert_domains(
                                lbipv4, lbport, servername=sname)
                print "SSL Configuration:"
                pprint_dict(lbd["sslTermination"])
                pprint_dict(cmapd["certificateMappings"])
            else:
                print "SSL Configuration (No Certificate Mappings found):"
                pprint_dict(lbd["sslTermination"])
    except KeyError:
        print "Error: SSL is not enabled on this load balancer."


def add_map(cmap_url, headers='', hostname='', certificates={}):
    data = dict()
    certificates['hostName'] = hostname
    data['certificateMapping'] = certificates

    jdata = json.dumps(data)

    crtadd = requests.post(cmap_url, headers=headers, data=jdata)

    print crtadd.text
    print crtadd.status_code


def del_maps(cmap_url, id_lst, headers=''):
    for cmap_id in id_lst:
        cmap_delete_url = '/'.join([cmap_url, cmap_id])
        cmapdel = requests.delete(cmap_delete_url, headers=headers)

        print cmapdel.status_code,
        print cmapdel.text


def process_args():
    parser = argparse.ArgumentParser(
        description='Manage certificate mappings for cloud load balancer.')
    parser.add_argument(
        '--username', metavar="USERNAME",
        help='The username for the account (or use the OS_USERNAME '
        'environment variable or the ~/.raxcreds file).')
    parser.add_argument(
        '--apikey', metavar="API_KEY",
        help='The username for the account (or use the OS_PASSWORD '
        'environment variable or the ~/.raxcreds file).')
    parser.add_argument(
        '--region', metavar="REGION", dest="region", type=str.lower,
        choices=['iad', 'dfw', 'ord', 'hkg', 'syd', 'lon'],
        help='The region for the loadbalancer (or use the OS_REGION_NAME '
        'environment variable or the ~/.raxcreds file).')

    subparser = parser.add_subparsers(dest='cmd')
    subparser.required = True

    subparser_lst = subparser.add_parser('list', help='list current mappings')
    subparser_lst.add_argument(
        'lbid', metavar="LB-ID",
        help='The id of the load balancer.')
    subparser_lst.add_argument(
        '--query', action='store_true',
        help='Query the certificates for the valid domains.')

    subparser_add = subparser.add_parser('add', help='add certificate mapping')
    subparser_add.add_argument(
        'lbid', metavar="LB-ID",
        help='The id of the load balancer.')
    subparser_add.add_argument(
        'dom', metavar="DOMAIN",
        help='The domain or hostname of the certificate.'
        'environment variable).')
    subparser_add.add_argument(
        '--ssl', action='store_true',
        help='enable SSL Termination and set this as default certificate.')
    # subparser_add.add_argument(
    #     '--sslrepl', action='store_true',
    #     help='Replace the main SSL certificates with those provided.')
    subparser_add.add_argument(
        '--key', metavar="PRIVATE-KEY-FILE", required=True,
        help='The filename containing the private key. ')
    subparser_add.add_argument(
        '--crt', metavar="CERTIFICATE-FILE", required=True,
        help='The filename containing the certificate. ')
    subparser_add.add_argument(
        '--cacrt', metavar="INTERMEDIATE-CERTIFICATE-FILE",
        help='The filename containing the intermediate certificate(s).')

    subparser_del = subparser.add_parser(
        'delete', help='delete certificate mapping')
    subparser_del.add_argument(
        'lbid', metavar="LB-ID",
        help='The id of the load balancer.')
    subparser_del.add_argument(
        'cmap_ids', metavar="CERTIFICATE-MAPPING-ID", nargs='+',
        help='The id(s) of the certificate mappings to delete.')

    return parser.parse_args()


def read_cert_file(f):
    try:
        with open(f, 'r') as infile:
            return infile.read()
    except IOError:
        print "Unable to open file {0}".format(f)
        sys.exit(1)


def check_arg_or_env(item, env):
    import ConfigParser
    if getattr(args, item) is not None:
        # print "args", item, getattr(args, item)
        return getattr(args, item)
    elif os.getenv(env):
        # print "env", item, os.getenv(env)
        return os.getenv(env)
    elif os.path.isfile(os.path.expanduser("~/.raxcreds")):
        config = ConfigParser.RawConfigParser()
        config.read(os.path.expanduser("~/.raxcreds"))
        try:
            # print "cfg", item, config.get('raxcreds', item)
            return config.get('raxcreds', item)
        except ConfigParser.NoOptionError:
            print "You need use a flag, environment variable,",
            print "or field in ~/.raxcreds."
            print "Error: No setting for '{0}' was found.".format(item)
            sys.exit(1)
    else:
        print "You need use a flag, environment variable,",
        print "or field in ~/.raxcreds."
        print "Error: No setting for '{0}' was found.".format(item)
        sys.exit(1)


def nullStderr():
    sys.stderr = open(os.devnull, "w")


def revertStderr():
    sys.stderr = sys.__stderr__


def get_servicecat(username, apikey):
    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    headers = {'content-type': 'application/json'}
    payload = {
        "auth": {
            "RAX-KSKEY:apiKeyCredentials": {
                "username": username,
                "apiKey": apikey
                }
            }
        }

    nullStderr()
    try:
        jservicecat = requests.post(url,
                                    data=json.dumps(payload),
                                    headers=headers
                                    ).content
    finally:
        revertStderr()

    return json.loads(jservicecat)


def enumerate_cert_domains(ip, port='443', servername=''):
    import tempfile
    import subprocess
    from os import devnull
    certdom = {}
    with tempfile.NamedTemporaryFile() as rcrt1:
        with open(devnull, "w") as fnull:
            if servername != '':
                rcrt1.write(subprocess.check_output(
                    ["openssl", "s_client", "-connect", ip + ":" + str(port),
                     "-servername", servername],
                    stderr=fnull))
            else:
                rcrt1.write(subprocess.check_output(
                    ["openssl", "s_client", "-connect", ip + ":" + str(port)],
                    stderr=fnull))
            rcrt1.flush()
            for line in subprocess.check_output(
                    ["openssl", "x509", "-noout", "-text", "-in", rcrt1.name],
                    stderr=fnull).split('\n'):
                if ("Subject:" in line):
                    certdom["commonName"] = line.partition("CN=")[2]
                elif "DNS:" in line:
                    certdom["subjectAlternativeNames"] =\
                        line.replace('DNS:', '').strip().split(', ')
            return certdom


args = process_args()

print args

#
# Set up all the variables
#
# Authentication variables:
#
username = check_arg_or_env("username", "OS_USERNAME")
apikey = check_arg_or_env("apikey", "OS_PASSWORD")
#
# region of the load balancer is needed
#
region = check_arg_or_env("region", "OS_REGION_NAME")
#
# Get the full service catalog from the API
#
servicecat = get_servicecat(username, apikey)
#
# Get the needed authentication token and tenant_id from the service catalog
#
token = servicecat["access"]["token"]["id"]
tenant_id = servicecat["access"]["token"]["tenant"]["id"]
#
# Get the load balancer sub-catalog from the full service catalog
#
mylbcat = [cat for cat in servicecat["access"]["serviceCatalog"]
           if cat["type"] == "rax:load-balancer"][0]
#
# Get the base url for the load balancer API and build the needed other urls
#
lburlbase = [endp["publicURL"] for endp in mylbcat["endpoints"]
             if endp["region"].lower() == region][0]
lburl = '/'.join([lburlbase, "loadbalancers", args.lbid])
lburl_ssl = '/'.join([lburl, "ssltermination"])
lburl_cmap = '/'.join([lburl_ssl, "certificatemappings"])
#
# Build the HTTP headers dictionary needed for the API calls
#
hdrs = dict()
hdrs['Content-Type'] = 'application/json'
hdrs['X-Auth-Token'] = token
#
# Call the API and build dictionaries of the resulting calls.
# The base LB dictionary, the SSL LB dictionary, and the
# Certificate Mapping LB dictionary
#
lbinf = json.loads(requests.get(lburl, headers=hdrs).content)
lbinf_ssl = json.loads(requests.get(lburl_ssl, headers=hdrs).content)
lbinf_cmap = json.loads(requests.get(lburl_cmap, headers=hdrs).content)

if args.cmd == 'list':
    lst_maps(lbinf["loadBalancer"], lbinf_cmap, args.query)

elif args.cmd == 'add':
    certs = dict()
    # certs["hostName"] = args.dom
    certs['privateKey'] = read_cert_file(args.key)
    certs['certificate'] = read_cert_file(args.crt)
    if args.cacrt:
        certs['intermediateCertificate'] = read_cert_file(args.cacrt)

    add_map(lburl_cmap, hdrs, hostname=args.dom, certificates=certs)

elif args.cmd == 'delete':
    del_maps(lburl_cmap, args.cmap_ids, headers=hdrs)

else:
    pass
#
