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
Create or add a certificate mapping for a cloud load balancer.

positional arguments:
    LB-ID                 The id of the load balancer.
    DOMAIN                The domain or hostname of the certificate.

optional arguments:
    -h, --help            show this help message and exit
    --username USERNAME   The username for the account (or set the OS_USERNAME
                          environment variable)
    --apikey API_KEY      The username for the account (or set the OS_PASSWORD
                          environment variable).
    --region REGION       The region for the loadbalancer (or set the
                          OS_REGION_NAME environment variable).
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


def lst_maps(lbd, url, headers):
    # crtlst = requests.get(url, headers=headers)
    print json.dumps(lbd,
                     sort_keys=True,
                     indent=4,
                     separators=(',', ': '))
    pass


def add_maps():
    pass


def del_maps():
    pass


def process_args():
    parser = argparse.ArgumentParser(
        description='Create certificate mapping for cloud load balancer.')
    # parser.add_argument(
    #     'lbid', metavar="LB-ID",
    #     help='The id of the load balancer.')
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
    # subparser_lst.set_defaults(dest='cmd')
    subparser_del = subparser.add_parser(
        'delete', help='delete certificate mapping')
    subparser_del.add_argument(
        'lbid', metavar="LB-ID",
        help='The id of the load balancer.')
    # subparser_del.set_defaults(dest='cmd')
    subparser_add = subparser.add_parser('add', help='add certificate mapping')
    subparser_add.add_argument(
        'lbid', metavar="LB-ID",
        help='The id of the load balancer.')
    # subparser_add.set_defaults(dest='cmd')
    subparser_add.add_argument(
        'dom', metavar="DOMAIN",
        help='The domain or hostname of the certificate.'
        'environment variable).')
    subparser_add.add_argument(
        '--ssl', action='store_true',
        help='enable SSL Termination and set this as default certificate.')
    subparser_add.add_argument(
        '--sslrepl', action='store_true',
        help='Replace the main SSL certificates with those provided.')
    subparser_add.add_argument(
        '--key', metavar="PRIVATE-KEY-FILE",
        help='The filename containing the private key. ')
    subparser_add.add_argument(
        '--crt', metavar="CERTIFICATE-FILE",
        help='The filename containing the certificate. ')
    subparser_add.add_argument(
        '--cacrt', metavar="INTERMEDIATE-CERTIFICATE-FILE",
        help='The filename containing the intermediate certificate(s).')
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


# def check_ssl_term(url, headers):
#     sslterm = requests.get(url, headers=headers)
#     try:
#         getattr(args, "ssl")
#     except AttributeError:
#         setattr(args, "ssl", False)
#     if (sslterm.status_code != 200) and (not args.ssl):
#         print
#         # print "Status: ", sslterm.status_code
#         print "Error: ", sslterm.json()["message"]
#         print "Please rerun with --ssl flag to enable SSL termination and "
#         print "use this certificate as the main, default certificate on "
#         print "this load balancer."
#         print
#         sys.exit(1)
#     elif (sslterm.status_code == 200) and (args.ssl):
#         print
#         print "Error:  This load balancer already has SSL termination",
#         print "and you passed the '--ssl' flag to enable it. Use the",
#         print "'--sslrepl flag to replace the current certificates."
#         print
#         sys.exit(1)


def enumerate_cert_domains(ip, port=443, servername=''):
    import tempfile
    import subprocess
    from os import devnull
    certdom = {}
    with tempfile.NamedTemporaryFile() as rcrt1:
        with open(devnull, "w") as fnull:
            if servername != '':
                rcrt1.write(subprocess.check_output(
                    ["openssl", "s_client", "-connect", lbipv4 + ":443",
                     "-servername", servername],
                    stderr=fnull))
            else:
                rcrt1.write(subprocess.check_output(
                    ["openssl", "s_client", "-connect", lbipv4 + ":443"],
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

username = check_arg_or_env("username", "OS_USERNAME")
apikey = check_arg_or_env("apikey", "OS_PASSWORD")
region = check_arg_or_env("region", "OS_REGION_NAME")

servicecat = get_servicecat(username, apikey)

mylbcat = [cat for cat in servicecat["access"]["serviceCatalog"]
           if cat["type"] == "rax:load-balancer"][0]

token = servicecat["access"]["token"]["id"]
tenant_id = servicecat["access"]["token"]["tenant"]["id"]

lburlbase = [endp["publicURL"] for endp in mylbcat["endpoints"]
             if endp["region"].lower() == region][0]

lburl = '/'.join([lburlbase, "loadbalancers", args.lbid])
lburl_ssl = '/'.join([lburl, "ssltermination"])
lburl_cmap = '/'.join([lburl_ssl, "certificatemappings"])

hdrs = dict()
hdrs['Content-Type'] = 'application/json'
hdrs['X-Auth-Token'] = token

lbinf = json.loads(requests.get(lburl, headers=hdrs).content)
lbinf_ssl = json.loads(requests.get(lburl_ssl, headers=hdrs).content)
lbinf_cmap = json.loads(requests.get(lburl_cmap, headers=hdrs).content)
print lbinf_cmap

lbipv4 = [ip["address"] for ip in lbinf["loadBalancer"]['virtualIps']
          if ip['ipVersion'] == 'IPV4' and ip['type'] == 'PUBLIC'][0]

# print "lb :"
# print lbinf
# print json.dumps(lbinf,
#                  sort_keys=True,
#                  indent=4,
#                  separators=(',', ': '))
try:
    if lbinf["loadBalancer"]["sslTermination"]["enabled"]:
        if args.cmd == 'list':
            print "SSL Configuration:"
            lbinf["loadBalancer"]["sslTermination"]["certificateDomains"] =\
                enumerate_cert_domains(lbipv4)
            lst_maps(lbinf["loadBalancer"]["sslTermination"], lburl_ssl, hdrs)
            if lbinf_cmap["certificateMappings"]:
                for item in lbinf_cmap["certificateMappings"]:
                    item["certificateMapping"]["certificateDomains"] =\
                        enumerate_cert_domains(
                            lbipv4,
                            servername=item["certificateMapping"]["hostName"]
                            )
                lst_maps(lbinf_cmap["certificateMappings"], lburl_cmap, hdrs)
            else:
                print
                print "No Certificate Mappings Found"
                print
    # print "lb ssl :"
    # print lbinf_ssl
    # print "lb cmap :"
    # print lbinf_cmap
except KeyError:
    print
    print "SSL is not enabled on this load balancer."
    print

# check_ssl_term(lburl_ssl, hdrs)

# # args.func(lburl_cmap, hdrs)
# if args.cmd == 'list':
#     lst_maps(lbinf, lburl, hdrs)

# cmap = dict()
# data = dict()
# cmap['hostName'] = args.dom
# cmap['privateKey'] = read_cert_file(args.key)
# cmap['certificate'] = read_cert_file(args.crt)
# if args.cacrt:
#     cmap['intermediateCertificate'] = read_cert_file(args.cacrt)
#
# data['certificateMapping'] = cmap
#
# jdata = json.dumps(data)

# crtadd = requests.post(lburl_cmap, headers=hdrs, data=jdata)

# print crtadd.text
# print crtadd.status_code

# crtlst = requests.get(lburl_cmap, headers=hdrs)

# print json.dumps(crtlst.json(),
#                  sort_keys=True,
#                  indent=4,
#                  separators=(',', ': '))
