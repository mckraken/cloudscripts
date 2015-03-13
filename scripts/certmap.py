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


def process_args():
    parser = argparse.ArgumentParser(
        description='Create certificate mapping for cloud load balancer.')
    parser.add_argument(
        'lbid', metavar="LB-ID",
        help='The id of the load balancer.')
    parser.add_argument(
        'dom', metavar="DOMAIN",
        help='The domain or hostname of the certificate.')
    parser.add_argument(
        '--username', metavar="USERNAME",
        help='The username for the account (or set the OS_USERNAME '
        'environment variable).')
    parser.add_argument(
        '--apikey', metavar="API_KEY",
        help='The username for the account (or set the OS_PASSWORD '
        'environment variable).')
    parser.add_argument(
        '--region', metavar="REGION", dest="region", type=str.lower,
        choices=['iad', 'dfw', 'ord', 'hkg', 'syd', 'lon'],
        help='The region for the loadbalancer (or set the OS_REGION_NAME '
        'environment variable).')
    parser.add_argument(
        '--ssl', action='store_true',
        help='enable SSL Termination and set this as default certificate.')
    parser.add_argument(
        '--key', metavar="PRIVATE-KEY-FILE",
        help='The filename containing the private key. ')
    parser.add_argument(
        '--crt', metavar="CERTIFICATE-FILE",
        help='The filename containing the certificate. ')
    parser.add_argument(
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

    jservicecat = requests.post(url,
                                data=json.dumps(payload),
                                headers=headers
                                ).content

    return json.loads(jservicecat)


def check_ssl_term():
    pass


args = process_args()

# print args

# username = check_arg_or_env(args.username, "OS_USERNAME")
# apikey = check_arg_or_env(args.apikey, "OS_PASSWORD")
# region = check_arg_or_env(args.region, "OS_REGION_NAME")

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
lbsslurl = '/'.join([lburl, "ssltermination"])
lbcmapurl = '/'.join([lbsslurl, "certificatemappings"])

hdrs = dict()
hdrs['Content-Type'] = 'application/json'
hdrs['X-Auth-Token'] = token

sslterm = requests.get(lbsslurl, headers=hdrs)
if (sslterm.status_code != 200) and (not args.ssl):
    print
    # print "Status: ", sslterm.status_code
    print "Error: ", sslterm.json()["message"]
    print "Please rerun with --ssl flag to enable SSL termination and "
    print "set this certificate as the main, default certificate on "
    print "this load balancer."
    print
    sys.exit(1)
elif (sslterm.status_code == 200) and (args.ssl):
    print
    print "Error:  This load balancer already has SSL termination",
    print "and you passed the --ssl flag to enable it."
    print
    sys.exit(1)

cmap = dict()
data = dict()
cmap['hostName'] = args.dom
cmap['privateKey'] = read_cert_file(args.key)
cmap['certificate'] = read_cert_file(args.crt)
if args.cacrt:
    cmap['intermediateCertificate'] = read_cert_file(args.cacrt)

data['certificateMapping'] = cmap

jdata = json.dumps(data)

# crtadd = requests.post(lbcmapurl, headers=hdrs, data=jdata)

# print crtadd.text
# print crtadd.status_code

# crtlst = requests.get(lbcmapurl, headers=hdrs)

# print json.dumps(crtlst.json(),
#                  sort_keys=True,
#                  indent=4,
#                  separators=(',', ': '))
