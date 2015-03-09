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
    --ddi TENANT_ID       The account number for the account (or set the
                          OS_TENANT_ID environment variable).
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
        '--region', metavar="REGION",
        help='The region for the loadbalancer (or set the OS_REGION_NAME '
        'environment variable).')
    parser.add_argument(
        '--ddi', metavar="TENANT_ID",
        help='The account number for the account (or set the OS_TENANT_ID '
        'environment variable).')
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
    with open(f, 'r') as infile:
        return infile.read()


def check_arg_or_env(arg, env):
    if arg:
        return arg
    elif os.getenv(env):
        return os.getenv(env)
    else:
        print "You need use a flag or use an Environment variable."
        print "No setting for {0} was found.".format(env)
        sys.exit(1)


def get_token(username, apikey):
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

    req = json.loads(requests.post(url,
                                   data=json.dumps(payload),
                                   headers=headers
                                   ).content
                     )

    return req["access"]["token"]["id"]


args = process_args()

# print args

username = check_arg_or_env(args.username, "OS_USERNAME")
apikey = check_arg_or_env(args.apikey, "OS_PASSWORD")

token = get_token(username, apikey)

ddi = check_arg_or_env(args.ddi, "OS_TENANT_ID")
reg = check_arg_or_env(args.region, "OS_REGION_NAME")
endp = "https://" + reg +\
       ".loadbalancers.api.rackspacecloud.com/"
lburl = "v1.0/" + ddi +\
        "/loadbalancers/" + args.lbid +\
        "/ssltermination/certificatemappings"

url = endp + lburl

hdrs = dict()
hdrs['Content-Type'] = 'application/json'
hdrs['X-Auth-Token'] = token
jhdrs = json.dumps(hdrs)

cmap = dict()
data = dict()
cmap['hostName'] = args.dom
cmap['privateKey'] = read_cert_file(args.key)
cmap['certificate'] = read_cert_file(args.crt)
if args.cacrt:
    cmap['intermediateCertificate'] = read_cert_file(args.cacrt)

data['certificateMapping'] = cmap

jdata = json.dumps(data)

crtadd = requests.post(url, headers=hdrs, data=jdata)

print crtadd.text
print crtadd.status_code

crtlst = requests.get(url, headers=hdrs)

print json.dumps(crtlst.json(), sort_keys=True, indent=4, separators=(',', ': '))
