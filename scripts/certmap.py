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

import os
import json
import requests
import argparse


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



def auth_w_env():
    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    headers = {'content-type': 'application/json'}
    payload = {
        "auth": {
            "RAX-KSKEY:apiKeyCredentials": {
                "username": os.getenv('OS_USERNAME'),
                "apiKey": os.getenv('OS_PASSWORD')
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

token = auth_w_env()

ddi = os.getenv('OS_TENANT_ID')
reg = "iad"
endp = "https://" + reg + ".loadbalancers.api.rackspacecloud.com/"
lburl = "v1.0/" + ddi + "/loadbalancers/" + args.lbid + "/ssltermination/certificatemappings"

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

crtlst = requests.get(url,headers=hdrs)

print json.dumps(crtlst.json(), sort_keys=True, indent=4, separators=(',', ': '))
