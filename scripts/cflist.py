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
import sys
import time


def process_args():
    parser = argparse.ArgumentParser(
        description='List objects in a Cloud Files container.')
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
        choices=['iad', 'dfw', 'ord', 'hkg', 'syd'],
        help='The region for the loadbalancer (or use the OS_REGION_NAME '
        'environment variable or the ~/.raxcreds file).')
    parser.add_argument(
        'cname', metavar="CONTAINER-NAME",
        help='The name of the Cloud Files container.')


    return parser.parse_args()


def check_arg_or_env(item, aitem, eitem):
    import ConfigParser
    if aitem is not None:
        return aitem
    elif os.getenv(eitem):
        return os.getenv(eitem)
    elif os.path.isfile(os.path.expanduser("~/.raxcreds")):
        config = ConfigParser.RawConfigParser()
        config.read(os.path.expanduser("~/.raxcreds"))
        try:
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


if __name__ == "__main__":
    args = process_args()

    username = check_arg_or_env("username",
                                args.username,
                                "OS_USERNAME").lower()
    apikey = check_arg_or_env("apikey",
                              args.apikey,
                              "OS_PASSWORD").lower()
    region = check_arg_or_env("region",
                              args.region,
                              "OS_REGION_NAME").lower()
    
    servicecat = get_servicecat(username, apikey)
    token = servicecat["access"]["token"]["id"]
    
    mycfcat = [cat for cat in servicecat["access"]["serviceCatalog"]
               if cat["type"] == "object-store"][0]
    
    cfurlbase = [endp["publicURL"] for endp in mycfcat["endpoints"]
                 if endp["region"].lower() == region][0]
    cfurl = '/'.join([cfurlbase, args.cname])
    
    hdrs = dict()
    hdrs['Content-Type'] = 'application/json'
    hdrs['X-Auth-Token'] = token

    cflst = []
    cfreq = requests.get(cfurl, headers=hdrs)
    while cfreq.status_code != 204:
        cfsublst = cfreq.content.rstrip('\n').split('\n')
        cfnewurl = '='.join([cfurl + '?' + 'marker', cfsublst[-1]])
        cfreq = requests.get(cfnewurl, headers=hdrs)
        cflst.extend(cfsublst)

    for item in cflst:
        print item

