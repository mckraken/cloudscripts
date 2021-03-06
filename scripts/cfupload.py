#!/usr/bin/python

# cfupload.py - Version 0.1
# Upload objects to a Rackspace Cloud Files container
# Copyright (C) 2015 Stephen McCracken - mckraken@mckraken.net
#
# Git repository available at:
# https://github.com/mckraken/cloudscripts/blob/master/scripts/cfupload.py
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.



import os
import json
import requests
import argparse
import sys
import hashlib


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
    parser.add_argument(
        'objlst', metavar="OBJECT-NAME", nargs='+',
        help='The name of the object(s) to upload to the container.')

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
    hdrs['X-Auth-Token'] = token

    for item in args.objlst:
        cfobjurl = '/'.join([cfurl, item])
        with open(item, 'rb') as openobj:
            obj_md5sum = hashlib.md5(openobj.read()).hexdigest()
            openobj.seek(0)
            hdrs['ETag'] = obj_md5sum
            cfreq = requests.put(cfobjurl, data=openobj, headers=hdrs)
            print cfreq
