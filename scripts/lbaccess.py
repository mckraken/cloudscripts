#!/usr/bin/python

#
# lbaccess.py - Version 0.1
# Rackspace Load Balancer Access List Management Script
# Copyright (C) 2015 Stephen McCracken - mckraken@mckraken.net
#
# Git repository available at http://github.com/mckraken/cloudscripts
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
#


'''
---------------
Base help:
---------------

'''

import os
import json
import requests
import argparse
import sys
import time
import netaddr
import logging


def pprint_dict(item):
    print json.dumps(item,
                     sort_keys=True,
                     indent=4,
                     separators=(',', ': '))


def wait_for_status(url, hdrs, verbose=False):
    start = time.time()
    while True:
        nullStderr()
        lbstatus = json.loads(
            requests.get(url, headers=hdrs).content
            )["loadBalancer"]["status"]
        revertStderr()
        log.info(
            "Current status: {0} ... (elapsed: {1:4.1f} seconds)".format(
                lbstatus, (time.time() - start))
            )
        if lbstatus in ['ACTIVE', 'ERROR']:
            return lbstatus
        else:
            time.sleep(15)


def upd_lb(rmethod, url, headers=None, data={}, params={}, verbose=False):
    jdata = json.dumps(data)
    status_url = url.rpartition('/')[0]
    log.info("Checking load balancer...")
    if wait_for_status(status_url, headers, verbose=verbose) == 'ERROR':
        log.warn("Load balancer is in ERROR state.")
        sys.exit(1)
    nullStderr()
    log.info("Sending request to load balancer...")
    lbupd = rmethod(url, headers=headers, data=jdata, params=params)
    revertStderr()
    log.debug('Request URL: ' + lbupd.url)

    if lbupd.status_code in [200, 202]:
        if wait_for_status(status_url, headers, verbose=verbose) == 'ERROR':
            log.warn("Load balancer is in ERROR state.")
            sys.exit(1)
        return lbupd
    else:
        log.warn(
            "Error (code {0}):\n{1}".format(
                lbupd.status_code, lbupd.json()["message"])
            )


def process_args():
    parser = argparse.ArgumentParser(
        description='Manage access lists for a cloud load balancer.')
    parser.add_argument(
        '--username', metavar="USERNAME",
        help='The username for the account (or use the OS_USERNAME '
        'environment variable or the ~/.raxcreds file).')
    parser.add_argument(
        '--apikey', metavar="API_KEY",
        help='The username for the account (or use the OS_PASSWORD '
        'environment variable or the ~/.raxcreds file).')
    # parser.add_argument(
    #    '--region', metavar="REGION", dest="region", type=str.lower,
    #    choices=['iad', 'dfw', 'ord', 'hkg', 'syd', 'lon'],
    #    help='The region for the loadbalancer (or use the OS_REGION_NAME '
    #    'environment variable or the ~/.raxcreds file).')
    lb_id_ip = parser.add_mutually_exclusive_group(required=True)
    lb_id_ip.add_argument(
        '--lbid', metavar="LB-ID", type=int,
        help='The id of the load balancer.')
    lb_id_ip.add_argument(
        '--lbip', metavar="LB-IP",
        help='The IP address of the load balancer.')
    parser.add_argument(
        '-q', '--quiet', dest='quiet', action='store_true',
        help='Suppress output.')

    subparser = parser.add_subparsers(dest='cmd')
    subparser.required = True

    subparser.add_parser('list', help='list current access list')

    subparser_add = subparser.add_parser('add', help='Add access list item(s)')
    add_allow_deny = subparser_add.add_mutually_exclusive_group()
    add_allow_deny.add_argument(
        '--deny', dest='listtype', action='store_const', const='DENY',
        help='Access list is a DENY list (default).')
    add_allow_deny.add_argument(
        '--allow', dest='listtype', action='store_const', const='ALLOW',
        help='Access list is an ALLOW list.')
    subparser_add.add_argument(
        'net', metavar="NETWORK", nargs='+',
        help='The network(s) to add to the access list.')

    subparser_del = subparser.add_parser(
        'delete', help='delete access list item')
    alst_ip_or_id = subparser_del.add_mutually_exclusive_group(required=True)
    alst_ip_or_id.add_argument(
        '--listid', metavar="LIST-ID", type=int, nargs='+',
        help='The access list id(s).')
    alst_ip_or_id.add_argument(
        '--listip', metavar="LIST-IP", nargs='+',
        help='The access list IP address(es).')

    subparser.add_parser('delete-all', help='Delete the full access list')

    return parser.parse_args()


def check_arg_or_env(item, argvar=None, envvar=''):
    import ConfigParser
    if argvar is not None:
        return argvar
    elif os.getenv(envvar):
        return os.getenv(envvar)
    elif os.path.isfile(os.path.expanduser("~/.raxcreds")):
        config = ConfigParser.RawConfigParser()
        config.read(os.path.expanduser("~/.raxcreds"))
        try:
            return config.get('raxcreds', item)
        except ConfigParser.NoOptionError:
            log.error("You need use a flag, environment variable, " +
                      "or field in ~/.raxcreds. " +
                      "No setting for '{0}' was found.".format(item))
            sys.exit(1)
    else:
        log.error("You need use a flag, environment variable, " +
                  "or field in ~/.raxcreds. " +
                  "No setting for '{0}' was found.".format(item))
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

    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)

    console = logging.StreamHandler()
    filehandler = logging.FileHandler('/tmp/lbaccess.log', mode='a')

    full_format = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')
    con_format = logging.Formatter(
        '%(asctime)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')
    brief_format = logging.Formatter(
        '%(message)s')

    if args.quiet:
        console.setFormatter(con_format)
        console.setLevel(logging.ERROR)
    else:
        console.setFormatter(brief_format)
        console.setLevel(logging.INFO)

    filehandler.setFormatter(full_format)
    filehandler.setLevel(logging.WARNING)

    log.addHandler(console)
    log.addHandler(filehandler)

    #
    # Set up all the variables
    #
    # Authentication variables:
    #
    username = check_arg_or_env("username",
                                args.username,
                                "OS_USERNAME").lower()
    apikey = check_arg_or_env("apikey",
                              args.apikey,
                              "OS_PASSWORD").lower()
    #
    # Get the full service catalog from the API
    #
    servicecat = get_servicecat(username, apikey)
    #
    # Get the needed authentication token from the service catalog
    #
    token = servicecat["access"]["token"]["id"]
    #
    # Get the load balancer sub-catalog from the full service catalog
    #
    mylbcat = [cat for cat in servicecat["access"]["serviceCatalog"]
               if cat["type"] == "rax:load-balancer"][0]
    #
    # Get the base url for the LB API and build the needed other urls
    #
    lburlbase = ['/'.join([endp["publicURL"], "loadbalancers"])
                 for endp in mylbcat["endpoints"]]
    #             if endp["region"].lower() == region]
    #
    # Build the HTTP headers dictionary needed for the API calls
    #
    hdrs = dict()
    hdrs['Content-Type'] = 'application/json'
    hdrs['X-Auth-Token'] = token

    if args.lbip:
        try:
            netaddr.IPAddress(args.lbip)
        except netaddr.core.AddrFormatError:
            log.error("Not a valid IPv4 address: {0}".format(args.lbip))
            sys.exit(1)

    for item in lburlbase:
        nullStderr()
        lbinf = json.loads(requests.get(item, headers=hdrs).content)
        revertStderr()
        if args.lbid:
            mylbid_l = [lbitem["id"] for lbitem in
                        lbinf["loadBalancers"] if
                        lbitem["id"] == args.lbid]
            if mylbid_l:
                # nested list comprehension here:
                mylbip = [lbaitem["address"] for lbaitem in
                          [lbitem["virtualIps"] for lbitem in
                          lbinf["loadBalancers"] if
                          lbitem["id"] == mylbid_l[0]][0] if
                          lbaitem["ipVersion"] == "IPV4" and
                          lbaitem["type"] == "PUBLIC"][0]
                break
        elif args.lbip:
            mylbid_l = [lbitem["id"] for lbitem in
                        lbinf["loadBalancers"] if
                        any(lbvips["address"] == args.lbip for
                            lbvips in lbitem["virtualIps"])
                        ]
            if mylbid_l:
                mylbip = args.lbip
                break

    if mylbid_l:
        lbreg = item.partition('//')[2].partition('.')[0].upper()
        mylburl = '/'.join([item, str(mylbid_l[0])])
    else:
        log.warn("The specified load balancer was not found.")
        sys.exit(1)
    log.info("Region: {0}".format(lbreg))
    log.info("LB id:  {0}".format(mylbid_l[0]))
    log.info("LB IP:  {0}".format(mylbip))
    lb_alst_url = '/'.join([mylburl, 'accesslist'])

    if args.cmd == 'list':
        lb_alst = json.loads(
            upd_lb(requests.get, lb_alst_url, headers=hdrs).content
            )
        pprint_dict(lb_alst)

    elif args.cmd == 'add':
        if args.listtype is None:
            args.listtype = 'DENY'
        alst_d = dict()
        alst_d["accessList"] = []
        #
        # Build AccessList dictionary
        #
        for item in args.net:
            item_d = dict()
            try:
                item_d["address"] = str(netaddr.IPNetwork(item).cidr)
                item_d["type"] = args.listtype
                alst_d["accessList"].append(item_d)
            except netaddr.core.AddrFormatError:
                log.error("Invalid IPv4 address or subnet: {0}".format(item))
                sys.exit(1)
        upd_lb(requests.post,
               lb_alst_url,
               headers=hdrs,
               data=alst_d,
               verbose=True)

    elif args.cmd == 'delete':
        # The documentation states a maximum of 10 per bulk delete operation
        chunklength = 10

        lb_alst = json.loads(
            upd_lb(requests.get, lb_alst_url, headers=hdrs).content
            )
        log.debug(lb_alst)
        if args.listid:
            alst_del_l = [str(item["id"]) for item in
                          lb_alst["accessList"] if
                          item["id"] in args.listid]
        elif args.listip:
            iplist_normalized = [str(netaddr.IPNetwork(ip).cidr) for
                                 ip in args.listip]
            alst_del_l = [str(item["id"]) for item in
                          lb_alst["accessList"] if
                          item["address"] in iplist_normalized]
        alst_del_chunked = (
            lambda l, n=chunklength: [l[i:i+n] for i in range(0, len(l), n)]
            )(alst_del_l)
        for item in alst_del_chunked:
            params = {"id": item}
            upd_lb(requests.delete,
                   lb_alst_url,
                   headers=hdrs,
                   params=params,
                   verbose=True)

    elif args.cmd == 'delete-all':
        upd_lb(requests.delete, lb_alst_url, headers=hdrs, verbose=True)
