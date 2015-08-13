#!/usr/bin/python

#
# lbaccess.py - Version 0.2
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
from copy import deepcopy


def pprint_dict(item):
    print json.dumps(item,
                     sort_keys=True,
                     indent=4,
                     separators=(',', ': '))


def wait_for_status(url, hdrs):
    start = time.time()
    while True:
        nullStderr()
        lbstatus = json.loads(
            requests.get(url, headers=hdrs).content
            )["loadBalancer"]["status"]
        revertStderr()
        log.debug(
            "Current status: {0} ... (elapsed: {1:4.1f} seconds)".format(
                lbstatus, (time.time() - start))
            )
        if lbstatus in ['ACTIVE', 'ERROR']:
            return lbstatus
        else:
            time.sleep(15)


def upd_lb(rmethod, url, headers=None, data={}, params={}):
    jdata = json.dumps(data)
    status_url = url.rpartition('/')[0]
    log.info("Checking load balancer...")
    if wait_for_status(status_url, headers) == 'ERROR':
        log.warn("Load balancer is in ERROR state.")
        sys.exit(1)
    nullStderr()
    log.info("Sending request to load balancer...")
    lbupd = rmethod(url, headers=headers, data=jdata, params=params)
    revertStderr()
    log.debug('Request URL: ' + lbupd.url)

    if lbupd.status_code in [200, 202]:
        if wait_for_status(status_url, headers) == 'ERROR':
            log.warn("Load balancer is in ERROR state.")
            sys.exit(1)
        return lbupd
    else:
        try:
            log.error("Error (code {0}):\n{1}".format(
                lbupd.status_code,
                lbupd.json()["message"]))
        except:
            try:
                log.error("Error (code {0}) sending".format(lbupd.status_code) +
                          " request to load balancer.")
            except:
                log.error("Error sending request to load balancer.")


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
    noisiness = parser.add_mutually_exclusive_group()
    noisiness.add_argument(
        '-q', '--quiet', dest='quiet', action='count',
        help='Suppress most output or -qq for all output.')
    noisiness.add_argument(
        '-v', '--verbose', dest='verbose', action='count',
        help='More verbose output.')

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
    del_allow_deny = subparser_del.add_mutually_exclusive_group()
    del_allow_deny.add_argument(
        '--deny', dest='listtype', action='store_const', const='DENY',
        help='Access list is a DENY list (default).')
    del_allow_deny.add_argument(
        '--allow', dest='listtype', action='store_const', const='ALLOW',
        help='Access list is an ALLOW list.')
    alst_ip_or_id = subparser_del.add_mutually_exclusive_group(required=True)
    alst_ip_or_id.add_argument(
        '--listid', metavar="LIST-ID", type=int, nargs='+',
        help='The access list id(s).')
    alst_ip_or_id.add_argument(
        '--listip', dest='net', metavar="LIST-IP", nargs='+',
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
        item_value = None
        for section in ['rax loadbalancers', 'raxcreds']:
            if config.has_section(section):
                try:
                    item_value = config.get(section, item)
                except ConfigParser.NoOptionError:
                    pass
            if item_value is not None:
                return item_value
        if item_value is None:
            log.error("You need use a flag, environment variable, " +
                      "or field in ~/.raxcreds. " +
                      "No setting for '{0}' was found.".format(item))
            sys.exit(1)
        else:
            return item_value
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


def dcopy_ipset(_ipset):
    if len(_ipset) == 0:
        return netaddr.IPSet()
    else:
        return deepcopy(_ipset)


def alst_changes(c_alst, ipnets, chtype='add', ltype='DENY'):
    log.debug('Current access list: {0}'.format(c_alst))

    curr_allw_l = [alst['address'] for alst in
                   c_alst['accessList'] if
                   alst['type'] == 'ALLOW']
    curr_allws_ipset = netaddr.IPSet(curr_allw_l)

    curr_deny_l = [alst['address'] for alst in
                   c_alst['accessList'] if
                   alst['type'] == 'DENY']
    curr_denys_ipset = netaddr.IPSet(curr_deny_l)

    args_addr_l = []
    for item in ipnets:
        try:
            args_addr_l.append(str(netaddr.IPNetwork(item).cidr))
        except netaddr.core.AddrFormatError:
            log.error(
                "Invalid IPv4 address or subnet: {0}".format(item))
            sys.exit(1)
    args_addrs_ipset = netaddr.IPSet(args_addr_l)

    if ltype == 'DENY' or ltype is None:
        new_allws_ipset = curr_allws_ipset
        new_denys_ipset = dcopy_ipset(curr_denys_ipset)
        if chtype == 'add':
            new_denys_ipset.update(args_addrs_ipset)
            del_denys_ipset = dcopy_ipset(curr_denys_ipset)
            add_denys_ipset = dcopy_ipset(new_denys_ipset)
        elif chtype == 'delete':
            new_denys_ipset = new_denys_ipset - args_addrs_ipset
            del_denys_ipset = dcopy_ipset(curr_denys_ipset)
            add_denys_ipset = dcopy_ipset(new_denys_ipset)
        for item in curr_denys_ipset.iter_cidrs():
            if item in new_denys_ipset.iter_cidrs():
                del_denys_ipset.remove(item)
                add_denys_ipset.remove(item)
        del_allws_ipset = netaddr.IPSet()
        add_allws_ipset = netaddr.IPSet()
    elif ltype == 'ALLOW':
        new_denys_ipset = curr_denys_ipset
        new_allws_ipset = dcopy_ipset(curr_allws_ipset)
        if chtype == 'add':
            new_allws_ipset.update(args_addrs_ipset)
            del_allws_ipset = dcopy_ipset(curr_allws_ipset)
            add_allws_ipset = dcopy_ipset(new_allws_ipset)
        elif chtype == 'delete':
            new_allws_ipset = new_allws_ipset - args_addrs_ipset
            del_allws_ipset = dcopy_ipset(curr_allws_ipset)
            add_allws_ipset = dcopy_ipset(new_allws_ipset)
        for item in curr_allws_ipset.iter_cidrs():
            if item in new_allws_ipset.iter_cidrs():
                del_allws_ipset.remove(item)
                add_allws_ipset.remove(item)
        del_denys_ipset = netaddr.IPSet()
        add_denys_ipset = netaddr.IPSet()

    log.debug('-------------------------------------------')
    log.debug('new_allws_ipset: {0}'.format(new_allws_ipset))
    log.debug('curr_allws_ipset: {0}'.format(curr_allws_ipset))
    log.debug('new_denys_ipset: {0}'.format(new_denys_ipset))
    log.debug('curr_denys_ipset: {0}'.format(curr_denys_ipset))
    log.debug('del_allws_ipset: {0}'.format(del_allws_ipset))
    log.debug('del_denys_ipset: {0}'.format(del_denys_ipset))
    log.debug('add_allws_ipset: {0}'.format(add_allws_ipset))
    log.debug('add_denys_ipset: {0}'.format(add_denys_ipset))
    log.debug('-------------------------------------------')

    del_alst_ids = [
        str(item["id"]) for item in
        c_alst["accessList"] if
        netaddr.IPSet([item["address"]]).issubset(del_allws_ipset) and
        item['type'] == 'ALLOW']
    del_alst_ids.extend([
        str(item["id"]) for item in
        c_alst["accessList"] if
        netaddr.IPSet([item["address"]]).issubset(del_denys_ipset) and
        item['type'] == 'DENY'])

    chg_d = dict()
    chg_d['add'] = []
    chg_d['delete'] = del_alst_ids
    for add_alitem in add_allws_ipset.iter_cidrs():
        al_item = dict()
        al_item['address'] = str(add_alitem)
        al_item['type'] = 'ALLOW'
        chg_d['add'].append(al_item)
    for add_alitem in add_denys_ipset.iter_cidrs():
        al_item = dict()
        al_item['address'] = str(add_alitem)
        al_item['type'] = 'DENY'
        chg_d['add'].append(al_item)

    return chg_d


if __name__ == "__main__":

    args = process_args()
    if args.cmd == 'add':
        args.listid = None

    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.set_name('console')
    fh = logging.FileHandler('/tmp/lbaccess.log', mode='a')
    fh.set_name('file')

    full_format = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')
    con_format = logging.Formatter(
        '%(asctime)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')
    brief_format = logging.Formatter(
        '%(message)s')

    if args.verbose == 1:
        ch.setFormatter(con_format)
        ch.setLevel(logging.INFO)
        log.addHandler(ch)
        fh.setLevel(logging.WARNING)
    elif args.verbose >= 2:
        ch.setFormatter(con_format)
        ch.setLevel(logging.DEBUG)
        log.addHandler(ch)
        fh.setLevel(logging.DEBUG)
    elif args.quiet >= 1:
        fh.setLevel(logging.WARNING)
    else:
        ch.setFormatter(brief_format)
        ch.setLevel(logging.ERROR)
        log.addHandler(ch)
        fh.setLevel(logging.WARNING)

    fh.setFormatter(full_format)
    log.addHandler(fh)

    # log.debug(args)
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
    # log.debug(servicecat['access']['user']['roles'])
    #
    # Get the needed authentication token from the service catalog
    #
    try:
        token = servicecat["access"]["token"]["id"]
    except KeyError:
        log.error("Authentication Error! Check permissions for '{0}'.".format(
            username))
        sys.exit(1)
    #
    # Get the load balancer sub-catalog from the full service catalog
    #
    try:
        mylbcat = [cat for cat in servicecat["access"]["serviceCatalog"]
                   if cat["type"] == "rax:load-balancer"][0]
    except KeyError:
        log.error("Authentication Error! Check permissions for '{0}'.".format(
            username))
        sys.exit(1)
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
                mylburlbase = item
                break
        elif args.lbip:
            mylbid_l = [lbitem["id"] for lbitem in
                        lbinf["loadBalancers"] if
                        any(lbvips["address"] == args.lbip for
                            lbvips in lbitem["virtualIps"])
                        ]
            if mylbid_l:
                mylbip = args.lbip
                mylburlbase = item
                break

    if mylbid_l:
        lbreg = mylburlbase.partition('//')[2].partition('.')[0].upper()
        mylburl_l = []
        for item in mylbid_l:
            mylburl_l.append('/'.join([mylburlbase, str(item)]))
    else:
        log.warn("The specified load balancer was not found.")
        sys.exit(1)
    log.info("Region: {0}".format(lbreg))
    log.info("LB id(s):  {0}".format(mylbid_l))
    log.info("LB IP:  {0}".format(mylbip))
    log.debug("LB URL:  {0}".format(mylburl_l))
    lb_alst_url_l = []
    for item in mylburl_l:
        lb_alst_url_l.append('/'.join([item, 'accesslist']))

    # The documentation states a maximum of 10 per
    # bulk delete operation
    chunklength = 10

    # loop through all the LBs specified (or that share the IP)
    for lb_alst_url in lb_alst_url_l:

        target_lb = lb_alst_url.partition(
            '/loadbalancers/')[2].partition('/')[0]
        log.info('Target LB: {0}'.format(target_lb))

        if args.cmd in ['list', 'add', 'delete']:
            lb_alst = json.loads(
                upd_lb(requests.get, lb_alst_url, headers=hdrs).content
                )

            if args.cmd == 'list':
                print "Access list for LB id {0}:".format(target_lb)
                pprint_dict(lb_alst)

            elif args.cmd == 'add' or (
                    args.cmd == 'delete' and not args.listid):

                changelist_d = alst_changes(
                    lb_alst, args.net, chtype=args.cmd, ltype=args.listtype)
                log.debug("Change list: {0}:".format(
                    changelist_d))

                if changelist_d['delete']:
                    log.info('LB {0}: Removing obsoleted list items...'.format(
                        target_lb))
                    chgl_del_chunked = (
                        lambda l, n=chunklength:
                        [l[i:i+n] for i in range(0, len(l), n)]
                        )(changelist_d['delete'])
                    log.debug('Access list(s) to delete: {0}'.format(
                        chgl_del_chunked))
                    for item in chgl_del_chunked:
                        params = {"id": item}

                        upd_lb(requests.delete,
                               lb_alst_url,
                               headers=hdrs,
                               params=params)

                if changelist_d['add']:
                    log.info('LB {0}: Adding new list items...'.format(
                        target_lb))

                    chgl_add_d = dict()
                    chgl_add_d["accessList"] = changelist_d['add']
                    log.debug('New access list: {0}'.format(chgl_add_d))

                    upd_lb(requests.post,
                           lb_alst_url,
                           headers=hdrs,
                           data=chgl_add_d)

            else:  # if args.cmd = 'delete' and args.listid is not None
                log.debug('Current access list: {0}'.format(lb_alst))

                log.info('LB {0}: Removing requested list items...'.format(
                    target_lb))
                alst_del_l = [str(item["id"]) for item in
                              lb_alst["accessList"] if
                              item["id"] in args.listid]

                if alst_del_l:
                    alst_del_chunked = (
                        lambda l, n=chunklength:
                        [l[i:i+n] for i in range(0, len(l), n)]
                        )(alst_del_l)
                    log.debug('Access list(s) to delete: {0}'.format(
                        alst_del_chunked))
                    for item in alst_del_chunked:
                        params = {"id": item}
                        upd_lb(requests.delete,
                               lb_alst_url,
                               headers=hdrs,
                               params=params)
                else:
                    log.info(
                        'No item found in list: {0}'.format(args.listid))

        elif args.cmd == 'delete-all':
            log.info('LB {0}: Removing access list...'.format(target_lb))
            upd_lb(requests.delete, lb_alst_url, headers=hdrs)
