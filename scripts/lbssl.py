#!/usr/bin/python

#
#
#
#
#
#
#

'''
---------------
Base help:
---------------
usage: lbssl.py [-h] [--username USERNAME] [--apikey API_KEY]
                [--region REGION]
                {add,list,update,delete} ...

Manage certificate mappings for cloud load balancer.

positional arguments:
  {add,list,update,delete}
    list                list current mappings
    add                 add certificate mapping
    update              Update the certificate mapping
    delete              delete certificate mapping

optional arguments:
  -h, --help            show this help message and exit
  --username USERNAME   The username for the account (or use the OS_USERNAME
                        environment variable or the ~/.raxcreds file).
  --apikey API_KEY      The username for the account (or use the OS_PASSWORD
                        environment variable or the ~/.raxcreds file).
  --region REGION       The region for the loadbalancer (or use the
                        OS_REGION_NAME environment variable or the ~/.raxcreds
                        file).

---------------
"list" help:
---------------
usage: lbssl.py list [-h] [--query] LB-ID

positional arguments:
  LB-ID       The id of the load balancer.

optional arguments:
  -h, --help  show this help message and exit
  --query     Query the certificates for the valid domains.

---------------
"add" help:
---------------
usage: lbssl.py add [-h] [--domain DOMAIN] --key PRIVATE-KEY-FILE --crt
                    CERTIFICATE-FILE [--cacrt INTERMEDIATE-CERTIFICATE-FILE]
                    [--ssl]
                    LB-ID

positional arguments:
  LB-ID                 The id of the load balancer.

optional arguments:
  -h, --help            show this help message and exit
  --domain DOMAIN       The domain or hostname of the certificate.
  --key PRIVATE-KEY-FILE
                        The filename containing the private key.
  --crt CERTIFICATE-FILE
                        The filename containing the certificate.
  --cacrt INTERMEDIATE-CERTIFICATE-FILE
                        The filename containing the intermediate
                        certificate(s).
  --ssl                 enable SSL Termination and set this as default
                        certificate.

---------------
"update" help:
---------------
usage: lbssl.py update [-h] [--domain DOMAIN] [--cmap-id CERT-MAPPING-ID]
                       [--key PRIVATE-KEY-FILE] [--crt CERTIFICATE-FILE]
                       [--cacrt INTERMEDIATE-CERTIFICATE-FILE] [--ssl]
                       LB-ID

positional arguments:
  LB-ID                 The id of the load balancer.

optional arguments:
  -h, --help            show this help message and exit
  --domain DOMAIN       The hostname of the certificate to update.
  --cmap-id CERT-MAPPING-ID
                        The certificate mapping id number to update.
  --key PRIVATE-KEY-FILE
                        The filename containing the private key.
  --crt CERTIFICATE-FILE
                        The filename containing the certificate.
  --cacrt INTERMEDIATE-CERTIFICATE-FILE
                        The filename containing the intermediate
                        certificate(s).
  --ssl                 Update the default SSL certificate on the load
                        balancer.

---------------
"delete" help:
---------------
usage: lbssl.py delete [-h]
                       (--ssl | --cmap-id CERTIFICATE-MAPPING-ID
                        [CERTIFICATE-MAPPING-ID ...])
                       LB-ID

positional arguments:
  LB-ID                 The id of the load balancer.

optional arguments:
  -h, --help            show this help message and exit
  --ssl                 Delete the main SSL termination configuration.
  --cmap-id CERTIFICATE-MAPPING-ID [CERTIFICATE-MAPPING-ID ...]
                        The id(s) of the certificate mappings to delete.

'''

import os
import json
import requests
import argparse
import sys
import time


def pprint_dict(item):
    print json.dumps(item,
                     sort_keys=True,
                     indent=4,
                     separators=(',', ': '))


def wait_for_status(url, hdrs):
    start = time.time()
    while True:
        lbstatus = json.loads(
            requests.get(url, headers=hdrs).content
            )["loadBalancer"]["status"]
        print "Current status: {0} ... (elapsed: {1:4.1f} seconds)".format(
            lbstatus, (time.time() - start))
        if lbstatus in ['ACTIVE', 'ERROR']:
            return lbstatus
        else:
            time.sleep(15)


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


def add_map(url, headers=None, data={}):
    jdata = json.dumps(data)
    status_url = url.rpartition('/ssl')[0]
    print "Checking current load balancer status.",
    if wait_for_status(status_url, headers) == 'ERROR':
        print "Load balancer is in ERROR state."
        sys.exit(1)

    crtadd = requests.post(url, headers=headers, data=jdata)

    if crtadd.status_code == 202:
        if wait_for_status(status_url, headers) == 'ERROR':
            print "Load balancer is in ERROR state."
            sys.exit(1)
        print "Success!"
        return 0
    else:
        print "Error (code {0}):\n{1}".format(
            crtadd.status_code, crtadd.json()["message"])


def upd_map(url, headers=None, hostname=None, data={}):
    jdata = json.dumps(data)
    status_url = url.rpartition('/ssl')[0]
    print "Checking current load balancer status."
    if wait_for_status(status_url, headers) == 'ERROR':
        print "Load balancer is in ERROR state."
        sys.exit(1)

    crtupd = requests.put(url, headers=headers, data=jdata)

    if crtupd.status_code == 202:
        if wait_for_status(status_url, headers) == 'ERROR':
            print "Load balancer is in ERROR state."
            sys.exit(1)
        print "Success!"
        return 0
    else:
        print "Error (code {0}):\n{1}".format(
            crtupd.status_code, crtupd.json()["message"])


def del_maps(url, id_lst=None, headers=''):
    if id_lst is not None:
        for cmap_id in id_lst:
            cmap_delete_url = '/'.join([url, cmap_id])
            cmapdel = requests.delete(cmap_delete_url, headers=headers)
            status_url = url.rpartition('/ssl')[0]
            print "Deleting certificate mapping ID {0} ...".format(cmap_id)
            if cmapdel.status_code == 202:
                if wait_for_status(status_url, headers) == 'ERROR':
                    print "Load balancer is in ERROR state."
                    sys.exit(1)
                print "Success!"
            else:
                print "Error (code {0}):\n{1}".format(
                    cmapdel.status_code, cmapdel.json()["message"])
    else:
        ssldel = requests.delete(url, headers=headers)
        status_url = url.rpartition('/ssl')[0]
        print "Deleting SSL Termination..."
        if ssldel.status_code == 202:
            if wait_for_status(status_url, headers) == 'ERROR':
                print "Load balancer is in ERROR state."
                sys.exit(1)
            print "Success!"
        else:
            print "Error (code {0}):\n{1}".format(
                ssldel.status_code, ssldel.json()["message"])


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
    add_cmap_or_ssl = subparser_add.add_mutually_exclusive_group(required=True)
    add_cmap_or_ssl.add_argument(
        '--ssl', action='store_true',
        help='enable SSL Termination and set this as default certificate.')
    add_cmap_or_ssl.add_argument(
        '--domain', metavar="DOMAIN",
        help='The domain or hostname of the certificate.')
    subparser_add.add_argument(
        '--key', metavar="PRIVATE-KEY-FILE",
        help='The filename containing the private key. ')
    subparser_add.add_argument(
        '--crt', metavar="CERTIFICATE-FILE",
        help='The filename containing the certificate. ')
    subparser_add.add_argument(
        '--cacrt', metavar="INTERMEDIATE-CERTIFICATE-FILE",
        help='The filename containing the intermediate certificate(s).')

    subparser_upd = subparser.add_parser(
        'update',
        help='Update the certificate mapping')
    subparser_upd.add_argument(
        'lbid', metavar="LB-ID",
        help='The id of the load balancer.')
    subparser_upd.add_argument(
        '--domain', metavar="DOMAIN",
        help='The hostname of the certificate to update.')
    subparser_upd.add_argument(
        '--cmap-id', metavar="CERT-MAPPING-ID", dest='cmid', type=int,
        help='The certificate mapping id number to update.')
    subparser_upd.add_argument(
        '--key', metavar="PRIVATE-KEY-FILE",
        help='The filename containing the private key. ')
    subparser_upd.add_argument(
        '--crt', metavar="CERTIFICATE-FILE",
        help='The filename containing the certificate. ')
    subparser_upd.add_argument(
        '--cacrt', metavar="INTERMEDIATE-CERTIFICATE-FILE",
        help='The filename containing the intermediate certificate(s).')
    subparser_upd.add_argument(
        '--ssl', action='store_true',
        help='Update the default SSL certificate on the load balancer.')

    subparser_del = subparser.add_parser(
        'delete', help='delete certificate mapping')
    subparser_del.add_argument(
        'lbid', metavar="LB-ID",
        help='The id of the load balancer.')
    del_cmap_or_ssl = subparser_del.add_mutually_exclusive_group(required=True)
    del_cmap_or_ssl.add_argument(
        '--ssl', action='store_true',
        help='Delete the main SSL termination configuration.')
    del_cmap_or_ssl.add_argument(
        '--cmap-id', metavar="CERTIFICATE-MAPPING-ID",
        dest='cmap_ids', nargs='+',
        help='The id(s) of the certificate mappings to delete.')

    return parser.parse_args()


def read_cert_file(f):
    try:
        with open(f, 'r') as infile:
            return infile.read()
    except IOError:
        print "Unable to open file {0}".format(f)
        sys.exit(1)


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
                    "echo | openssl s_client -connect " + ip + ":" +
                    str(port) + " -servername " + servername,
                    stderr=fnull,
                    shell=True)
                    )
            else:
                rcrt1.write(subprocess.check_output(
                    "echo | openssl s_client -connect " + ip + ":" + str(port),
                    stderr=fnull,
                    shell=True)
                    )
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


def read_cert_input(crt_type, verify_f=None):
    import tempfile
    # import subprocess
    label = {
        'key': 'private key',
        'crt': 'certificate',
        'cacrt': 'CA cerificates'
        }
    verify_cmd = {
        'key': verify_key,
        'crt': verify_crt,
        'cacrt': verify_cacrt,
        }
    tries = 1
    sentinel = ""
    print "Input the {0} (end with blank line):".format(label[crt_type])
    if verify_f is None:
        v_fn = None
    else:
        v_fn = verify_f.name
    with tempfile.NamedTemporaryFile(delete=False) as rawcert:
        while tries <= 3:
            if tries != 1:
                print "Try again (try {0} of 3):".format(tries)
            rawcert.write('\n'.join(iter(raw_input, sentinel)))
            rawcert.flush()
            rawcert.seek(0)
            if verify_cmd[crt_type](rawcert.name, v_fn):
                return rawcert
            else:
                tries += 1
                print "Invalid input.",
                rawcert.truncate()
        print "Aborting."
        rawcert.close()
        os.unlink(rawcert.name)
        return None


def verify_key(k_fn, v_f=None):
    import subprocess
    v_cmd = ["openssl", "rsa", "-check", "-noout", "-in", k_fn]
    v_rslt = 'RSA key ok'
    try:
        v_input = subprocess.check_output(
            v_cmd, stderr=subprocess.STDOUT).strip('\n')
        if v_input != v_rslt:
            print "Bad key...",
            return False
        else:
            return True
    except:
        print "Bad key...",
        return False


def verify_crt(c_fn, k_fn):
    import subprocess
    from datetime import datetime
    v_cmd = ["openssl", "x509", "-noout", "-in", c_fn]
    v_rslt = ''
    try:
        v_input = subprocess.check_output(
            v_cmd, stderr=subprocess.STDOUT).strip('\n')
        if v_input != v_rslt:
            print "Bad certificate...",
            return False
        else:
            cmod_cmd = ["openssl", "x509", "-modulus", "-noout", "-in", c_fn]
            kmod_cmd = ["openssl", "rsa", "-modulus", "-noout", "-in", k_fn]
            crt_mod = subprocess.check_output(
                cmod_cmd, stderr=subprocess.STDOUT).strip('\n')
            key_mod = subprocess.check_output(
                kmod_cmd, stderr=subprocess.STDOUT).strip('\n')
            if crt_mod == key_mod:
                edat_cmd = ["openssl", "x509", "-enddate", "-noout",
                            "-in", c_fn]
                crt_edat = subprocess.check_output(
                    edat_cmd, stderr=subprocess.STDOUT
                    ).strip('\n').partition('=')[2].rstrip(' GMT')
                format = '%b %d %H:%M:%S %Y'
                crt_end = datetime.strptime(crt_edat, format)
                now_utc = datetime.utcnow()
                days_to_expiration = (crt_end - now_utc).days
                if days_to_expiration <= 0:
                    print "Error:  Certificate has expired."
                    return False
                else:
                    print "Certificate is valid for {0} more days.".format(
                        days_to_expiration)
                    return True
            else:
                print "ERROR: The certificate does not match the private key!"
                return False
    except:
        print "Bad certificate...",
        return False
    pass


def verify_cacrt(cac_fn, c_fn):
    import subprocess
    v_cmd = ["openssl", "x509", "-noout", "-in", cac_fn]
    v_rslt = ''
    try:
        v_input = subprocess.check_output(
            v_cmd, stderr=subprocess.STDOUT).strip('\n')
        if v_input != v_rslt:
            print '0'
            print "Bad certificate...",
            return False
        else:
            v_rslt = 'OK'
            vchain_cmd = ["openssl", "verify", "-CAfile", cac_fn, c_fn]
            vchain_out = subprocess.check_output(
                vchain_cmd, stderr=subprocess.STDOUT).strip('\n')
            if vchain_out.partition(' ')[2] != v_rslt:
                print "ERROR: The certificate chain does not",
                print "verify with the certificate."
                return False
            else:
                return True
    except:
        print '1'
        print "Bad certificate...",
        return False
    pass


def close_and_exit(f_lst, ecode=1):
    for item in f_lst:
        item.close
        os.unlink(item.name)
    sys.exit(ecode)


if __name__ == "__main__":
    args = process_args()

    print args

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
    # region of the load balancer is needed
    #
    region = check_arg_or_env("region",
                              args.region,
                              "OS_REGION_NAME").lower()
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
    # lbinf_ssl = json.loads(requests.get(lburl_ssl, headers=hdrs).content)
    lbinf_cmap = json.loads(requests.get(lburl_cmap, headers=hdrs).content)

    if args.cmd == 'list':
        lst_maps(lbinf["loadBalancer"], lbinf_cmap, args.query)

    elif args.cmd == 'add':
        exitcode = 0
        certs = dict()
        t_flst = []

        if not args.ssl:
            certs["hostName"] = args.domain
        else:
            certs["enabled"] = True
            certs["securePort"] = 443

        if args.key is not None and os.path.isfile(
                os.path.expanduser(args.key)):
            if not verify_key(args.key):
                print "(in {0})".format(args.key)
                close_and_exit(t_flst)
            key_fn = args.key

            if args.ssl:
                certs['privatekey'] = read_cert_file(args.key)
            else:
                certs['privateKey'] = read_cert_file(args.key)

        else:
            if args.key is not None:
                print "{0} is not found.".format(args.key),
                print "Trying input from the command line."
            key_f = read_cert_input('key')
            if key_f is None:
                close_and_exit(t_flst)
            t_flst.append(key_f)
            key_fn = key_f.name

        if args.crt is not None and os.path.isfile(
                os.path.expanduser(args.crt)):
            if not verify_crt(args.crt, key_fn):
                print "(in {0})".format(args.crt)
                close_and_exit(t_flst)
            crt_fn = args.crt
            certs['certificate'] = read_cert_file(args.crt)
        else:
            if args.crt is not None:
                print "{0} is not found.".format(args.crt),
                print "Trying input from the command line."
            crt_f = read_cert_input('crt', key_f)
            if crt_f is None:
                close_and_exit(t_flst)
            t_flst.append(crt_f)
            crt_fn = crt_f.name

        if os.path.isfile(os.path.expanduser(args.cacrt)):
            if not verify_cacrt(args.cacrt, crt_fn):
                print "(in {0})".format(args.cacrt)
                close_and_exit(t_flst)
            certs['intermediateCertificate'] = read_cert_file(args.cacrt)
        else:
            if args.cacrt is not None:
                print "{0} is not found.".format(args.crt),
                print "Trying input from the command line."
            cacrt_f = read_cert_input('cacrt', crt_f)
            if cacrt_f is None:
                close_and_exit(t_flst)
            t_flst.append(cacrt_f)
            cacrt_fn = crt_f.name

        exitcode = 1
        if exitcode:
            close_and_exit(t_flst)
            sys.exit(exitcode)

        if not args.ssl:
            certdata = dict()
            certdata['certificateMapping'] = certs
            add_map(lburl_cmap, hdrs, data=certdata)
        else:
            certdata = dict()
            certdata['sslTermination'] = certs
            upd_map(lburl_ssl, hdrs, data=certdata)

    elif args.cmd == 'update':
        if not args.ssl:
            if args.cmid:
                mycmapid = [cmap["certificateMapping"]["id"] for cmap in
                            lbinf_cmap["certificateMappings"] if
                            cmap["certificateMapping"]["id"] == args.cmid]
            elif args.domain:
                mycmapid = [cmap["certificateMapping"]["id"] for cmap in
                            lbinf_cmap["certificateMappings"] if
                            cmap["certificateMapping"]["hostName"] ==
                            args.domain]
            else:
                print "Error: One of either --domain (hostname) or --cmap-id",
                print "must be specified for which configuration to update."
                sys.exit(1)
            if not mycmapid:
                print "Error: The specified certificate mapping was not found."
                sys.exit(1)

        certs = dict()
        exitcode = 0
        update = 0
        if args.domain and not args.ssl:
            certs["hostName"] = args.domain
            update = 1
        if args.ssl:
            certs["enabled"] = True
            certs["securePort"] = 443
        if args.key is not None:
            if os.path.isfile(os.path.expanduser(args.key)):
                if args.ssl:
                    certs['privatekey'] = read_cert_file(args.key)
                else:
                    certs['privateKey'] = read_cert_file(args.key)
                update = 1
            else:
                print "Error: Private key file {0} not found.".format(args.key)
                exitcode = 1
        if args.crt is not None:
            if os.path.isfile(os.path.expanduser(args.crt)):
                certs['certificate'] = read_cert_file(args.crt)
                update = 1
            else:
                print "Error: Certificate file {0} not found.".format(args.crt)
                exitcode = 1
        if args.cacrt is not None:
            if os.path.isfile(os.path.expanduser(args.cacrt)):
                certs['intermediateCertificate'] = read_cert_file(args.cacrt)
                update = 1
            else:
                print "Error: CA Certificate file {0} not found.".format(
                    args.cacrt)
                exitcode = 1
        if exitcode:
            sys.exit(exitcode)

        if update:
            if not args.ssl:
                certdata = dict()
                certdata['certificateMapping'] = certs
                upd_url = '/'.join([lburl_cmap, str(mycmapid[0])])
                upd_map(upd_url, hdrs, data=certdata)
            else:
                certdata = dict()
                certdata['sslTermination'] = certs
                upd_map(lburl_ssl, hdrs, data=certdata)
        else:
            print "Error: Nothing to update"
            sys.exit(1)

    elif args.cmd == 'delete':
        if not args.ssl:
            del_maps(lburl_cmap, args.cmap_ids, headers=hdrs)
        else:
            del_maps(lburl_ssl, headers=hdrs)
#
