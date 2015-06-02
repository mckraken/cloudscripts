lbssl.py
========

This is written using python 2.7 and now really depends also on openssl being callable as a subprocess.  This is used to verify the keys and certificates entered.

Authentication
--------------

For working with the API, (obviously) one needs to authenticate.  This script looks for authentication from command-line flags, environment variables, or a ~/.raxcreds "ini" style file in that order.  The .raxcreds file is assumed to have the following format:

    [raxcreds]
    username: <username>
    apikey: <apikey>
    region: <region>

Options
-------

### list

This command will just list out the current SSL configuration and any Certificate Mappings found.  There is a --query flag which will also list out the valid domains contained in the certificates installed on the load balancer (This is not part of the API, but from calls to openssl.)

### add

This command will add another certificate mapping to the load balancer.  The certificates are can be in files and the file locations passed as arguments to the program or they will be read from the command line.

If the --ssl flag is passed, then the certificates are installed instead in the main SSL configuration and SSL termination is enabled on port 443.

### update

This command is similar to "add" but updates a certificate mapping in place.  All arguments are optional as one has the ability to update any single item in the mapping (hostname, private key, certificate, ca certificate).  If you are not updating the domain, it can be used to specify the mapping to update rather than the id, if so desired.

If the --ssl flag is passed, the private key and certificate are currently required by the API to do the update on the main SSL configuration as currently we are only updating the certificates or key rather than any other configuration option in the main SSL configuration.

### delete

This command can be used to delete one or more certificate mappings on the load balancer.  

If the --ssl flag is passed, the main SSL termination configuration is deleted.





