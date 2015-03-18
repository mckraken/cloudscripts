lbssl.py
========

There should be no external dependancies beyond regular python.  Please let me know if you find some.  For the "list --query" it does assume a linux OS as it assumes openssl is callable through the subprocess module.

Authentication
--------------

For working with the API, (obviously) one needs to authenticate.  This script looks for authentication from command-line flags, environment variables, or a ~/.raxcreds "ini" style file in that order.  The .raxcreds file is assumed to have the following format:

::
	[raxcreds]
	username: <username>
	apikey: <apikey>
	region: <apikey>

Options
-------

### list

This command will just list out the current SSL configuration and any Certificate Mappings found.  There is an "experimental" --query flag which will also list out the valid domains contained in the certificates installed on the load balancer.

### add

This command will add another certificate mapping to the load balancer.  The certificates are currently assumed to be in files and the file locations passed as arguments to the program.  

If the --ssl flag is passed, then the certificates are installed instead in the main SSL configuration and SSL termination is enabled on port 443.

### update

This command is similar to "add" but updates a certificate mapping in place.  All arguments are optional as one has the ability to update any single item in the mapping (hostname, private key, certificate, ca certificate).  If you are not updating the domain, it can be used to specify the mapping to update rather than the id, if so desired.

If the --ssl flag is passed, the private key and certificate are currently required by the API to do the update on the main SSL configuration as currently we are only updating the certificates rather than any other option in the main SSL configuration.

### delete

This command can be used to delete one or more certificate mappings on the load balancer.  

If the --ssl flag is passed, the main SSL termination configuration is deleted.





