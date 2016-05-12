import os
import shutil

from subprocess import call

# When running inside a container, it's important that the deployer has a way
# to provide key material and configuration data

# This script looks for two mounted volumes '/key' and '/config'. They can
# contain key material and configuration files respectively. If data is found
# in either of these volumes it will be used to over-write the defaults within
# the Anchor container.
# In the case that '/key' is empty. This script will generate a new private key
# and copy that over the one to be used by Anchor.
# In the case that '/config' is empty no action will be taken

# It's worth noting that the default location for key material can be modified
# in the config.json. That's really up to the deployer.

# The reason we have a separate /key volume is to trigger a new key to be
# created even if we want to use a default configuration.

newkey_newcert = ["openssl", "req", "-out", "/key/root-ca.crt", "-keyout",
                  "/key/root-ca-unwrapped.key", "-newkey", "rsa:4096", "-subj",
                  "/CN=Anchor Test CA", "-nodes", "-x509", "-days", "365"]

newcert_existkey = ["openssl", "req", "-new" "-out", "/key/root-ca.crt", "-key",
                  "/key/root-ca-unwrapped.key", "-subj", "/CN=Anchor Test CA",
                  "-nodes", "-x509", "-days", "365"]

#/key
#TODO: Exception handling
if os.path.isdir('/key'):
    if not os.path.exists('/key/root-ca-unwrapped.key'):
        #If the user for some reason has given us a certificate but no key, that
        #wont work, we'll create a new key and overwrite the certificate
        print "[container_bootstrap.py] Generating new key and new certificate"
        call(newkey_newcert)

    if os.path.exists('/key/root-ca-unwrapped.key'):
        if not os.path.exists('/key/root-ca.crt'):
            print "[container_bootstrap.py] Generating new certificate"
            call(newcert_existkey)

    #COPY KEY TO DEFAULT LOCATION WITHIN container
    shutil.copy2('/key/root-ca-unwrapped.key', 'CA/')
    shutil.copy2('/key/root-ca.crt', 'CA/')

    os.chmod('/key/root-ca-unwrapped.key', 0600)

#/config
if os.path.exists('/config/config.json'):
    shutil.copy2('/config/config.json','./')

call(['pecan','serve','config.py'])
