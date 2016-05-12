import os
import shutil

from subprocess import call

import logging

logging.basicConfig()
logger = logging.getLogger('Anchor_Bootstrap')
logger.setLevel(logging.DEBUG)

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

newkey_newcert = ["openssl", "req", "-out", "CA/root-ca.crt", "-keyout",
                  "CA/root-ca-unwrapped.key", "-newkey", "rsa:4096", "-subj",
                  "/CN=Anchor Test CA", "-nodes", "-x509", "-days", "365"]

newcert_existkey = ["openssl", "req", "-new" "-out", "CA/root-ca.crt", "-key",
                  "/key/root-ca-unwrapped.key", "-subj", "/CN=Anchor Test CA",
                  "-nodes", "-x509", "-days", "365"]

# Anchor containers no longer build with built in keys. See if a deployer has
# provided a key, if they have, use that. If not then build one now. The key
# built in this way will disappear along with the container.
if os.path.exists('/key/root-ca-unwrapped.key'):
  if os.path.exists('/key/root-ca.crt'):
    # Provided both a key and a certificate
    logger.info("Private key and certificate provided")
    shutil.copy2('/key/root-ca-unwrapped.key', 'CA/')
    shutil.copy2('/key/root-ca.crt', 'CA/')
    os.chmod('CA/root-ca-unwrapped.key', 0400)
  else:
    # Provided key but no certificate
    logger.info("Key provided without certificate. Generating certificate")
    call(newcert_existingkey)
    shutil.copy2('/key/root-ca-unwrapped.key', 'CA/')
    os.chmod('CA/root-ca-unwrapped.key', 0400)
else:
  logger.info("""No key provided.
                 To use the anchor container with the same key each time you
                 must create it and provide a key volume to docker.""")
  logger.info("Generating new key and certificate")
  call(newkey_newcert) #No key or cert provided. Possibly no /key volume at all
  os.chmod('CA/root-ca-unwrapped.key', 0400)


# If the user has provdided a config file in a /config volume, use that
#/config
if os.path.exists('/config/config.json'):
    shutil.copy2('/config/config.json','./')

if os.path.exists('/config/config.py'):
    shutil.copy2('/config/config.py','./')

#Start the pecan service
call(['pecan','serve','config.py'])
