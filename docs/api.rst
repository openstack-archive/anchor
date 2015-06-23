API version 1
=============

The following endpoints are available in version 1 of the API.

/robots.txt (GET)
-----------------

Prevents attempts to index the service.

/v1/sign/<registration_authority> (POST)
----------------------------------------

Requests signing of the CSR provided in the POST parameters. The request is
processed by the selected virtual registration authority.

Request parameters
~~~~~~~~~~~~~~~~~~

* ``user``: username used in authentication (optional)
* ``secret``: secret used in authentication
* ``encoding``: request encoding - currently supported: "pem"
* ``csr``: the text of the submitted CSR

Result
~~~~~~

Signed certificate
