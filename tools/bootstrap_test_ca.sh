#!/bin/bash

openssl req -x509 -newkey rsa:384 -keyout CA/root-ca-unwrapped.key -out CA/root-ca.crt -nodes -batch
