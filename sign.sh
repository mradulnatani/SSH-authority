#!/bin/bash

KEY="$1"
IDENTITY="$2"
PRINCIPALS="$3"
CA_KEY="/ssh-ca/id_rsa"

ssh-keygen -s "$CA_KEY" -I "$IDENTITY" -n "$PRINCIPALS" -V +1d "$KEY"
