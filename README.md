# Peplink Router API for Python

This repository contains a Python module for interacting with the Peplink Router API.

    $ pip install git+https://github.com/whoigit/peplinkctl.git


## Command Line

The library also provides a command line utility:

    $ peplinkctl --help
    usage: peplinkctl [-h] -s SERVER [-c CLIENT] [-k] [-t TOKEN]
                      {create-client,get-token,get-status-wan-connection}

    $ PEPLINK_USER=admin \
      PEPLINK_PASSWORD=s3cr3t \
      peplinkctl -k -s https://192.168.1.1 create-client -c CLI
    CLIENT_ID="026a74c97807e2dc3385c99ce90f80f8"
    CLIENT_SECRET="75c61f25908c67a4d157cad9c6f7ca55"

    $ CLIENT_ID="026a74c97807e2dc3385c99ce90f80f8" \
      CLIENT_SECRET="75c61f25908c67a4d157cad9c6f7ca55" \
      peplinkctl -k -s https://192.168.1.1 get-token
    TOKEN="e527e5468d85a577e6620c0b5f1f253c"
    EXPIRATION="2025-01-26 23:24:06.471771+00:00"

    $ peplinkctl -k -s https://192.168.1.1 -t e527e5468d85a577e6620c0b5f1f253c \
        get-status-wan-connection | jq '."2"|{name,statusLed}'
    {
      "name": "Cellular",
      "statusLed": "green"
    }
