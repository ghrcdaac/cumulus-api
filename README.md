
# py-Cumulus-api
Python client library that abstracts
[CUMULUS API](https://nasa.github.io/cumulus-api/)
 calls  to interact with the [Cumulus Framework](https://github.com/cumulus-nasa/cumulus), such as monitoring status or
 creating, editing, and deleting records. This is the same API that powers the
 [Cumulus dashboard](https://github.com/cumulus-nasa/cumulus-dashboard
).

## The use case
This python client library provides various utilities for developers to interact with
[Cumulus Framework](https://github.com/cumulus-nasa/cumulus)


## Installation
python setup.py install

## Usage
Either source env.sh file and create CumulusApi instance as
```code
from cumulus_api import CumulusApi
cml = CumulusApi()
```
or add the path to the config file config.cfg to CumulusAPI instance as
```code
from cumulus_api import CumulusApi
cml = CumulusApi("path/to/config.cfg")
```

Note: The order of precedence for instantiation is a provided token, EDL credentials, and lastly Launchpad. Ensure
that you are only setting the desired environment variables.

Please see examples folder

## config
Example of a config file passed to cumulus-api instance
```
[DEFAULT]
# Cumulus
INVOKE_BASE_URL=                    # Cumulus archive URL

# AWS
AWS_PROFILE=                        # The AWS profile
AWS_REGION=                         # The AWS region 

# EDL
CLIENT_ID=                          # URS application id
EDL_UNAME=                          # URS username
EDL_PWORD=                          # URS password

# Launchpad
LAUNCHPAD_PASSPHRASE=               # LAUNCHPAD Passphrase
LAUNCHPAD_PASSPHRASE_SECRET_NAME=   # AWS Secrets "Secret name" value for the launchpad password
LAUNCHPAD_URL=                      # most likely https://api.launchpad.nasa.gov/icam/api/sm/v1/gettoken
FS_LAUNCHPAD_CERT=                  # local path to LAUNCHPAD pfx file
S3URI_LAUNCHPAD_CERT=               # S3 URI of LAUNCHPAD pfx file
```

## env.sh
Example of setting up environment variables
```
# Cumulus
export INVOKE_BASE_URL=                    # Cumulus archive URL

# AWS
export AWS_PROFILE=                        # The AWS profile
export AWS_REGION=                         # The AWS region 

# EDL
export CLIENT_ID=                          # URS application id
export EDL_UNAME=                          # URS username
export EDL_PWORD=                          # URS password

# Launchpad
export LAUNCHPAD_PASSPHRASE=               # LAUNCHPAD Passphrase
export LAUNCHPAD_PASSPHRASE_SECRET_NAME=   # AWS Secrets "Secret name" value for the launchpad password
export LAUNCHPAD_URL=                      # most likely https://api.launchpad.nasa.gov/icam/api/sm/v1/gettoken
export FS_LAUNCHPAD_CERT=                  # local path to LAUNCHPAD pfx file
export S3URI_LAUNCHPAD_CERT=               # S3 URI of LAUNCHPAD pfx file
```
If you are running this tool locally and using AWS hosted launchpad credentials then you need to add your AWS_PROFILE 
name to the config.
