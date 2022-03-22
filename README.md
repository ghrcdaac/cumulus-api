
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

Please see examples folder

## config
Example of a config file passed to cumulus-api instance
```angular2html
[DEFAULT]
INVOKE_BASE_URL=************                     // Cumulus archive URL
S3URI_LAUNCHPAD_CERT=****                       // s3 URI  to LAUNCHPAD pfx file
LAUNCHPAD_PASSPHRASE_SECRET_NAME=*****         // LAUNCHPADPassphrase  secret id
LAUNCHPAD_URL=*****                           // most likely https://api.launchpad.nasa.gov/icam/api/sm/v1/gettoken
AWS_PROFILE=***                              // (Optional) Only if you want to run it locally
```

## env.sh
Example of setting up environment variables
```code
#!/usr/bash
export INVOKE_BASE_URL=************                      // Cumulus archive URL
export S3URI_LAUNCHPAD_CERT=****                        // s3 URI  to LAUNCHPAD pfx file
export LAUNCHPAD_PASSPHRASE_SECRET_NAME=*****          // LAUNCHPADPassphrase  secret id
export LAUNCHPAD_URL=*****                            // most likely https://api.launchpad.nasa.gov/icam/api/sm/v1/gettoken
export AWS_PROFILE=***                               // (Optional) Only if you want to run it locally
```
If you are running this tool locally you need to add your AWS_PROFILE name to the config
