
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
```angular2html
[DEFAULT]
INVOKE_BASE_URL=************       // Cumulus archive URL
BASE_URL=************              // URS URL (https://uat.urs.earthdata.nasa.gov/)

# EDL
CLIENT_ID=************************ // URS application id
USER_NAME=************             // URS username
USER_PASSWORD=************         // URS password

# Launchpad
LAUNCHPAD_CERT=****                // path to LAUNCHPAD pfx file
LAUNCHPAD_PASSPHRASE=*****         // LAUNCHPAD Passphrase
LAUNCHPAD_URL=*****                // most likely https://api.launchpad.nasa.gov/icam/api/sm/v1/gettoken
```

## env.sh
Example of setting up environment variables
```code
INVOKE_BASE_URL=************       // Cumulus archive URL
BASE_URL=************              // URS URL (https://uat.urs.earthdata.nasa.gov/)

# EDL
CLIENT_ID=************************ // URS application id
USER_NAME=************             // URS username
USER_PASSWORD=************         // URS password

# Launchpad
LAUNCHPAD_CERT=****                // path to LAUNCHPAD pfx file
LAUNCHPAD_PASSPHRASE=*****         // LAUNCHPAD Passphrase
LAUNCHPAD_URL=*****                // most likely https://api.launchpad.nasa.gov/icam/api/sm/v1/gettoken
```
If you are running this tool locally then you need to add your AWS_PROFILE name to the config.
