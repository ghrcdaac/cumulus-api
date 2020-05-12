
# py-Cumulus-api
Python client library that abstracts 
[CUMULUS API](https://cumulus-nasa.github.io/cumulus-api/?language=cURL#cumulus-api)
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
Either source the env.sh and create cumulus-api instance as 
```code
from cumulus_api import CumulusApi
cml = CumulusApi()
```
or add the path to the config file to CumulusAPI instance as
```code
from cumulus_api import CumulusApi
cml = CumulusApi("path/to/configFile")
```

Please see examples folder

## config
Example of a config file passed to cumulus-api instance
```angular2html
[DEFAULT]
INVOKE_BASE_URL=************
BASE_URL=************
CLIENT_ID=************************
USER_NAME=************
USER_PASSWORD=************
```

## env.sh
Example of setting up environment variables
```code
export INVOKE_BASE_URL=************
export BASE_URL=************
export CLIENT_ID=************************
export USER_NAME=************
export USER_PASSWORD=************
```
