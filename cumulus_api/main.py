import json
import logging
import os
import re
from configparser import ConfigParser
from json.decoder import JSONDecodeError
from types import SimpleNamespace

import boto3
from requests import Session

from .cumulus_token import CumulusToken


# pylint: disable=too-many-public-methods
class CumulusApi:
    def __init__(self, token=None, config_path=None):
        """
        Initiate cumulus API instance, by default it reads from OS environment
        :param token: Earthdata token
        :param config_path: absolute or relative path to config file or directory
        """
        self.allowed_verbs = SimpleNamespace(GET='GET', PATCH='PATCH', POST='POST', PUT='PUT', DELETE='DELETE')
        self.TOKEN = token
        self.cumulus_token = None
        self.auth = None
        self.HEADERS = None

        if not config_path:
            values = [
                'INVOKE_BASE_URL', 'EDL_UNAME', 'EDL_PWORD', 'CLIENT_ID', 'AWS_PROFILE', 'AWS_REGION',
                'LAUNCHPAD_PASSPHRASE_SECRET_NAME', 'LAUNCHPAD_PASSPHRASE', 'FS_LAUNCHPAD_CERT', 'S3URI_LAUNCHPAD_CERT',
                'LAUNCHPAD_URL', 'PRIVATE_API_LAMBDA_ARN'
            ]
            config = {x: os.getenv(x) for x in values if x in os.environ}

        else:
            config_parser = ConfigParser(interpolation=None)
            config_parser.optionxform = str
            config_parser.read(config_path)
            config = dict(config_parser['DEFAULT'])

        if 'PRIVATE_API_LAMBDA_ARN' not in config:
            self.crud_function = self.__use_endpoints
            self.config = config
            self.INVOKE_BASE_URL = self.config['INVOKE_BASE_URL'].rstrip('/')

            if 'EDL_UNAME' in config and 'EDL_PWORD' in config:
                self.auth = (config.get('EDL_UNAME'), config.get('EDL_PWORD'))
                if not self.TOKEN:
                    self.TOKEN = self.get_token().get('message').get('token')
            else:
                self.cumulus_token = CumulusToken(config=config)
                self.TOKEN = self.cumulus_token.get_token()

            self.HEADERS = {
                'Authorization': f'Bearer {self.TOKEN}',
                'Cumulus-API-Version': '2',
            }

        else:
            self.crud_function = self.__use_private_api_lambda

    def __use_endpoints(self, record_type, verb, data=None, auth=None, **kwargs):
        """
        :param verb: HTTP requests verbs GET|POST|PUT|DELETE
        :param record_type: Provider | Collection | PDR ...
        :param data: json data to be ingested
        :return: False in case of error
        """
        session = Session()
        url = f"{self.INVOKE_BASE_URL}/v1/{record_type}"
        and_sign = ""
        query = ""
        for key, value in kwargs.items():
            query = f"{query}{and_sign}{key}={value}"
            and_sign = "&"
        if kwargs:
            url = f"{url}?{query}"
        rsp = getattr(session, verb.lower())(url=url, json=data, headers=self.HEADERS, auth=auth)
        if re.search('https://.*urs.earthdata.nasa.gov/oauth/authorize', rsp.url):
            rsp = session.get(rsp.url, auth=auth)
        try:
            return rsp.json()
        except JSONDecodeError:
            logging.error(f'Cumulus API response was not valid JSON: {rsp}')
            raise

    @staticmethod
    def __add_query_string_parameters(**kwargs):
        qsp = {}
        if 'searchContext' in kwargs:
            # We need to slice the search context string to remove the first and last 3 characters as there are extra
            # characters that will cause an error. Example %5B1692388761773%5D
            context_list = [kwargs.pop('searchContext')[3:-3]]
            # The searchContext must be a list containing a json string of a list ['[1234]']
            qsp.update({'searchContext': json.dumps(context_list)})

        for k, v in kwargs.items():
            temp_lst = [str(v)]
            qsp.update({k: temp_lst})

        return qsp

    def __use_private_api_lambda(self, record_type, verb, data='', **kwargs):
        boto3.setup_default_session(profile_name=os.getenv('AWS_PROFILE'))
        client = boto3.client('lambda')
        # Payload Reference: https://github.com/nasa/cumulus/blob/v15.0.4/packages/api-client/src/types.ts#L6-L13
        payload = {
            "httpMethod": verb,
            "resource": "/{proxy+}",
            "path": f"/{record_type}",
            "headers": {
                "Content-Type": "application/json",
                "Cumulus-API-Version": "2"
            },
            "queryStringParameters": self.__add_query_string_parameters(**kwargs) if kwargs else '',
            "body": json.dumps(data) if data else ''
        }
        rsp = client.invoke(
            FunctionName=os.getenv('PRIVATE_API_LAMBDA_ARN'),
            Payload=json.dumps(payload).encode()
        )
        lambda_payload = json.loads(rsp.get('Payload').read())
        body = lambda_payload.get('body')
        try:
            return json.loads(body)
        except JSONDecodeError:
            logging.error(f'Cumulus API response was not valid JSON: {body}')
            raise

    def __crud_records(self, **kwargs):
        return self.crud_function(**kwargs)

    # ============== Version ===============
    def get_version(self):
        """
        Get cumulus API version
        :return:
        """
        return self.__crud_records(record_type="version", verb=self.allowed_verbs.GET)

    # ============== Token ==================
    def get_token(self):
        return self.__crud_records(
            record_type='token', verb=self.allowed_verbs.GET, auth=self.auth
        )

    def refresh_token(self):
        """
        Refreshes a bearer token received from oAuth with Earthdata Login service.
        The token will be returned as a JWT (JSON Web Token).
        :return: True if the token is refreshed
        """
        if self.cumulus_token:
            self.TOKEN = self.cumulus_token.get_token()
        else:
            data = {"token": self.TOKEN}
            refreshed_token = self.__crud_records(record_type="refresh", verb=self.allowed_verbs.POST, data=data)
            self.TOKEN = refreshed_token
        self.HEADERS = {
            'Authorization': f'Bearer {self.TOKEN}',
            'Cumulus-API-Version': '2',
        }

        return self.TOKEN

    def delete_token(self):
        """
        Delete the record for an access token received from oAuth with
        Earthdata Login service.
        :return: Message the token was deleted
        """
        record_type = f"tokenDelete/{self.TOKEN}"
        self.TOKEN = None
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.DELETE)

    # ============== Providers ===============

    def list_providers(self, **kwargs):
        """
        List granules in the Cumulus system
        :param kwargs: cumulus query strings and parameters
        :return:
        """
        record_type = "providers"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def get_provider(self, provider_id, **kwargs):
        """
        Get a provider
        :param provider_id: cumulus provider id
        :param kwargs: cumulus query strings and parameters
        :return:
        """
        record_type = f"providers/{provider_id}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def create_provider(self, data):
        """
        Create a New provider
        :param data: json object containing granule definition
        :return: request response
        """
        record_type = "providers"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data)

    def update_provider(self, data):
        """
        Update values for a provider
        :param data: json object containing provider definition
        :return: message of success or raise error
        """
        record_type = f"providers/{data['id']}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.PUT, data=data)

    def delete_provider(self, provider_id):
        """
        Delete a provider
        :param provider_id: cumulus provider id
        :return:
        """
        record_type = f"providers/{provider_id}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.DELETE)

    # ============== Collections ===============

    def list_collections(self, **kwargs):
        """
        List collections in the Cumulus system
        :param kwargs: cumulus query strings and parameters
        :return: Request response
        """
        record_type = "collections"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def list_collections_with_active_granules(self, **kwargs):
        """
        List collections in the Cumulus system that have active associated granules.
        :param kwargs: cumulus query strings and parameters
        :return: Request response
        """
        record_type = "collections/active"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def get_collection(self, collection_name, collection_version, **kwargs):
        """
        Get a collection
        :param collection_name: cumulus collection name
        :param collection_version: cumulus collection version
        :param kwargs: cumulus query strings and parameters
        :return:
        """
        record_type = f"collections/{collection_name}/{collection_version}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def create_collection(self, data):
        """
        Create a New collection
        :param data: json object containing a collection definition
        :return: request response
        """
        record_type = "collections"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data)

    def update_collection(self, data):
        """
        Update values for a collection
        :param data: json object containing updated collection definition
        the ones that are being updated.
        :return:
        """
        record_type = f"collections/{data['name']}/{data['version']}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.PUT, data=data)

    def delete_collection(self, collection_name, collection_version):
        """
        Delete a collection from Cumulus, but not from CMR.
        All related granules in Cumulus must have already been deleted from Cumulus.
        :param collection_name: cumulus collection name
        :param collection_version: cumulus collection version
        :return:
        """
        record_type = f"collections/{collection_name}/{collection_version}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.DELETE)

    # ============== Granules ===============

    def list_granules(self, **kwargs):
        """
        List granules in the Cumulus system
        :param kwargs: cumulus query strings and parameters
        :return:
        """
        record_type = "granules"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def get_granule(self, collection_id='', granule_id='', **kwargs):
        """
        Get a granule
        :param granule_id: cumulus granule id
        :param collection_id: ID of the collection the granule belongs to
        :param kwargs: cumulus query strings and parameters
        :return:
        """
        if collection_id:
            collection_id = f'{collection_id}/'
        record_type = f"granules/{collection_id}{granule_id}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def create_granule(self, data):
        """
        Create a granule
        :param data: json object containing granule definition
        :return: Request response
        """
        record_type = "granules"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data)

    def update_granule(self, data):
        """
        Updates a granule
        :param data: json object containing updated granule definition
        :return: Request response
        """
        collection_id = data.get('collectionId', '')
        if collection_id:
            collection_id = f'{collection_id}/'
        record_type = f"granules/{collection_id}{data.get('granuleId')}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.PATCH, data=data)

    def associate_execution(self, data):
        """
        Associate an execution with a granule
        :param data: json object containing execution definition
        :return: Request response
        """
        record_type = f"granules/{data['granuleId']}/executions"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data)

    def reingest_granule(self, granule_id, data=None):
        """
        Reingest a granule. This causes the granule to re-download to Cumulus from source,
        and begin processing from scratch. Reingesting a granule will overwrite existing
        granule files.
        :param granule_id: cumulus granule id
        :param data: json object containing reingest definition
        :return:
        """
        record_type = f"granules/{granule_id}"
        data = {} if data is None else data
        data.update({"action": "reingest"})
        return self.__crud_records(record_type=record_type, data=data, verb=self.allowed_verbs.PATCH)

    def apply_workflow_to_granule(self, granule_id, workflow_name):
        """
        Apply the named workflow to the granule. Workflow input will be built from template
        and provided entire Cumulus granule record as payload.
        :param granule_id: cumulus granule id
        :param workflow_name: cumulus workflow name
        :return: status message
        """
        record_type = f"granules/{granule_id}"
        data = {"action": "applyWorkflow", "workflow": workflow_name}
        return self.__crud_records(record_type=record_type, data=data, verb=self.allowed_verbs.PATCH)

    def move_granule(self, granule_id, regex, bucket, file_path):
        """
        Move a granule from one location on S3 to another. Individual files are moved to
        specific locations by using a regex that matches their filenames.
        :param granule_id: cumulus granule id
        :param regex: regex to match granule names to move
        :param bucket: bucket where the granule is located
        :param file_path: new file path
        :return:
        """
        record_type = f"granules/{granule_id}"
        data = {"action": "move",
                "destinations": [{"regex": regex, "bucket": bucket, "filepath": file_path}]}
        return self.__crud_records(record_type=record_type, data=data, verb=self.allowed_verbs.PATCH)

    def remove_granule_from_cmr(self, granule_id):
        """
        Remove a Cumulus granule from CMR.
        :param granule_id: cumulus granule id
        :return:
        """
        record_type = f"granules/{granule_id}"
        data = {"action": "removeFromCmr"}
        return self.__crud_records(record_type=record_type, data=data, verb=self.allowed_verbs.PATCH)

    def replace_granule(self, data):
        record_type = f'granules/{data.get("collection_id")}/{data.get("granule_id")}'
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.PUT, data=data)

    def delete_granule(self, collection_id='', granule_id=''):
        """
        Delete a granule from Cumulus. It must already be removed from CMR.
        :param granule_id:
        :param collection_id:
        :return:
        """
        if collection_id:
            collection_id = f'{collection_id}/'
        record_type = f"granules/{collection_id}{granule_id}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.DELETE)

    def granules_bulk_op(self, data):
        """
        Apply a workflow to the granules provided
        :param data:
        :return:
        """
        record_type = "granules/bulk"
        return self.__crud_records(record_type=record_type, data=data, verb=self.allowed_verbs.POST)

    def bulk_delete(self, data):
        """
        Bulk delete the provided granules
        :param data: format: https://nasa.github.io/cumulus-api/#bulk-delete
        {forceRemoveFromCmr: true/false,
        }
        :return: Request response
        """
        record_type = "granules/bulkDelete"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data)

    def bulk_reingest(self, data):
        """
        Bulk reingest the provided granules
        :return: Request response
        """
        record_type = "granules/bulkReingest"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data)

    # ============== PDRs ===============

    def list_pdrs(self, **kwargs):
        """
        List PDRs in the Cumulus system.
        :param kwargs: Query terms in the form of key=value
        :return: Request response
        """
        record_type = "pdrs"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def get_pdr(self, pdr_name, **kwargs):
        """
        Get a pdr
        :param pdr_name:
        :param kwargs: Cumulus query strings and parameters
        :return:
        """
        record_type = f"pdrs/{pdr_name}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def delete_pdr(self, pdr_name):
        """
        Delete a PDR from Cumulus
        :return: Request response
        """
        record_type = f"pdrs/{pdr_name}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.DELETE)

    # ============== Rules ===============

    def list_rules(self, **kwargs):
        """
        List rules in the Cumulus system.
        :param kwargs: Cumulus query strings and parameters
        :return:
        """
        record_type = "rules"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def get_rule(self, rule_name, **kwargs):
        """
        Get a rule
        :param rule_name:
        :param kwargs: Cumulus query strings and parameters
        :return:
        """
        record_type = f"rules/{rule_name}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def create_rule(self, data):
        """
        Create a rule
        :param data: json object
        :return:
        """
        record_type = "rules"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data)

    def update_rule(self, data):
        """
        Update state and/or rule.value of a rule.
        :param data: Can accept the whole rule object, or just a subset of fields, the ones that
        are being updated.
        :return: Returns a mapping of the updated properties.
        """
        record_type = f"rules/{data['name']}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.PATCH, data=data)

    def replace_rule(self, data):
        """
        Replace an existing rule. Expects payload to specify the entire rule object, and will
        completely replace the existing rule with the specified payload.
        :param data: json definition of the rule
        :return: update response
        """
        record_type = f"rules/{data.get('name')}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.PUT, data=data)

    def delete_rule(self, rule_name):
        """
        Delete a rule from cumulus
        :param rule_name: rule name
        :return:
        """
        record_type = f"rules/{rule_name}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.DELETE)

    def run_rule(self, rule_name):
        """
        Run a rule
        :param rule_name: rule name
        :return: object
        """
        record_type = f"rules/{rule_name}"
        data = {"name": rule_name, "action": "rerun"}
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.PUT, data=data)

    # ============== Stats ===============

    def get_stats_summary(self):
        """
        Retrieve a summary of various metrics for all of the Cumulus engine
        :return:
        """
        record_type = "stats"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET)

    def get_stats_aggregate(self, **kwargs):
        """
        Count the value frequencies for a given field, for a given type of record in Cumulus
        :param kwargs: Cumulus query strings and parameters
        :return:
        """
        record_type = "stats/aggregate"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    # ============== Logs ===============

    def list_logs(self, **kwargs):
        """
        List processing logs from the Cumulus engine. A log's level field may be either info or
        error.
        :param kwargs: Cumulus query strings and parameters
        :return:
        """
        record_type = "logs"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def get_log(self, execution_name, **kwargs):
        """
        Get a log
        :param execution_name:
        :param kwargs: Cumulus query strings and parameters
        :return:
        """
        record_type = f"logs/{execution_name}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    # ============== Executions ===============

    def list_executions(self, **kwargs):
        """
        List executions in the Cumulus system.
        :param kwargs: Cumulus query strings and parameters
        :return: Request response
        """
        record_type = "executions"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def get_execution(self, execution_arn, **kwargs):
        """
        Get an execution
        :param execution_arn:
        :param kwargs: Cumulus query strings and parameters
        :return:
        """
        record_type = f"executions/{execution_arn}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def get_execution_status(self, execution_arn):
        """
        Retrieve details and status of a specific execution
        :return: Request response
        """
        record_type = f"executions/status/{execution_arn}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET)

    def search_executions_by_granules(self, data, **kwargs):
        """
        Return executions associated with specific granules
        :param data: json search definition
        :param kwargs: Cumulus query strings and parameters
        :return: Request response
        """
        record_type = "executions/search-by-granules"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data, **kwargs)

    def search_workflows_by_granules(self, data, **kwargs):
        """
        Return the workflows that have run on specific granules
        :param data: json search definition
        :param kwargs: Cumulus query strings and parameters
        :return: Request response
        """
        record_type = "executions/workflows-by-granules"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data, **kwargs)

    def create_execution(self, data):
        """
        Create an execution
        :return: Request response
        """
        record_type = "executions"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data)

    def update_execution(self, data):
        """
        Update/replace an existing execution.
        :return: Request response
        """
        record_type = f"executions/{data['arn']}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.PUT, data=data)

    def delete_execution(self, execution_arn):
        """
        Delete an execution from Cumulus.
        :return: Request response
        """
        record_type = f"executions/{execution_arn}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.DELETE)

    # ============== Workflows ===============

    def list_workflows(self, **kwargs):
        """
        List workflows
        :param kwargs: Cumulus query strings and parameters
        :return:
        """
        record_type = "workflows"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def get_workflow(self, workflow_name, **kwargs):
        """
        List workflows
        :param workflow_name: The name of the workflow to retrieve
        :param kwargs: Cumulus query strings and parameters
        :return:
        """
        record_type = f"workflows/{workflow_name}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    # ============== Async Operations ===============

    def list_async_operations(self, **kwargs):
        """
        List async operations in the Cumulus system.
        :param kwargs: Cumulus query strings and parameters
        :return: Request response
        """
        record_type = "asyncOperations"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def get_async_operation(self, operation_id, **kwargs):
        """
        Get an async operation
        :param operation_id:
        :param kwargs: Cumulus query strings and parameters
        :return:
        """
        record_type = f"asyncOperations/{operation_id}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    # ============== Replays ===============

    def replay_ingest_notification(self, data):
        """
        Replay ingest notifications
        :return: Request response
        """
        record_type = "replays"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data)

    # ============== Schemas ===============

    def get_schema(self, schema_type):
        """
        Retrieve the data schema for a particular type of Cumulus record.
        :return: Request response
        """
        record_type = f"schemas/{schema_type}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET)

    # ============== Reconciliation Reports ===============

    def list_reconciliation_reports(self, **kwargs):
        """
        List reconciliation reports in the Cumulus system.
        :param kwargs: Cumulus query strings and parameters
        :return: Request response
        """
        record_type = "reconciliationReports"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def get_reconciliation_report(self, report_name, **kwargs):
        """
        Get a reconciliation report
        :param report_name:
        :param kwargs: Cumulus query strings and parameters
        :return:
        """
        record_type = f"reconciliationReports/{report_name}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)

    def create_reconciliation_report(self, **kwargs):
        """
        Create a new reconciliation report.
        :param kwargs: Cumulus query strings and parameters
        :return: Request response
        """
        record_type = "reconciliationReports"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, **kwargs)

    def delete_reconciliation_report(self, report_name):
        """
        Delete a reconciliation report from Cumulus.
        :return: Request response
        """
        record_type = f"reconciliationReports/{report_name}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.DELETE)

    # ============== Instance Metadata ===============

    def get_instance_metadata(self):
        """
        Get a json object with information about how the Cumulus stack is configured
        :return: Request response
        """
        record_type = "instanceMeta"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET)

    # ============== Elasticsearch ===============

    def reindex_elasticsearch(self, **kwargs):
        """
        Create a new index and reindexes the source index to the new, destination index
        :param kwargs: Cumulus query strings and parameters
        :return: Request response
        """
        record_type = "elasticsearch/reindex"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, **kwargs)

    def get_elasticsearch_reindex_status(self):
        """
        Get the status of your reindex and the status of your indices.
        :return: Request response
        """
        record_type = "elasticsearch/reindex-status"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET)

    def update_elasticsearch_index(self, data):
        """
        Switch the Elasticsearch index to point to the new index, rather than the current index.
        :return: Request response
        """
        record_type = "elasticsearch/change-index"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.PUT, data=data)

    def reindex_elasticsearh_from_database(self, **kwargs):
        """
        Reindex your data from the database
        :param kwargs: cumulus query strings and parameters
        :return: Request response
        """
        record_type = "elasticsearch/index-from-database"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, **kwargs)

    def get_elasticsearch_indices_info(self):
        """
        Get information about your elasticsearch indices
        :return: Request response
        """
        record_type = "elasticsearch/indices-status"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET)

    def get_elasticsearch_index(self):
        """
        Get the current aliased index being used by the Cumulus Elasticsearch instance.
        :return: Request response
        """
        record_type = "elasticsearch/current-index"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET)

    # ============== Dashboard ===============

    def serve_dashboard_from_bucket(self, bucket, key):
        """
        Serve the dashboard from an S3 bucket.
        :return: Request response
        """
        record_type = f"dashboard/{bucket}/{key}"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET)

    # ============== ORCA ===============

    # def list_orca_recovery_status(self, **kwargs):
    #     """
    #     List ORCA recovery request status.
    #     :return: Request response
    #     """
    #     record_type = "orca/recovery"
    #     return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.GET, **kwargs)
    #
    # def post_orca(self, **kwargs):
    #     """
    #     List ORCA recovery request status.
    #     :return: Request response
    #     """
    #     record_type = "orca"
    #     return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, **kwargs)

    # ============== Migration Counts ===============

    def run_migration_count(self, **kwargs):
        """
        Trigger a run of the postgres-migration-count-tool as an async operation of type Migration
        Count Report.
        :param kwargs: Cumulus query strings and parameters
        :return: Request response
        """
        record_type = "migrationCounts"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, **kwargs)

    # ============== Dead Letter Archive ===============
    def recover_cumulus_messages(self, bucket: str = None, path: str = None) -> dict:
        """
        :param bucket: bucket name for the dead letter queue location
        :type bucket: string
        :param path: Path to dead letter queue records
        :type path: string
        :return: Response of the execution
        :rtype: python dictionary
        """
        data: dict = {}
        if path:
            data['path'] = path
        if bucket:
            data['bucket'] = bucket
        record_type = "deadLetterArchive/recoverCumulusMessages"
        return self.__crud_records(record_type=record_type, verb=self.allowed_verbs.POST, data=data)
