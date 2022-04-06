import requests
import logging
import boto3
import os
import re
from configparser import ConfigParser
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.backends import default_backend
from requests_toolbelt.adapters.x509 import X509Adapter


class CumulusApi:
    def __init__(self, os_env=True, config_path=None, token=None):
        """
        Initiate cumulus API instance, by default it reads from OS environment
        :param config_path: absolute or relative path to config file
        :param token: earthdata token
        """
        # The user should provide the config file or the token
        if {None, False} == {config_path, token, os_env}:
            error = "Config file path, environment variables or token should be supplied"
            logging.error(error)
            raise ValueError(error)
        config = os.environ
        # If the token provided ignore the config file
        if config_path:
            config_parser = ConfigParser(config)
            config_parser.read(config_path)
            config = config_parser['DEFAULT']
        self.config = config
        boto3.setup_default_session(profile_name=self.config.get('AWS_PROFILE'),
                                    region_name=self.config.get('AWS_REGION', "us-west-2"))
        self.INVOKE_BASE_URL = self.config.get("INVOKE_BASE_URL").rstrip('/')
        self.TOKEN = token if token else self.get_token()
        self.HEADERS = {'Authorization': 'Bearer {}'.format(self.TOKEN)}

    def __crud_records(self, record_type, verb, data=None, **kwargs):
        """
        :param verb: HTTP requests verbs GET|POST|PUT|DELETE
        :param record_type: Provider | Collection | PDR ...
        :param data: json data to be ingested
        :return: False in case of error
        """
        allowed_verbs = ['GET', 'POST', 'PUT', 'DELETE']
        if verb.upper() not in allowed_verbs:
            return "{} is not a supported http request".format(verb)
        url = f"{self.INVOKE_BASE_URL}/v1/{record_type}"
        and_sign = ""
        query = ""
        for ele in kwargs.keys():
            query = "{}{}{}={}".format(query, and_sign, ele, kwargs[ele])
            and_sign = "&"
        if kwargs:
            url = "{}?{}".format(url, query)
        re = getattr(requests, verb.lower())(url=url, json=data, headers=self.HEADERS)
        try:
            return re.json()
        except Exception as e:
            logging.error("%s" % str(e))
            return re.content

    # ============== Version ===============
    def get_version(self):
        """
        Get cumulus API version
        :return:
        """
        return self.__crud_records(record_type="version", verb="get")

    # ============== Tokens ===============

    def get_launchpad_certificate_body_s3(self, s3_certificate_path):
        """

        :param s3_certificate_path:
        :type s3_certificate_path:
        :param config:
        :type config:
        :return:
        :rtype:
        """
        groups = re.match("s3://(((?!\/).)+)/(.*)", s3_certificate_path)
        if not groups:
            logging.error("S3 path should be of a format s3://<bucket_name>/path")
            raise Exception(f"{s3_certificate_path} is not of the format s3://<bucket_name>/path")
        s3 = boto3.resource('s3')
        bucket_name, certificate_path = groups[1], groups[3]
        obj = s3.Object(bucket_name=bucket_name, key=certificate_path)
        return obj.get()['Body'].read()

    def get_launchpad_certificate_body_file_system(self, certificate_path):
        """

        :param config:
        :type config:
        :return:
        :rtype:
        """
        with open(certificate_path, "rb") as pkcs12_file:
            pkcs12_data = pkcs12_file.read()
        return pkcs12_data

    def get_launchpad_pass_phrase_secret_manager(self, secret_manager_id):
        """

        :param config:
        :type config:
        :return:
        :rtype:
        """
        client = boto3.client('secretsmanager')
        response = client.get_secret_value(SecretId=secret_manager_id)
        return response['SecretString']

    def get_token_launchpad(self):
        """
        Get token using launchpad authentication
        return: cumulus token
        """
        error_str = "Getting the token (Launchpad)"
        config = self.config
        try:
            backend = default_backend()
            pkcs12_data = ""
            pkcs12_password_bytes = b""
            if config.get("FS_LAUNCHPAD_CERT"):
                pkcs12_data = self.get_launchpad_certificate_body_file_system(config.get("FS_LAUNCHPAD_CERT"))
            if config.get("S3URI_LAUNCHPAD_CERT"):
                pkcs12_data = self.get_launchpad_certificate_body_s3(config.get("S3URI_LAUNCHPAD_CERT"))
            pass_phrase_secret_manager_id = config.get("LAUNCHPAD_PASSPHRASE_SECRET_NAME")
            if pass_phrase_secret_manager_id:
                pkcs12_password_bytes = self.get_launchpad_pass_phrase_secret_manager(
                    pass_phrase_secret_manager_id).encode()
            elif config.get("LAUNCHPAD_PASSPHRASE"):
                pkcs12_password_bytes = config.get("LAUNCHPAD_PASSPHRASE").encode()

            pycaP12 = load_key_and_certificates(
                pkcs12_data, pkcs12_password_bytes, backend
            )

            cert_bytes = pycaP12[1].public_bytes(Encoding.DER)
            pk_bytes = pycaP12[0].private_bytes(
                Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
            )

            adapter = X509Adapter(
                max_retries=3,
                cert_bytes=cert_bytes,
                pk_bytes=pk_bytes,
                encoding=Encoding.DER,
            )
            session = requests.Session()
            session.mount("https://", adapter)

            r = session.get(config.get("LAUNCHPAD_URL"))
            response = r.json()
            token = response["sm_token"]
            return token
        except Exception as ex:
            error_str = f"{error_str} {str(ex)}"
            logging.error(error_str)
            raise Exception(error_str)

    def get_token(self):
        """
        Get Earth Data Token
        :return: Token otherwise raise exception
        """
        return self.get_token_launchpad()

    def refresh_token(self):
        """
        Refreshes a bearer token received from oAuth with Earthdata Login service.
        The token will be returned as a JWT (JSON Web Token).
        :return: True if the token is refreshed
        """
        # data = {"token": self.TOKEN}
        # refreshed_token = self.__crud_records(record_type="refresh", verb="post", data=data)
        self.TOKEN = self.get_token()
        self.HEADERS = {'Authorization': 'Bearer {}'.format(self.TOKEN)}

        # refreshed_token.get('token')
        return True

    def delete_token(self):
        """
        Delete the record for an access token received from oAuth with
        Earthdata Login service.
        :return: Message the token was deleted
        """
        record_type = f"tokenDelete/{self.TOKEN}"
        self.TOKEN = None
        return self.__crud_records(record_type=record_type, verb="delete")

    # ============== Providers ===============

    def list_providers(self, **kwargs):
        """
        List granules in the Cumulus system
        :paramkwargs:
        :return:
        """
        record_type = "providers"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def get_provider(self, provider_id, **kwargs):
        """
        Get a provider
        :param provider_id:
        :paramkwargs:
        :return:
        """
        record_type = f"providers/{provider_id}"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def create_provider(self, data):
        """
        Create a New provider
        :param data: Json data of the collection to be ingested
        :return: request response
        """
        record_type = "providers"
        return self.__crud_records(record_type=record_type, verb="post", data=data)

    def update_provider(self, data):
        """
        Update values for a provider
        :param data: provider data with updated fields,
        :return: message of success or raise error
        """
        record_type = f"providers/{data['id']}"
        return self.__crud_records(record_type=record_type, verb="put", data=data)

    def delete_provider(self, provider_id):
        """
        Delete a provider
        :param provider_id: Provider id
        :return:
        """
        record_type = f"providers/{provider_id}"
        return self.__crud_records(record_type=record_type, verb="delete")

    # ============== Collections ===============

    def list_collections(self, **kwargs):
        """
        List collections in the Cumulus system
        :return: Request response
        """
        record_type = "collections"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def list_collections_with_active_granules(self, **kwargs):
        """
        List collections in the Cumulus system that have active associated granules.
        :return: Request response
        """
        record_type = "collections/active"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def get_collection(self, collection_name, collection_version, **kwargs):
        """
        Get a collection
        :param collection_name:
        :param collection_version:
        :param kwargs:
        :return:
        """
        record_type = f"collections/{collection_name}/{collection_version}"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def create_collection(self, data):
        """
        Create a New collection
        :param data: Json data of the collection to be ingested
        :return: request response
        """
        record_type = "collections"
        return self.__crud_records(record_type=record_type, verb="post", data=data)

    def update_collection(self, data):
        """
        Update values for a collection
        :param data: Can be the whole collection object or just a subset of fields,
        the ones that are being updated.
        :return:
        """
        record_type = f"collections/{data['name']}/{data['version']}"
        return self.__crud_records(record_type=record_type, verb="put", data=data)

    def delete_collection(self, collection_name, collection_version):
        """
        Delete a collection from Cumulus, but not from CMR.
        All related granules in Cumulus must have already been deleted from Cumulus.
        :param collection_name: Collection name
        :param collection_version: Collection version
        :return:
        """
        record_type = f"collections/{collection_name}/{collection_version}"
        return self.__crud_records(record_type=record_type, verb="delete")

    # ============== Granules ===============

    def list_granules(self, **kwargs):
        """
        List granules in the Cumulus system
        :paramkwargs:
        :return:
        """
        record_type = "granules"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def get_granule(self, granule_id, **kwargs):
        """
        Get a granule
        :param granule_id:
        :param kwargs:
        :return:
        """
        record_type = f"granules/{granule_id}"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def create_granule(self, data):
        """
        Create a granule
        :return: Request response
        """
        record_type = "granules"
        return self.__crud_records(record_type=record_type, verb="post", data=data)

    def update_granule(self, data):
        """
        Updates a granule
        :return: Request response
        """
        record_type = f"granules/{data['granuleId']}"
        return self.__crud_records(record_type=record_type, verb="put", data=data)

    def associate_execution(self, data):
        """
        Associate an execution with a granule
        :return: Request response
        """
        record_type = f"granules/{data['granuleId']}/executions"
        return self.__crud_records(record_type=record_type, verb="post", data=data)

    def reingest_granule(self, granule_id, data=None):
        """
        Reingest a granule. This causes the granule to re-download to Cumulus from source,
        and begin processing from scratch. Reingesting a granule will overwrite existing
        granule files.
        :param granule_id: GranuleId
        :param data: response request parameters
        :return:
        """
        record_type = f"granules/{granule_id}"
        data = dict() if data is None else data
        data.update({"action": "reingest"})
        return self.__crud_records(record_type=record_type, data=data, verb="put")

    def apply_workflow_to_granule(self, granule_id, workflow_name):
        """
        Apply the named workflow to the granule. Workflow input will be built from template
        and provided entire Cumulus granule record as payload.
        :return: status message
        """
        record_type = f"granules/{granule_id}"
        data = {"action": "applyWorkflow", "workflow": workflow_name}
        return self.__crud_records(record_type=record_type, data=data, verb="put")

    def move_granule(self, granule_id, regex, bucket, file_path):
        """
        Move a granule from one location on S3 to another. Individual files are moved to
        specific locations by using a regex that matches their filenames.
        :param granule_id: granuleId
        :param regex: granule regex
        :param bucket: bucket where the granule is located
        :param file_path: new file path
        :return:
        """
        record_type = f"granules/{granule_id}"
        data = {"action": "move",
                "destinations": [{"regex": regex, "bucket": bucket, "filepath": file_path}]}
        return self.__crud_records(record_type=record_type, data=data, verb="put")

    def remove_granule_from_cmr(self, granule_id):
        """
        Remove a Cumulus granule from CMR.
        :param granule_id: granuleId
        :return:
        """
        record_type = f"granules/{granule_id}"
        data = {"action": "removeFromCmr"}
        return self.__crud_records(record_type=record_type, data=data, verb="put")

    def delete_granule(self, granule_id):
        """
        Delete a granule from Cumulus. It must already be removed from CMR.
        :param granule_id:
        :return:
        """
        record_type = f"granules/{granule_id}"
        return self.__crud_records(record_type=record_type, verb="delete")

    def granules_bulk_op(self, data):
        """
        Apply a workflow to the granules provided
        :param data:
        :return:
        """
        record_type = f"granules/bulk"
        return self.__crud_records(record_type=record_type, data=data, verb="post")

    def bulk_delete(self, data):
        """
        Bulk delete the provided granules
        :return: Request response
        """
        record_type = "granules/bulkDelete"
        return self.__crud_records(record_type=record_type, verb="post", data=data)

    def bulk_reingest(self, data):
        """
        Bulk reingest the provided granules
        :return: Request response
        """
        record_type = "granules/bulkReingest"
        return self.__crud_records(record_type=record_type, verb="post", data=data)

    # ============== PDRs ===============

    def list_pdrs(self, **kwargs):
        """
        List PDRs in the Cumulus system.
        :return: Request response
        """
        record_type = "pdrs"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def get_pdr(self, pdr_name, **kwargs):
        """
        Get a pdr
        :param pdr_name:
        :param kwargs:
        :return:
        """
        record_type = f"pdrs/{pdr_name}"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def delete_pdr(self, pdr_name):
        """
        Delete a PDR from Cumulus
        :return: Request response
        """
        record_type = f"pdrs/{pdr_name}"
        return self.__crud_records(record_type=record_type, verb="delete")

    # ============== Rules ===============

    def list_rules(self, **kwargs):
        """
        List rules in the Cumulus system.
        :return:
        """
        record_type = "rules"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def get_rule(self, rule_name, **kwargs):
        """
        Get a rule
        :param rule_name:
        :param kwargs:
        :return:
        """
        record_type = f"rules/{rule_name}"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def create_rule(self, data):
        """
        Create a rule
        :param data: json object
        :return:
        """
        record_type = "rules"
        return self.__crud_records(record_type=record_type, verb="post", data=data)

    def update_rule(self, data):
        """
        Update state and/or rule.value of a rule.
        :param data: Can accept the whole rule object, or just a subset of fields, the ones that
        are being updated.
        :return: Returns a mapping of the updated properties.
        """
        record_type = f"rules/{data['name']}"
        return self.__crud_records(record_type=record_type, verb="put", data=data)

    def delete_rule(self, rule_name):
        """
        Delete a rule from cumulus
        :param rule_name: rule name
        :return:
        """
        record_type = f"rules/{rule_name}"
        return self.__crud_records(record_type=record_type, verb="delete")

    def run_rule(self, rule_name):
        """
        Run a rule
        :param rule_name: rule name
        :return: object
        """
        record_type = f"rules/{rule_name}"
        data = {"name": rule_name, "action": "rerun"}
        return self.__crud_records(record_type=record_type, verb="put", data=data)

    # ============== Stats ===============

    def get_stats_summary(self):
        """
        Retrieve a summary of various metrics for all of the Cumulus engine
        :return:
        """
        record_type = "stats"
        return self.__crud_records(record_type=record_type, verb="get")

    def get_stats_aggregate(self, **kwargs):
        """
        Count the value frequencies for a given field, for a given type of record in Cumulus
        :paramkwargs: Query required by cumulus api
        :return:
        """
        record_type = "stats/aggregate"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    # ============== Logs ===============

    def list_logs(self, **kwargs):
        """
        List processing logs from the Cumulus engine. A log's level field may be either info or
        error.
        :paramkwargs: Query required by cumulus api
        :return:
        """
        record_type = "logs"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def get_log(self, execution_name, **kwargs):
        """
        Get a log
        :param execution_name:
        :param kwargs:
        :return:
        """
        record_type = f"logs/{execution_name}"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    # ============== Granule CSV ===============

    def get_granules_csv(self):
        """
        Get a CSV file of all the granule in the Cumulus database.
        :return:
        """
        record_type = "granule-csv"
        return self.__crud_records(record_type=record_type, verb="get")

    # ============== Executions ===============

    def list_executions(self, **kwargs):
        """
        List executions in the Cumulus system.
        :return: Request response
        """
        record_type = "executions"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def get_execution(self, execution_arn, **kwargs):
        """
        Get an execution
        :param execution_arn:
        :param kwargs:
        :return:
        """
        record_type = f"executions/{execution_arn}"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def get_execution_status(self, execution_arn):
        """
        Retrieve details and status of a specific execution
        :return: Request response
        """
        record_type = f"executions/status/{execution_arn}"
        return self.__crud_records(record_type=record_type, verb="get")

    def search_executions_by_granules(self, data, **kwargs):
        """
        Return executions associated with specific granules
        :return: Request response
        """
        record_type = "executions/search-by-granules"
        return self.__crud_records(record_type=record_type, verb="post", data=data, **kwargs)

    def search_workflows_by_granules(self, data, **kwargs):
        """
        Return the workflows that have run on specific granules
        :return: Request response
        """
        record_type = "executions/workflows-by-granules"
        return self.__crud_records(record_type=record_type, verb="post", data=data, **kwargs)

    def create_execution(self, data):
        """
        Create an execution
        :return: Request response
        """
        record_type = "executions"
        return self.__crud_records(record_type=record_type, verb="post", data=data)

    def update_execution(self, data):
        """
        Update/replace an existing execution.
        :return: Request response
        """
        record_type = f"executions/{data['arn']}"
        return self.__crud_records(record_type=record_type, verb="put", data=data)

    def delete_execution(self, execution_arn):
        """
        Delete an execution from Cumulus.
        :return: Request response
        """
        record_type = f"executions/{execution_arn}"
        return self.__crud_records(record_type=record_type, verb="delete")

    # ============== Workflows ===============

    def list_workflows(self, **kwargs):
        """
        List workflows
        :paramkwargs:
        :return:
        """
        record_type = "workflows"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def get_workflow(self, workflow_name, **kwargs):
        """
        List workflows
        :paramkwargs:
        :return:
        """
        record_type = f"workflows/{workflow_name}"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    # ============== Async Operations ===============

    def list_async_operations(self, **kwargs):
        """
        List async operations in the Cumulus system.
        :return: Request response
        """
        record_type = "asyncOperations"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def get_async_operation(self, operation_id, **kwargs):
        """
        Get an async operation
        :param operation_id:
        :param kwargs:
        :return:
        """
        record_type = f"asyncOperations/{operation_id}"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    # ============== Replays ===============

    def replay_ingest_notification(self, data):
        """
        Replay ingest notifications
        :return: Request response
        """
        record_type = "replays"
        return self.__crud_records(record_type=record_type, verb="post", data=data)

    # ============== Schemas ===============

    def get_schema(self, schema_type):
        """
        Retrieve the data schema for a particular type of Cumulus record.
        :return: Request response
        """
        record_type = f"schemas/{schema_type}"
        return self.__crud_records(record_type=record_type, verb="get")

    # ============== Reconciliation Reports ===============

    def list_reconciliation_reports(self, **kwargs):
        """
        List reconciliation reports in the Cumulus system.
        :return: Request response
        """
        record_type = "reconciliationReports"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def get_reconciliation_report(self, report_name, **kwargs):
        """
        Get a reconciliation report
        :param report_name:
        :param kwargs:
        :return:
        """
        record_type = f"reconciliationReports/{report_name}"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    def create_reconciliation_report(self, **kwargs):
        """
        Create a new reconciliation report.
        :return: Request response
        """
        record_type = "reconciliationReports"
        return self.__crud_records(record_type=record_type, verb="post", **kwargs)

    def delete_reconciliation_report(self, report_name):
        """
        Delete a reconciliation report from Cumulus.
        :return: Request response
        """
        record_type = f"reconciliationReports/{report_name}"
        return self.__crud_records(record_type=record_type, verb="delete")

    # ============== Instance Metadata ===============

    def get_instance_metadata(self):
        """
        Get a json object with information about how the Cumulus stack is configured
        :return: Request response
        """
        record_type = "instanceMeta"
        return self.__crud_records(record_type=record_type, verb="get")

    # ============== Elasticsearch ===============

    def reindex_elasticsearch(self, **kwargs):
        """
        Create a new index and reindexes the source index to the new, destination index
        :return: Request response
        """
        record_type = "elasticsearch/reindex"
        return self.__crud_records(record_type=record_type, verb="post", **kwargs)

    def get_elasticsearch_reindex_status(self):
        """
        Get the status of your reindex and the status of your indices.
        :return: Request response
        """
        record_type = "elasticsearch/reindex-status"
        return self.__crud_records(record_type=record_type, verb="get")

    def update_elasticsearch_index(self, data):
        """
        Switch the Elasticsearch index to point to the new index, rather than the current index.
        :return: Request response
        """
        record_type = "elasticsearch/change-index"
        return self.__crud_records(record_type=record_type, verb="post", data=data)

    def reindex_elasticsearh_from_database(self, **kwargs):
        """
        Reindex your data from the database
        :return: Request response
        """
        record_type = "elasticsearch/index-from-database"
        return self.__crud_records(record_type=record_type, verb="post", **kwargs)

    def get_elasticsearch_indices_info(self):
        """
        Get information about your elasticsearch indices
        :return: Request response
        """
        record_type = "elasticsearch/indices-status"
        return self.__crud_records(record_type=record_type, verb="get")

    def get_elasticsearch_index(self):
        """
        Get the current aliased index being used by the Cumulus Elasticsearch instance.
        :return: Request response
        """
        record_type = "elasticsearch/current-index"
        return self.__crud_records(record_type=record_type, verb="get")

    # ============== Dashboard ===============

    def serve_dashboard_from_bucket(self, bucket, key):
        """
        Serve the dashboard from an S3 bucket.
        :return: Request response
        """
        record_type = f"dashboard/{bucket}/{key}"
        return self.__crud_records(record_type=record_type, verb="get")

    # ============== ORCA ===============

    def list_orca_recovery_status(self, **kwargs):
        """
        List ORCA recovery request status.
        :return: Request response
        """
        record_type = "orca/recovery"
        return self.__crud_records(record_type=record_type, verb="get", **kwargs)

    # ============== Migration Counts ===============

    def run_migration_count(self, **kwargs):
        """
        Trigger a run of the postgres-migration-count-tool as an async operation of type Migration
        Count Report.
        :return: Request response
        """
        record_type = "migrationCounts"
        return self.__crud_records(record_type=record_type, verb="post", **kwargs)

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
        data = {} if [bucket, path] else None
        if path:
            data['path'] = path
        if bucket:
            data['bucket'] = bucket
        record_type = "deadLetterArchive/recoverCumulusMessages"
        return self.__crud_records(record_type=record_type, verb="post", data=data)


if __name__ == "__main__":
    cml = CumulusApi()
    cll = cml.list_collections(limit=3)
