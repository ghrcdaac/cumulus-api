import requests
import logging
import os
from configparser import ConfigParser


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
        self.__config = os.environ
        # If the token provided ignore the config file
        if config_path:
            config_parser = ConfigParser(self.__config)
            self.__config = config_parser.read(config_path)['DEFAULT']
        self.INVOKE_BASE_URL = self.__config.get("INVOKE_BASE_URL").rstrip('/')
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
            query = "{}{}{}={}".format(query, and_sign, ele,kwargs[ele])
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

    def get_token(self):
        """
        Get Earth Data Token
        :return: Token otherwise raise exception
        """
        ed_base_url = self.__config.get("BASE_URL", "https://uat.urs.earthdata.nasa.gov").rstrip('/')  # Earth data base URL
        ed_client_id = self.__config.get("CLIENT_ID")  # Earth data client (application) id
        url = f"{ed_base_url}/oauth/authorize?client_id={ed_client_id}" \
              f"&redirect_uri={self.INVOKE_BASE_URL}/token&response_type=code"
        user_name, password = self.__config.get("USER_NAME"), self.__config.get("USER_PASSWORD")
        re = requests.get(url=url, auth=(user_name, password))
        error_str = "Getting the token"
        try:
            data = re.json()
            if "time out" in data['message']:
                logging.error(data['message']) 
                error_str = f"{error_str}: {data['message']}"
            return data['message']['token']
        except Exception as ex:
            error_str = f"{error_str} {str(ex)}"
            logging.error(error_str)
            raise error_str

    def refresh_token(self):
        """
        Refreshes a bearer token received from oAuth with Earthdata Login service.
        The token will be returned as a JWT (JSON Web Token).
        :return: Refreshed token
        """
        data = {"token": self.TOKEN}
        refreshed_token = self.__crud_records(record_type="refresh", verb="post", data=data)
        self.TOKEN = refreshed_token.get('token')
        return self.TOKEN

    def delete_token(self):
        """
        Delete the record for an access token received from oAuth with
        Earthdata Login service.
        :return: Message the token was deleted
        """
        record_type = f"tokenDelete/{self.TOKEN}"
        self.TOKEN = None
        return self.__crud_records(record_type=record_type, verb="delete")

    # ============== Collections ===============

    def list_collections(self, **kwargs):
        """
        List collections in the Cumulus system
        :return: Request response
        """
        return self.__crud_records(record_type="collections", verb="get", **kwargs)

    def update_collection(self, name, version, data):
        """
        Update values for a collection
        :param name: Collection name
        :param version: Collection version
        :param data: Can be the whole collection object or just a subset of fields,
        the ones that are being updated.
        :return:
        """
        record_type = "collections/%s/%s" % (name, version)
        return self.__crud_records(record_type=record_type, verb="put", data=data)

    def create_collection(self, data):
        """
        Create a New collection
        :param data: Json data of the collection to be ingested
        :return: request response
        """
        return self.__crud_records(record_type="collections", verb="post", data=data)

    def delete_collection(self, name, version):
        """
        Delete a collection from Cumulus, but not from CMR.
        All related granules in Cumulus must have already been deleted from Cumulus.
        :param name: Collection name
        :param version: Collection version
        :return:
        """
        record_type = "collections/%s/%s" % (name, version)

        return self.__crud_records(record_type=record_type, verb="delete")

    # ============== Granules ===============

    def list_granules(self, **kwargs):
        """
        List granules in the Cumulus system
        :paramkwargs:
        :return:
        """
        return self.__crud_records(record_type="granules", verb="get", **kwargs)

    def reingest_granule(self, granule_id):
        """
        Reingest a granule. This causes the granule to re-download to Cumulus from source,
        and begin processing from scratch. Reingesting a granule will overwrite existing
        granule files.
        :param granule_id: GranuleId
        :return:
        """
        record_type = f"granules/{granule_id}"
        data = {"action": "reingest"}
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
        data = {"action": "move", "destinations": [{"regex": regex, "bucket": bucket, "filepath": file_path}]}
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

        :param data: Apply a workflow to the granules provided. Granule can be sent as a list
        of IDs or as an Elasticsearch query to the Metrics' Elasticsearch.
        :return:
        """
        record_type = f"granules/bulk"

        return self.__crud_records(record_type=record_type, data=data, verb="post")

    def get_granules_csv(self):
        """
        Get a CSV file of all the granule in the Cumulus database.
        :return:
        """
        return self.__crud_records(record_type="granule-csv", verb="get")

    # ============== Providers ===============

    def list_providers(self, **kwargs):
        """
        List granules in the Cumulus system
        :paramkwargs:
        :return:
        """
        return self.__crud_records(record_type="providers", verb="get", **kwargs)

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
        return self.__crud_records(record_type="providers", verb="post", data=data)

    def update_provider(self, provider_id, data):
        """
        Update values for a provider
        :param provider_id: Provider id
        :param data: provider data with updated fields,
        :return: message of success or raise error
        """
        record_type = f"providers/{provider_id}"
        return self.__crud_records(record_type=record_type, verb="put", data=data)

    def delete_provider(self, provider_id):
        """
        Delete a provider
        :param provider_id: Provider id
        :return:
        """
        record_type = f"providers/{provider_id}"
        return self.__crud_records(record_type=record_type, verb="delete")
    
    # ============== Workflows ===============

    def list_workflows(self, **kwargs):
        """
        List workflows
        :paramkwargs:
        :return:
        """
        return self.__crud_records(record_type="workflows", verb="get", **kwargs)

    def get_workflow(self, workflow_name, **kwargs):
        """
        List workflows
        :paramkwargs:
        :return:
        """
        return self.__crud_records(record_type=f"workflows/{workflow_name}", verb="get", **kwargs)

    # ============== Rules ===============

    def list_rules(self, **kwargs):
        """
        List rules in the Cumulus system.
        :return:
        """
        return self.__crud_records(record_type="rules", verb="get", **kwargs)

    def create_rule(self, data):
        """
        Create a rule
        :param data: json object
        :return:
        """
        return self.__crud_records(record_type="rules", verb="post", data=data)

    def update_rule(self,name, data):
        """
        Update state and/or rule.value of a rule.
        :param data:Can accept the whole rule object, or just a subset of fields, the ones that are being updated.
        :return: Returns a mapping of the updated properties.
        """
        record_type = "rules/%s" % name
        return self.__crud_records(record_type=record_type, verb="put", data=data)

    def delete_rule(self, name):
        """
        Delete a rule from cumulus
        :param name: rule name
        :return:
        """
        record_type = "rules/%s" % name
        return self.__crud_records(record_type=record_type, verb="delete")

    def run_rule(self, name):
        """
        Run a rule
        :param name: rule name
        :return:
        """
        record_type = "rules/%s" % name
        return self.__crud_records(record_type=record_type, verb="put")


    # ============== Stats ===============

    def get_stats_summary(self):
        """
        Retrieve a summary of various metrics for all of the Cumulus engine
        :return:
        """
        return self.__crud_records(record_type="stats", verb="get")

    def get_stats_histogram(self, **kwargs):
        """
        Retrieve metrics over various time periods, to produce a histogram for dashboards.
        :paramkwargs: https://cumulus-nasa.github.io/cumulus-api/?language=cURL#summary
        :return:
        """
        return self.__crud_records(record_type="stats/histogram", verb="get", **kwargs)

    def get_stats_aggregate(self, **kwargs):
        """
        Count the value frequencies for a given field, for a given type of record in Cumulus
        :paramkwargs: Query required by cumulus api
        :return:
        """
        return self.__crud_records(record_type="stats/aggregate", verb="get", **kwargs)

    # ============== Logs ===============

    def list_logs(self, **kwargs):
        """
        List processing logs from the Cumulus engine. A log's level field may be either info or error.
        :paramkwargs: Query required by cumulus api
        :return:
        """
        return self.__crud_records(record_type="logs", verb="get", **kwargs)


if __name__ == "__main__":
    cml = CumulusApi()
    cll = cml.list_collections(limit=3)
