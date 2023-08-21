
import logging
import os
import re
from configparser import SectionProxy
from typing import Dict, Union

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat)
from cryptography.hazmat.primitives.serialization.pkcs12 import \
    load_key_and_certificates
from .aws_services import AWS_Services
from requests_toolbelt.adapters.x509 import X509Adapter


class CumulusToken:
    def __init__(self, use_os_env=False, config: Union[SectionProxy, dict] = None):
        """
        :param config: PyLOT Configuration
        """
        self.config = config
        if self.config.get("USE_EDL", "false").upper() == 'TRUE':
            return
        if use_os_env:
            aws_profile = os.getenv('AWS_PROFILE')
            aws_region = os.getenv('AWS_REGION', 'us-west-2')
        else:
            aws_profile: Union[str, None] = self.config.get('AWS_PROFILE')
            aws_region: str = self.config.get('AWS_REGION', 'us-west-2')

        aws_services = AWS_Services(aws_profile=aws_profile, aws_region=aws_region)
        self.s3_resource = aws_services.get_s3_resource()
        self.secretmanager_client = aws_services.get_secretmanager_client()

    def get_s3_object_body(self, bucket_name, prefix):
        """
        :return:
        :rtype:
        """
        obj = self.s3_resource.Object(bucket_name=bucket_name, key=prefix)
        return obj.get()['Body'].read()

    def __get_launchpad_certificate_body_s3(self, s3_certificate_path: str) -> bytes:
        """
        :param s3_certificate_path: S3 path of launchpad certificate
        :type s3_certificate_path: string
        :return:
        :rtype:
        """
        groups = re.match(r"s3://(((?!/).)+)/(.*)", s3_certificate_path)
        if not groups:
            logging.error("S3 path should be of a format s3://<bucket_name>/path")
            raise Exception(f"{s3_certificate_path} is not of the format s3://<bucket_name>/path")
        bucket_name, certificate_path = groups[1], groups[3]

        return self.get_s3_object_body(bucket_name=bucket_name, prefix=certificate_path)

    @staticmethod
    def __get_launchpad_certificate_body_file_system(certificate_path: str) -> bytes:
        """
        :param certificate_path:
        :type certificate_path:
        :return:
        :rtype:
        """
        with open(certificate_path, "rb") as pkcs12_file:
            pkcs12_data = pkcs12_file.read()
        return pkcs12_data

    def __get_launchpad_pass_phrase_secret_manager(self, secret_manager_id: str):
        """
        :param secret_manager_id:
        :type secret_manager_id:
        :return:
        :rtype:
        """
        response = self.secretmanager_client.get_secret_value(SecretId=secret_manager_id)
        return response['SecretString']

    def get_launchpad_pass_phrase(self):
        """

        :return:
        :rtype:
        """
        secret_pass_phrase = self.config.get('LAUNCHPAD_PASSPHRASE_SECRET_NAME')
        if secret_pass_phrase:
            return self.__get_launchpad_pass_phrase_secret_manager(secret_manager_id=secret_pass_phrase)
        return self.config.get('LAUNCHPAD_PASSPHRASE')

    def get_launchpad_certificate_body(self) -> bytes:
        """
        :return:
        :rtype:
        """
        config = self.config
        pkcs12_data: bytes = b""
        if config.get("FS_LAUNCHPAD_CERT"):
            pkcs12_data = self.__get_launchpad_certificate_body_file_system(config["FS_LAUNCHPAD_CERT"])
        if config.get("S3URI_LAUNCHPAD_CERT"):
            pkcs12_data = self.__get_launchpad_certificate_body_s3(config["S3URI_LAUNCHPAD_CERT"])
        return pkcs12_data

    def get_launchpad_secret_phrase(self) -> bytes:
        """


        :return:
        :rtype:
        """
        config = self.config
        pass_phrase_secret_manager_id = config.get("LAUNCHPAD_PASSPHRASE_SECRET_NAME")
        if pass_phrase_secret_manager_id:
            pkcs12_password_bytes = self.get_launchpad_pass_phrase().encode()
            return pkcs12_password_bytes
        return config.get("LAUNCHPAD_PASSPHRASE", "").encode()

    def __get_launchpad_adapter(self):
        """
        Get launchpad adapter
        return: launchpad configured request adapter
        """
        error_str = "Getting launchpad adapter"
        backend = default_backend()
        pkcs12_data = self.get_launchpad_certificate_body()
        pkcs12_password_bytes = self.get_launchpad_secret_phrase()
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
        return adapter

    def initialize_edl_variables(self) -> list:
        """
        Initialize variables needed for EDL request
        """
        ed_base_url = self.config.get("BASE_URL", "https://uat.urs.earthdata.nasa.gov").rstrip('/')  # Earth data base URL
        ed_client_id = self.config.get("CLIENT_ID")  # Earth data client (application) id
        url = f"{ed_base_url}/oauth/authorize?client_id={ed_client_id}" \
              f"&redirect_uri={self.config.get('INVOKE_BASE_URL').rstrip('/')}/token&response_type=code"
        user_name, password = self.config.get("USER_NAME"), self.config.get("USER_PASSWORD")
        return [url, user_name, password]

    def get_edl_token(self):
        """
        Get auth token using Earthdata Login to authenticate
        """
        url, user_name, password = self.initialize_edl_variables()
        re = requests.get(url=url, auth=(user_name, password))
        error_str = "Getting auth token"
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

    def get_token(self):
        """
        Get API autehntication token
        :return: Token otherwise raise exception
        """
        if self.config.get("USE_EDL", "false").upper() == 'TRUE':
            return self.get_edl_token()
        # Use launchpad authentication
        adapter = self.__get_launchpad_adapter()
        session = requests.Session()
        session.mount("https://", adapter)
        r = session.get(self.config.get("LAUNCHPAD_URL"))
        response = r.json()
        return response["sm_token"]
        

