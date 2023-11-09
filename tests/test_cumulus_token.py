import os
import unittest

import boto3
import pytest
from moto import mock_s3, mock_secretsmanager

from cumulus_api.cumulus_token import CumulusToken


class TestCumulusToken(unittest.TestCase):
    bucket_name = "test_bucket"
    certificate_s3_key = "temp/certificate.pfx"
    expected_body = "NoThingToS33HereExceptS@meRandoMText\n"
    certificate_path = os.path.join(os.path.dirname(__file__), "fixtures/certificate.pfx")
    secret_name = "fake_secretmanager"
    secret_string = "supersecretstring"

    @pytest.fixture
    def s3_resource(self):
        """Pytest fixture that creates the recipes bucket in
        the fake moto AWS account
        Yields a fake boto3 s3 resource
        """
        with mock_s3():
            mocked_s3_resource = boto3.resource("s3")
            mocked_s3_resource.create_bucket(
                Bucket=self.bucket_name, CreateBucketConfiguration={'LocationConstraint': 'us-west-2'}
            )
            s3_client = boto3.client('s3')
            s3_client.upload_file(self.certificate_path, self.bucket_name, self.certificate_s3_key)
            yield mocked_s3_resource

    @pytest.fixture
    def secretmanager_client(self):
        """Pytest fixture that creates a secretmanager to a
        the fake moto AWS account
        Yields a fake secret manager client
        """
        with mock_secretsmanager():

            mocked_secretmanger_client = boto3.client('secretsmanager', region_name="us-west-2")
            mocked_secretmanger_client.create_secret(
                Name=self.secret_name,
                SecretString=self.secret_string
            )
            yield mocked_secretmanger_client

    def test__get_launchpad_certificate_body_raise(self):
        s3_certificate_path = "/fake/path/launchpad.pfx"
        config = {'S3URI_LAUNCHPAD_CERT': s3_certificate_path}
        cml_token = CumulusToken(config=config)

        with self.assertRaises(Exception) as context:
            cml_token.get_launchpad_certificate_body()
        self.assertEqual(f'{s3_certificate_path} is not of the format s3://<bucket_name>/path', str(context.exception))

    # Either we can use this or we can define @pytest.fixture(autouse=True) to be used automatically
    @pytest.mark.usefixtures("s3_resource")
    def test__get_launchpad_certificate_body_s3(self):
        config = {'S3URI_LAUNCHPAD_CERT': f"s3://{self.bucket_name}/{self.certificate_s3_key}"}
        cml_token = CumulusToken(config=config)
        body = cml_token.get_launchpad_certificate_body()
        self.assertEqual(body, self.expected_body.encode("utf-8"))

    def test__get_launchpad_certificate_body_file_system(self):
        config = {"FS_LAUNCHPAD_CERT": self.certificate_path}
        cml_token = CumulusToken(config=config)
        body = cml_token.get_launchpad_certificate_body()
        self.assertEqual(body, self.expected_body.encode("utf-8"))

    @pytest.mark.usefixtures("secretmanager_client")
    def test__get_launchpad_pass_phrase_secret_manager(self):
        config = {"LAUNCHPAD_PASSPHRASE_SECRET_NAME": self.secret_name}
        cml_token = CumulusToken(config=config)
        secret = cml_token.get_launchpad_pass_phrase()
        self.assertEqual("supersecretstring", secret)

    def test__get_launchpad_pass_phrase(self):
        config = {"LAUNCHPAD_PASSPHRASE": self.secret_string}
        cml_token = CumulusToken(config=config)
        secret = cml_token.get_launchpad_pass_phrase()
        self.assertEqual("supersecretstring", secret)