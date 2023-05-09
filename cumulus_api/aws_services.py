from dataclasses import dataclass
from typing import Union

import boto3


@dataclass
class AWS_Services:
    aws_region: str
    aws_profile: Union[str, None] = None

    def __post_init__(self):
        boto3.setup_default_session(profile_name=self.aws_profile,
                                    region_name=self.aws_region)

    @staticmethod
    def get_s3_resource():
        return boto3.resource('s3')

    @staticmethod
    def get_secretmanager_client():
        return boto3.client('secretsmanager')
