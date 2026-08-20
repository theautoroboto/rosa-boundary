"""
AWS credential helpers for integration tests.
"""

import os
import uuid
from typing import Dict

import boto3
from botocore.exceptions import ClientError


def assume_role_with_token(id_token: str, session_name: str = None) -> Dict[str, str]:
    """
    AssumeRoleWithWebIdentity and return credentials dict.

    Args:
        id_token: OIDC ID token from Keycloak
        session_name: Optional session name (auto-generated if not provided)

    Returns:
        Dict with AWS credentials (access_key_id, secret_access_key, session_token)

    Raises:
        ClientError: If role assumption fails
    """
    role_arn = os.getenv('SRE_ROLE_ARN')
    if not role_arn:
        raise ValueError("SRE_ROLE_ARN environment variable required")

    if session_name is None:
        session_name = f'test-session-{uuid.uuid4()}'

    sts = boto3.client('sts')

    try:
        response = sts.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=id_token,
            DurationSeconds=3600
        )
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        raise ValueError(
            f"Failed to assume role {role_arn}: {error_code} - {error_msg}"
        ) from e

    credentials = response['Credentials']

    return {
        'aws_access_key_id': credentials['AccessKeyId'],
        'aws_secret_access_key': credentials['SecretAccessKey'],
        'aws_session_token': credentials['SessionToken']
    }


def get_boto3_client(service: str, credentials: Dict[str, str], region: str = None):
    """
    Create boto3 client with specific credentials.

    Args:
        service: AWS service name (ecs, efs, etc.)
        credentials: Credentials dict from assume_role_with_token()
        region: AWS region (default from AWS_REGION env var)

    Returns:
        Boto3 client
    """
    if region is None:
        region = os.getenv('AWS_REGION', 'us-east-2')

    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=credentials['aws_access_key_id'],
        aws_secret_access_key=credentials['aws_secret_access_key'],
        aws_session_token=credentials['aws_session_token']
    )


def get_caller_identity(credentials: Dict[str, str]) -> Dict:
    """
    Get STS caller identity for debugging.

    Args:
        credentials: Credentials dict

    Returns:
        Dict with UserId, Account, Arn
    """
    sts = get_boto3_client('sts', credentials)
    return sts.get_caller_identity()


def extract_session_tags(credentials: Dict[str, str]) -> Dict[str, str]:
    """
    Extract session tags from assumed role ARN.

    Note: This requires additional AWS API calls and may not work in all cases.
    Session tags are visible in CloudTrail but not directly queryable via API.

    Args:
        credentials: Credentials dict

    Returns:
        Dict of session tags (best effort)
    """
    identity = get_caller_identity(credentials)
    # ARN format: arn:aws:sts::123456789012:assumed-role/role-name/session-name
    # Session tags are not directly accessible via API, only visible in CloudTrail
    # For testing, we rely on the fact that IAM will enforce them
    return {
        'arn': identity['Arn'],
        'user_id': identity['UserId']
    }
