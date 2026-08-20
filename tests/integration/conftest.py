"""
Pytest configuration and fixtures for ABAC integration tests.
"""

import os
import pytest
import boto3
from typing import List, Dict, Tuple

from fixtures.oidc import get_oidc_token
from fixtures.aws import assume_role_with_token, get_boto3_client


@pytest.fixture(scope='session')
def test_config():
    """
    Load test configuration from environment variables.

    Required env vars:
    - KEYCLOAK_URL or USE_MOCK_TOKENS=true
    - SRE_ROLE_ARN
    - ECS_CLUSTER
    - EFS_FILESYSTEM_ID

    Optional env vars:
    - AWS_REGION (default: us-east-2)
    - ALICE_PASSWORD (default: test-alice)
    - BOB_PASSWORD (default: test-bob)
    """
    config = {
        'keycloak_url': os.getenv('KEYCLOAK_URL'),
        'use_mock': os.getenv('USE_MOCK_TOKENS', 'false').lower() == 'true',
        'sre_role_arn': os.getenv('SRE_ROLE_ARN'),
        'ecs_cluster': os.getenv('ECS_CLUSTER'),
        'efs_filesystem_id': os.getenv('EFS_FILESYSTEM_ID'),
        'aws_region': os.getenv('AWS_REGION', 'us-east-2'),
        'alice_password': os.getenv('ALICE_PASSWORD', 'test-alice'),
        'bob_password': os.getenv('BOB_PASSWORD', 'test-bob')
    }

    # Validate required config
    if not config['use_mock']:
        if not config['keycloak_url']:
            pytest.skip("KEYCLOAK_URL not set and USE_MOCK_TOKENS not enabled")

    if not config['sre_role_arn']:
        pytest.skip("SRE_ROLE_ARN environment variable not set")

    if not config['ecs_cluster']:
        pytest.skip("ECS_CLUSTER environment variable not set")

    if not config['efs_filesystem_id']:
        pytest.skip("EFS_FILESYSTEM_ID environment variable not set")

    return config


@pytest.fixture(scope='function')
def alice_credentials(test_config):
    """Get AWS credentials for test user Alice."""
    token = get_oidc_token(
        user='alice',
        password=test_config['alice_password'],
        mock=test_config['use_mock']
    )
    return assume_role_with_token(token, session_name='integration-test-alice')


@pytest.fixture(scope='function')
def bob_credentials(test_config):
    """Get AWS credentials for test user Bob."""
    token = get_oidc_token(
        user='bob',
        password=test_config['bob_password'],
        mock=test_config['use_mock']
    )
    return assume_role_with_token(token, session_name='integration-test-bob')


@pytest.fixture(scope='function')
def cleanup_resources(test_config):
    """
    Track and cleanup AWS resources created during tests.

    Usage:
        def test_something(cleanup_resources):
            task_arn = create_task(...)
            cleanup_resources['tasks'].append(task_arn)
            # Test will clean up task even if it fails
    """
    resources = {
        'tasks': [],
        'access_points': [],
        'task_definitions': []
    }

    yield resources

    # Cleanup tasks
    if resources['tasks']:
        ecs = boto3.client('ecs', region_name=test_config['aws_region'])
        for task_arn in resources['tasks']:
            try:
                ecs.stop_task(
                    cluster=test_config['ecs_cluster'],
                    task=task_arn,
                    reason='Integration test cleanup'
                )
            except Exception as e:
                print(f"Warning: Failed to cleanup task {task_arn}: {e}")

    # Cleanup EFS access points
    if resources['access_points']:
        efs = boto3.client('efs', region_name=test_config['aws_region'])
        for ap_id in resources['access_points']:
            try:
                efs.delete_access_point(AccessPointId=ap_id)
            except Exception as e:
                print(f"Warning: Failed to cleanup access point {ap_id}: {e}")

    # Note: Task definitions cannot be deleted, only deregistered
    # They age out automatically after inactivity


@pytest.fixture(scope='function')
def alice_bob_pair(alice_credentials, bob_credentials, test_config):
    """
    Fixture providing both Alice and Bob credentials and clients.

    Returns:
        Tuple of (alice_dict, bob_dict) where each dict contains:
        - credentials: AWS credentials dict
        - ecs: ECS client
        - efs: EFS client
    """
    alice = {
        'credentials': alice_credentials,
        'ecs': get_boto3_client('ecs', alice_credentials, test_config['aws_region']),
        'efs': get_boto3_client('efs', alice_credentials, test_config['aws_region'])
    }

    bob = {
        'credentials': bob_credentials,
        'ecs': get_boto3_client('ecs', bob_credentials, test_config['aws_region']),
        'efs': get_boto3_client('efs', bob_credentials, test_config['aws_region'])
    }

    return alice, bob
