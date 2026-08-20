"""
Integration tests for ABAC isolation on EFS access points.

Verifies that IAM policies prevent users from deleting each other's access points.
"""

import pytest
from botocore.exceptions import ClientError


@pytest.mark.integration
@pytest.mark.abac
class TestABACEFSIsolation:
    """Test that ABAC tags prevent cross-user EFS access point operations."""

    def test_user_cannot_delete_other_user_access_point(
        self,
        alice_bob_pair,
        test_config
    ):
        """
        Verify Bob cannot delete Alice's EFS access point.

        IAM policy should deny elasticfilesystem:DeleteAccessPoint when
        aws:ResourceTag/uuid != aws:PrincipalTag/uuid
        """
        alice, bob = alice_bob_pair

        # Find Alice's access points
        alice_aps_resp = alice['efs'].describe_access_points(
            FileSystemId=test_config['efs_filesystem_id'],
            MaxResults=10
        )

        alice_access_points = [
            ap for ap in alice_aps_resp.get('AccessPoints', [])
            if ap.get('LifeCycleState') == 'available'
        ]

        if not alice_access_points:
            pytest.skip("No access points found for Alice. Create investigation first.")

        # Find an access point tagged with uuid
        alice_ap = None
        for ap in alice_access_points:
            tags = {tag['Key']: tag['Value'] for tag in ap.get('Tags', [])}
            if 'uuid' in tags and 'ManagedBy' in tags:
                if tags['ManagedBy'] == 'rosa-boundary-lambda':
                    alice_ap = ap
                    break

        if not alice_ap:
            pytest.skip("No rosa-boundary access points found with uuid tag")

        alice_ap_id = alice_ap['AccessPointId']

        # Bob tries to delete Alice's access point
        with pytest.raises(ClientError) as exc_info:
            bob['efs'].delete_access_point(AccessPointId=alice_ap_id)

        # Verify access denied
        error = exc_info.value.response['Error']
        assert error['Code'] in ['AccessDeniedException', 'AccessDenied'], \
            f"Expected AccessDenied, got {error['Code']}: {error['Message']}"

        error_msg_lower = error['Message'].lower()
        assert any(keyword in error_msg_lower for keyword in [
            'not authorized', 'access denied', 'permission'
        ]), f"Unexpected error message: {error['Message']}"

    def test_user_can_delete_own_access_point(
        self,
        alice_credentials,
        test_config,
        cleanup_resources
    ):
        """
        Verify Alice CAN delete her own access point (positive test).

        IAM policy should allow elasticfilesystem:DeleteAccessPoint when
        aws:ResourceTag/uuid == aws:PrincipalTag/uuid

        Note: This test creates a temporary access point for deletion.
        """
        from fixtures.aws import get_boto3_client

        alice_efs = get_boto3_client('efs', alice_credentials, test_config['aws_region'])

        # Create a test access point for Alice to delete
        # In real usage, this would be created by the Lambda
        test_ap_response = alice_efs.create_access_point(
            FileSystemId=test_config['efs_filesystem_id'],
            PosixUser={
                'Uid': 1000,
                'Gid': 1000
            },
            RootDirectory={
                'Path': '/integration-test-alice-deletable',
                'CreationInfo': {
                    'OwnerUid': 1000,
                    'OwnerGid': 1000,
                    'Permissions': '0755'
                }
            },
            Tags=[
                {'Key': 'uuid', 'Value': 'test-uuid-alice'},
                {'Key': 'ManagedBy', 'Value': 'rosa-boundary-lambda'},
                {'Key': 'IntegrationTest', 'Value': 'true'}
            ]
        )

        test_ap_id = test_ap_response['AccessPointId']
        cleanup_resources['access_points'].append(test_ap_id)

        # Wait for access point to become available
        import time
        for _ in range(30):  # 30 second timeout
            ap_details = alice_efs.describe_access_points(
                AccessPointId=test_ap_id
            )
            if ap_details['AccessPoints'][0]['LifeCycleState'] == 'available':
                break
            time.sleep(1)
        else:
            pytest.fail("Access point did not become available within 30 seconds")

        # Alice deletes her own access point - should succeed
        response = alice_efs.delete_access_point(AccessPointId=test_ap_id)

        # Verify successful deletion
        assert response['ResponseMetadata']['HTTPStatusCode'] == 204

        # Remove from cleanup list since we successfully deleted it
        cleanup_resources['access_points'].remove(test_ap_id)

    def test_user_can_describe_all_access_points(
        self,
        alice_bob_pair,
        test_config
    ):
        """
        Verify users can describe all access points (read operations allowed).

        elasticfilesystem:DescribeAccessPoints has no ABAC restrictions.
        Users can see all access points but should filter by tags in application.
        """
        alice, bob = alice_bob_pair

        # Both users can describe access points
        alice_aps = alice['efs'].describe_access_points(
            FileSystemId=test_config['efs_filesystem_id'],
            MaxResults=100
        )

        bob_aps = bob['efs'].describe_access_points(
            FileSystemId=test_config['efs_filesystem_id'],
            MaxResults=100
        )

        # Both calls should succeed
        assert 'AccessPoints' in alice_aps
        assert 'AccessPoints' in bob_aps

        # Both users see the same access points (IAM doesn't filter reads)
        alice_ap_ids = {ap['AccessPointId'] for ap in alice_aps['AccessPoints']}
        bob_ap_ids = {ap['AccessPointId'] for ap in bob_aps['AccessPoints']}

        assert alice_ap_ids == bob_ap_ids, \
            "Both users should see the same access points (read not restricted)"

        # Note: Application-layer filtering by uuid tag happens in CLI, not IAM

    def test_access_point_has_required_abac_tags(
        self,
        alice_credentials,
        test_config
    ):
        """
        Verify access points created by rosa-boundary have required ABAC tags.

        Tags required for ABAC enforcement:
        - uuid: User's UUID for access control
        - ManagedBy: rosa-boundary-lambda
        - ClusterID: Cluster identifier
        - InvestigationID: Investigation identifier
        """
        from fixtures.aws import get_boto3_client

        alice_efs = get_boto3_client('efs', alice_credentials, test_config['aws_region'])

        # Find rosa-boundary access points
        aps_response = alice_efs.describe_access_points(
            FileSystemId=test_config['efs_filesystem_id'],
            MaxResults=100
        )

        rosa_aps = [
            ap for ap in aps_response.get('AccessPoints', [])
            if any(
                tag['Key'] == 'ManagedBy' and tag['Value'] == 'rosa-boundary-lambda'
                for tag in ap.get('Tags', [])
            )
        ]

        if not rosa_aps:
            pytest.skip("No rosa-boundary access points found")

        # Check first access point has required tags
        ap = rosa_aps[0]
        tags = {tag['Key']: tag['Value'] for tag in ap.get('Tags', [])}

        required_tags = ['uuid', 'ManagedBy', 'ClusterID', 'InvestigationID']
        missing_tags = [tag for tag in required_tags if tag not in tags]

        assert not missing_tags, \
            f"Access point {ap['AccessPointId']} missing required tags: {missing_tags}"

        # Verify uuid tag is not empty
        assert tags['uuid'], "uuid tag should not be empty"

        # Verify ManagedBy is correct
        assert tags['ManagedBy'] == 'rosa-boundary-lambda', \
            f"Expected ManagedBy=rosa-boundary-lambda, got {tags['ManagedBy']}"
