"""
Integration tests for EFS path isolation (defense-in-depth).

Verifies that different users get different EFS paths even for the same
investigation, preventing data collision at the filesystem level.
"""

import hashlib
import pytest


@pytest.mark.integration
@pytest.mark.abac
class TestABACPathIsolation:
    """Test that different ABAC identities get isolated EFS paths."""

    def test_alice_and_bob_get_different_paths_same_investigation(
        self,
        alice_bob_pair,
        test_config
    ):
        """
        Verify Alice and Bob get different EFS paths for the same investigation.

        Path format: /{cluster}/{sha256(uuid)[:16]}/{investigation}

        Even if they both work on cluster-1/inv-1, their paths should differ
        based on their UUID hash, preventing data collision.
        """
        alice, bob = alice_bob_pair

        # Find Alice's access points
        alice_aps = alice['efs'].describe_access_points(
            FileSystemId=test_config['efs_filesystem_id'],
            MaxResults=100
        )

        # Find Bob's access points
        bob_aps = bob['efs'].describe_access_points(
            FileSystemId=test_config['efs_filesystem_id'],
            MaxResults=100
        )

        # Extract rosa-boundary access points for each user
        def get_rosa_aps_for_user(aps_response, expected_uuid_prefix):
            rosa_aps = []
            for ap in aps_response.get('AccessPoints', []):
                tags = {tag['Key']: tag['Value'] for tag in ap.get('Tags', [])}
                if tags.get('ManagedBy') == 'rosa-boundary-lambda':
                    # Check if this is the user's AP based on uuid tag
                    if tags.get('uuid', '').startswith(expected_uuid_prefix):
                        rosa_aps.append(ap)
            return rosa_aps

        alice_rosa_aps = get_rosa_aps_for_user(alice_aps, 'test-uuid-alice')
        bob_rosa_aps = get_rosa_aps_for_user(bob_aps, 'test-uuid-bob')

        if not alice_rosa_aps:
            pytest.skip("No Alice access points found")

        if not bob_rosa_aps:
            pytest.skip("No Bob access points found")

        # Get paths
        alice_paths = [
            ap['RootDirectory']['Path']
            for ap in alice_rosa_aps
        ]

        bob_paths = [
            ap['RootDirectory']['Path']
            for ap in bob_rosa_aps
        ]

        # Verify no path overlap
        alice_path_set = set(alice_paths)
        bob_path_set = set(bob_paths)

        overlap = alice_path_set.intersection(bob_path_set)
        assert not overlap, \
            f"Alice and Bob should have no overlapping paths, found: {overlap}"

        # Verify path format includes hash
        for path in alice_paths:
            parts = path.split('/')
            assert len(parts) >= 4, \
                f"Expected path format /cluster/hash/investigation, got {path}"

            # Second part should be a 16-char hex hash
            hash_part = parts[2]
            assert len(hash_part) == 16, \
                f"Expected 16-char hash in path, got {hash_part}"
            assert all(c in '0123456789abcdef' for c in hash_part), \
                f"Hash should be hex, got {hash_part}"

    def test_path_hash_deterministic(self):
        """
        Verify path hash is deterministic for the same UUID.

        This is important so the same user always gets the same path
        for a given cluster/investigation combination.
        """
        uuid1 = "test-uuid-alice"
        uuid2 = "test-uuid-bob"

        # Hash function used by Lambda
        def compute_path_hash(uuid_value: str) -> str:
            return hashlib.sha256(uuid_value.encode('utf-8')).hexdigest()[:16]

        # Same UUID should always produce same hash
        hash1_a = compute_path_hash(uuid1)
        hash1_b = compute_path_hash(uuid1)
        assert hash1_a == hash1_b, "Hash should be deterministic"

        # Different UUIDs should produce different hashes
        hash2 = compute_path_hash(uuid2)
        assert hash1_a != hash2, "Different UUIDs should produce different hashes"

        # Verify hash length
        assert len(hash1_a) == 16, "Hash should be 16 characters"

    def test_path_within_aws_100_char_limit(
        self,
        alice_credentials,
        test_config
    ):
        """
        Verify EFS paths stay within AWS 100-character limit.

        AWS EFS RootDirectory.Path has a 100-character limit.
        Path format: /{cluster}/{hash}/{investigation} must fit.
        """
        from fixtures.aws import get_boto3_client

        alice_efs = get_boto3_client('efs', alice_credentials, test_config['aws_region'])

        # Get all rosa-boundary access points
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

        # Check all paths are within limit
        for ap in rosa_aps:
            path = ap['RootDirectory']['Path']
            path_length = len(path)

            assert path_length <= 100, \
                f"Path {path} exceeds 100-char limit: {path_length} chars"

            # Log longest path for monitoring
            if path_length > 80:
                print(f"Warning: Path {path} is {path_length} chars (close to 100 limit)")

    def test_path_collision_prevention(self):
        """
        Verify hash-based paths prevent collision even with identical
        cluster/investigation IDs.

        Example:
        - Alice works on cluster-1/inv-1 → /cluster-1/2bd806c97f0e00af/inv-1
        - Bob works on cluster-1/inv-1 → /cluster-1/81b637d8fcd2c6da/inv-1

        Different hash parts prevent collision.
        """
        import hashlib

        cluster_id = "cluster-1"
        investigation_id = "inv-1"

        alice_uuid = "test-uuid-alice"
        bob_uuid = "test-uuid-bob"

        # Compute paths
        alice_hash = hashlib.sha256(alice_uuid.encode()).hexdigest()[:16]
        bob_hash = hashlib.sha256(bob_uuid.encode()).hexdigest()[:16]

        alice_path = f"/{cluster_id}/{alice_hash}/{investigation_id}"
        bob_path = f"/{cluster_id}/{bob_hash}/{investigation_id}"

        # Paths must be different
        assert alice_path != bob_path, \
            f"Paths should differ: Alice={alice_path}, Bob={bob_path}"

        # Hash parts must be different
        assert alice_hash != bob_hash, \
            f"Hashes should differ: Alice={alice_hash}, Bob={bob_hash}"

        # Cluster and investigation parts should be the same
        assert cluster_id in alice_path and cluster_id in bob_path
        assert investigation_id in alice_path and investigation_id in bob_path
