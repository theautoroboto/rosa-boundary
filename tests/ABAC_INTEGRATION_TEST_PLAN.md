# ABAC Isolation Integration Test Plan

## Overview

This document defines integration tests to verify that ABAC (Attribute-Based Access Control) prevents users from accessing each other's work at the AWS IAM policy enforcement layer.

**Current gap:** Lambda-layer tag matching is unit tested, but IAM policy enforcement is not integration tested.

## Test Scenarios

### Scenario 1: Cross-User ECS Task Access Denied

**Setup:**
1. Alice creates investigation: `create-investigation --cluster-id test-cluster --investigation-id alice-inv`
   - Lambda creates ECS task tagged `uuid=<alice-uuid>`
2. Bob obtains his OIDC token (different UUID than Alice)
   - Bob assumes SRE role → session tagged `aws:PrincipalTag/uuid=<bob-uuid>`

**Test Cases:**

| Action | Actor | Target | Expected Result | IAM Check |
|--------|-------|--------|-----------------|-----------|
| `ecs:ExecuteCommand` | Bob | Alice's task | `AccessDenied` | `ResourceTag/uuid ≠ PrincipalTag/uuid` |
| `ecs:StopTask` | Bob | Alice's task | `AccessDenied` | `ResourceTag/uuid ≠ PrincipalTag/uuid` |
| `ecs:DescribeTasks` | Bob | Alice's task | `200 OK` (but filtered) | Read allowed, results filtered by tags |
| `ecs:ExecuteCommand` | Alice | Alice's task | `200 OK` | `ResourceTag/uuid == PrincipalTag/uuid` |

**Implementation:**
```python
# tests/integration/test_abac_ecs_isolation.py

def test_user_cannot_exec_into_other_user_task():
    # Alice creates task
    alice_token = get_oidc_token(user='alice')
    alice_creds = assume_role_with_token(alice_token)
    alice_task = create_investigation(alice_creds, cluster='test', inv='alice-inv')
    
    # Bob tries to exec into Alice's task
    bob_token = get_oidc_token(user='bob')
    bob_creds = assume_role_with_token(bob_token)
    
    with pytest.raises(ClientError) as exc:
        ecs_client_bob = boto3.client('ecs', **bob_creds)
        ecs_client_bob.execute_command(
            cluster='rosa-boundary-dev',
            task=alice_task['TaskArn'],
            command='/bin/bash',
            interactive=True
        )
    
    assert exc.value.response['Error']['Code'] == 'AccessDeniedException'
    assert 'ResourceTag/uuid' in exc.value.response['Error']['Message'] or \
           'not authorized' in exc.value.response['Error']['Message'].lower()
```

### Scenario 2: Cross-User EFS Access Point Deletion Denied

**Setup:**
1. Alice creates investigation → EFS access point created and tagged `uuid=<alice-uuid>`
2. Bob obtains his OIDC token

**Test Cases:**

| Action | Actor | Target | Expected Result | IAM Check |
|--------|-------|--------|-----------------|-----------|
| `DeleteAccessPoint` | Bob | Alice's AP | `AccessDenied` | `aws:ResourceTag/uuid ≠ aws:PrincipalTag/uuid` |
| `DeleteAccessPoint` | Alice | Alice's AP | `200 OK` | `aws:ResourceTag/uuid == aws:PrincipalTag/uuid` |
| `DescribeAccessPoints` | Bob | All APs | `200 OK` (all visible) | Read allowed, no ABAC on describe |

**Implementation:**
```python
# tests/integration/test_abac_efs_isolation.py

def test_user_cannot_delete_other_user_access_point():
    # Alice creates access point
    alice_token = get_oidc_token(user='alice')
    alice_creds = assume_role_with_token(alice_token)
    alice_ap = create_investigation(alice_creds, cluster='test', inv='alice-inv')
    alice_ap_id = extract_access_point_id(alice_ap)
    
    # Bob tries to delete Alice's access point
    bob_token = get_oidc_token(user='bob')
    bob_creds = assume_role_with_token(bob_token)
    
    with pytest.raises(ClientError) as exc:
        efs_client_bob = boto3.client('efs', **bob_creds)
        efs_client_bob.delete_access_point(AccessPointId=alice_ap_id)
    
    assert exc.value.response['Error']['Code'] == 'AccessDeniedException'
    
    # Verify Alice can still delete her own access point
    efs_client_alice = boto3.client('efs', **alice_creds)
    response = efs_client_alice.delete_access_point(AccessPointId=alice_ap_id)
    assert response['ResponseMetadata']['HTTPStatusCode'] == 204
```

### Scenario 3: EFS Path Isolation (Defense-in-Depth)

**Setup:**
1. Alice and Bob both create investigations for same cluster/investigation ID
2. Lambda creates separate access points with different path hashes

**Test Cases:**

| Check | Expected Result |
|-------|-----------------|
| Alice's path | `/test-cluster/<alice-hash>/test-inv` |
| Bob's path | `/test-cluster/<bob-hash>/test-inv` |
| Path equality | Paths must be different |
| Mounted directory | Alice sees Alice's data, Bob sees Bob's data |

**Implementation:**
```python
# tests/integration/test_abac_efs_path_isolation.py

def test_same_investigation_gets_isolated_paths():
    # Alice creates investigation
    alice_token = get_oidc_token(user='alice')
    alice_result = create_investigation(alice_token, cluster='test', inv='shared-inv')
    alice_path = extract_efs_path(alice_result)
    
    # Bob creates investigation for SAME cluster/investigation ID
    bob_token = get_oidc_token(user='bob')
    bob_result = create_investigation(bob_token, cluster='test', inv='shared-inv')
    bob_path = extract_efs_path(bob_result)
    
    # Paths must be different (hash-based isolation)
    assert alice_path != bob_path
    assert '/test-cluster/' in alice_path
    assert '/test-cluster/' in bob_path
    assert 'shared-inv' in alice_path
    assert 'shared-inv' in bob_path
    
    # Extract hashes from paths
    alice_hash = alice_path.split('/')[2]  # /cluster/HASH/inv
    bob_hash = bob_path.split('/')[2]
    assert alice_hash != bob_hash
    assert len(alice_hash) == 16  # SHA256[:16]
    assert len(bob_hash) == 16
```

### Scenario 4: Tag Tampering Prevention

**Setup:**
Verify that users cannot create tasks/access points with forged tags

**Test Cases:**

| Action | Expected Result |
|--------|-----------------|
| Bob creates task with `uuid=alice-uuid` tag | Denied (Lambda validates) |
| Bob assumes role with forged session tag | Denied (STS validates against JWT) |
| Bob modifies JWT before STS call | Signature validation fails |

**Implementation:**
```python
# tests/integration/test_abac_tag_tampering.py

def test_cannot_create_task_with_forged_tag():
    """Verify Lambda validates session tag matches resource tag."""
    bob_token = get_oidc_token(user='bob')
    bob_creds = assume_role_with_token(bob_token)
    
    # Bob tries to create investigation with forged ABAC value
    # This should fail in the Lambda handler when it validates
    # that the session tag matches the requested tag
    with pytest.raises(Exception) as exc:
        # Hypothetical: Bob tries to pass alice's UUID
        create_investigation(
            bob_creds,
            cluster='test',
            inv='forged-inv',
            forged_abac_tag='alice-uuid-here'  # This would be rejected
        )
    
    # Lambda should reject mismatched tags
    assert 'ABAC' in str(exc.value) or 'tag' in str(exc.value).lower()
```

## Test Infrastructure Requirements

### 1. Multi-User OIDC Token Generator

```python
# tests/integration/fixtures/oidc.py

def get_oidc_token(user: str) -> str:
    """
    Get OIDC token for test user.
    
    Options:
    - Real Keycloak (dev environment with test users alice, bob)
    - Mock JWT generator (for unit-like integration tests)
    """
    if os.getenv('USE_REAL_KEYCLOAK'):
        return keycloak_login(username=user, password=f'test-{user}')
    else:
        return generate_mock_jwt(
            sub=user,
            uuid=f'test-uuid-{user}',
            groups=['sre-operators']
        )
```

### 2. AWS Credentials Helper

```python
# tests/integration/fixtures/aws.py

def assume_role_with_token(id_token: str) -> dict:
    """AssumeRoleWithWebIdentity and return credentials dict."""
    sts = boto3.client('sts')
    response = sts.assume_role_with_web_identity(
        RoleArn=os.getenv('SRE_ROLE_ARN'),
        RoleSessionName=f'test-session-{uuid.uuid4()}',
        WebIdentityToken=id_token
    )
    return {
        'aws_access_key_id': response['Credentials']['AccessKeyId'],
        'aws_secret_access_key': response['Credentials']['SecretAccessKey'],
        'aws_session_token': response['Credentials']['SessionToken']
    }
```

### 3. Cleanup Fixture

```python
# tests/integration/conftest.py

@pytest.fixture(scope='function')
def cleanup_resources():
    """Track and cleanup resources created during tests."""
    created_tasks = []
    created_aps = []
    
    yield {'tasks': created_tasks, 'aps': created_aps}
    
    # Cleanup
    for task_arn in created_tasks:
        try:
            ecs.stop_task(cluster=CLUSTER, task=task_arn, reason='test cleanup')
        except:
            pass
    
    for ap_id in created_aps:
        try:
            efs.delete_access_point(AccessPointId=ap_id)
        except:
            pass
```

## Test Execution

### Local/Dev Environment

```bash
# Requires real AWS credentials and Keycloak instance
export USE_REAL_KEYCLOAK=true
export KEYCLOAK_URL=https://keycloak.dev.example.com
export SRE_ROLE_ARN=arn:aws:iam::123456789012:role/rosa-boundary-dev-sre-shared
export ECS_CLUSTER=rosa-boundary-dev

pytest tests/integration/test_abac_*.py -v --tb=short
```

### CI Pipeline

```yaml
# .github/workflows/integration-tests.yml

name: ABAC Integration Tests
on: [pull_request]

jobs:
  abac-isolation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup test users in Keycloak
        run: |
          # Create alice and bob test users
          ./tests/integration/setup-keycloak-users.sh
      
      - name: Run ABAC isolation tests
        env:
          USE_REAL_KEYCLOAK: "true"
          KEYCLOAK_URL: ${{ secrets.DEV_KEYCLOAK_URL }}
          SRE_ROLE_ARN: ${{ secrets.DEV_SRE_ROLE_ARN }}
        run: |
          pytest tests/integration/test_abac_*.py -v --junit-xml=results.xml
      
      - name: Cleanup test resources
        if: always()
        run: ./tests/integration/cleanup-test-resources.sh
```

## Success Criteria

**All tests must pass before merging ABAC-related changes:**

- [ ] Bob cannot exec into Alice's task (ECS ABAC)
- [ ] Bob cannot stop Alice's task (ECS ABAC)
- [ ] Bob cannot delete Alice's access point (EFS ABAC)
- [ ] Alice and Bob get different EFS paths for same investigation
- [ ] Tag tampering attempts are rejected
- [ ] Alice can access her own resources (positive test)

## Current Status

| Layer | Unit Tests | Integration Tests | Status |
|-------|------------|-------------------|--------|
| Lambda (Layer 2) | ✅ Yes | ❌ No | Partially tested |
| EFS Path (Layer 3) | ✅ Yes | ❌ No | Partially tested |
| IAM Policy (Layer 1) | ❌ No | ❌ **Missing** | **Not tested** |

**Recommendation:** Implement integration tests before declaring ABAC feature complete.

## References

- AWS IAM testing best practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html
- Lambda test patterns: https://docs.aws.amazon.com/lambda/latest/dg/testing-functions.html
- ECS integration testing: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-testing.html
