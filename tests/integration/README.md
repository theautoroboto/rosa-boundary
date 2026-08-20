# ABAC Integration Tests

Integration tests verifying that IAM policies correctly enforce ABAC (Attribute-Based Access Control) isolation, preventing users from accessing each other's work.

## Overview

These tests verify three layers of ABAC enforcement:

1. **IAM Policies** - AWS IAM prevents cross-user ECS/EFS operations
2. **Lambda Validation** - Create-investigation handler validates tag matching
3. **EFS Path Isolation** - Different users get different filesystem paths

## Prerequisites

### 1. AWS Environment

You need a deployed rosa-boundary environment with:
- ✅ Keycloak instance with test users
- ✅ IAM OIDC provider configured
- ✅ SRE shared role deployed (`rosa-boundary-{stage}-sre-shared`)
- ✅ ECS cluster running (`rosa-boundary-{stage}`)
- ✅ EFS filesystem with access points

### 2. Test Users

Create two test users in Keycloak:

**User: alice**
- Username: `alice`
- Password: `test-alice` (or set `ALICE_PASSWORD` env var)
- UUID attribute: `test-uuid-alice`
- Groups: `sre-operators`

**User: bob**
- Username: `bob`
- Password: `test-bob` (or set `BOB_PASSWORD` env var)
- UUID attribute: `test-uuid-bob`
- Groups: `sre-operators`

See `docs/configuration/dev-keycloak-uuid-setup.md` for Keycloak configuration.

### 3. Python Environment

```bash
cd tests/integration
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Running Tests

### Quick Start (Local Dev)

```bash
export KEYCLOAK_URL=https://keycloak.dev.example.com
export SRE_ROLE_ARN=arn:aws:iam::123456789012:role/rosa-boundary-dev-sre-shared
export ECS_CLUSTER=rosa-boundary-dev
export EFS_FILESYSTEM_ID=fs-0123456789abcdef
export AWS_REGION=us-east-2

# Run all ABAC tests
pytest -v -m abac

# Run specific test file
pytest -v test_abac_ecs_isolation.py

# Run specific test
pytest -v test_abac_ecs_isolation.py::TestABACECSIsolation::test_user_cannot_exec_into_other_user_task
```

### With Custom Passwords

```bash
export ALICE_PASSWORD=my-alice-password
export BOB_PASSWORD=my-bob-password

pytest -v -m abac
```

### Using Mock Tokens (Unit-Like Tests)

For tests that don't need real AWS STS calls:

```bash
export USE_MOCK_TOKENS=true
pytest -v test_abac_path_isolation.py  # Path logic tests don't need real AWS
```

### Parallel Execution

```bash
# Run tests in parallel (faster, but harder to debug)
pytest -v -m abac -n auto
```

### Generate HTML Report

```bash
pytest -v -m abac --html=report.html --self-contained-html
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KEYCLOAK_URL` | Yes* | - | Keycloak base URL |
| `SRE_ROLE_ARN` | Yes | - | ARN of sre-shared IAM role |
| `ECS_CLUSTER` | Yes | - | ECS cluster name |
| `EFS_FILESYSTEM_ID` | Yes | - | EFS filesystem ID |
| `AWS_REGION` | No | `us-east-2` | AWS region |
| `KEYCLOAK_REALM` | No | `rosa-boundary` | Keycloak realm name |
| `OIDC_CLIENT_ID` | No | `rosa-boundary-sre` | OIDC client ID |
| `ALICE_PASSWORD` | No | `test-alice` | Alice's password |
| `BOB_PASSWORD` | No | `test-bob` | Bob's password |
| `USE_MOCK_TOKENS` | No | `false` | Use mock JWTs instead of real Keycloak |

\* Not required if `USE_MOCK_TOKENS=true`

## Test Structure

```
tests/integration/
├── README.md                          # This file
├── requirements.txt                   # Python dependencies
├── conftest.py                        # Pytest fixtures
├── fixtures/
│   ├── oidc.py                       # OIDC token generation
│   └── aws.py                         # AWS credential helpers
├── test_abac_ecs_isolation.py        # ECS task isolation tests
├── test_abac_efs_isolation.py        # EFS access point isolation tests
└── test_abac_path_isolation.py       # Path hash isolation tests
```

## Test Scenarios

### ECS Task Isolation (`test_abac_ecs_isolation.py`)

- ✅ Bob cannot exec into Alice's task
- ✅ Bob cannot stop Alice's task
- ✅ Alice CAN exec into her own task (positive test)
- ✅ Users can list all tasks (read not restricted)

### EFS Access Point Isolation (`test_abac_efs_isolation.py`)

- ✅ Bob cannot delete Alice's access point
- ✅ Alice CAN delete her own access point (positive test)
- ✅ Users can describe all access points (read not restricted)
- ✅ Access points have required ABAC tags

### Path Isolation (`test_abac_path_isolation.py`)

- ✅ Alice and Bob get different paths for same investigation
- ✅ Path hash is deterministic
- ✅ Paths stay within AWS 100-char limit
- ✅ Hash-based paths prevent collision

## Expected Test Results

### Successful Run

```
tests/integration/test_abac_ecs_isolation.py::TestABACECSIsolation::test_user_cannot_exec_into_other_user_task PASSED
tests/integration/test_abac_ecs_isolation.py::TestABACECSIsolation::test_user_cannot_stop_other_user_task PASSED
tests/integration/test_abac_ecs_isolation.py::TestABACECSIsolation::test_user_can_exec_into_own_task PASSED
tests/integration/test_abac_efs_isolation.py::TestABACEFSIsolation::test_user_cannot_delete_other_user_access_point PASSED
tests/integration/test_abac_efs_isolation.py::TestABACEFSIsolation::test_user_can_delete_own_access_point PASSED
tests/integration/test_abac_path_isolation.py::TestABACPathIsolation::test_alice_and_bob_get_different_paths_same_investigation PASSED

======================== 6 passed in 45.23s ========================
```

### Test Failures

**If tests fail with `AccessDeniedException` for Alice:**
- IAM policy may be misconfigured
- Session tags may not be propagating from JWT
- Check Keycloak JWT includes `https://aws.amazon.com/tags.principal_tags.uuid`

**If tests fail with `pytest.skip`:**
- No tasks/access points exist for testing
- Run `rosa-boundary create-investigation` first to create resources

**If tests fail with authentication errors:**
- Verify Keycloak users exist with correct passwords
- Check `KEYCLOAK_URL` is accessible
- Verify OIDC client ID matches

## Debugging

### Enable Verbose Boto3 Logging

```bash
export BOTO_LOG_LEVEL=DEBUG
pytest -v -s test_abac_ecs_isolation.py
```

### Inspect JWT Token

```python
from fixtures.oidc import get_oidc_token, decode_jwt_payload

token = get_oidc_token(user='alice', password='test-alice')
payload = decode_jwt_payload(token)
print(payload)
# Should show: {'uuid': 'test-uuid-alice', 'https://aws.amazon.com/tags': {...}}
```

### Check IAM Policy

```bash
aws iam get-role-policy \
  --role-name rosa-boundary-dev-sre-shared \
  --policy-name SRESharedPolicy
```

Verify condition includes:
```json
{
  "StringEquals": {
    "ecs:ResourceTag/uuid": "${aws:PrincipalTag/uuid}"
  }
}
```

## Running in CI

These tests can be run in any CI system that supports:
- Python 3.11+
- AWS credentials (IAM role or access keys)
- Access to Keycloak (or use `USE_MOCK_TOKENS=true` for path tests)

**CI Environment Setup:**
- Install dependencies: `pip install -r requirements.txt`
- Set environment variables (see Environment Variables section)
- Run tests: `pytest -v -m abac`

## Cleanup

Tests automatically clean up resources created during testing (via `cleanup_resources` fixture).

Manual cleanup if needed:

```bash
# Stop test tasks
aws ecs list-tasks --cluster rosa-boundary-dev --query 'taskArns[]' --output text | \
  xargs -I {} aws ecs stop-task --cluster rosa-boundary-dev --task {}

# Delete test access points
aws efs describe-access-points --file-system-id fs-xxx --query 'AccessPoints[?Tags[?Key==`IntegrationTest`]].AccessPointId' --output text | \
  xargs -I {} aws efs delete-access-point --access-point-id {}
```

## Troubleshooting

### Error: "Missing required ABAC claim: uuid"

**Cause:** JWT doesn't contain `principal_tags.uuid`

**Fix:** Configure Keycloak protocol mapper:
```yaml
protocolMappers:
  - name: aws-session-tags
    protocol: openid-connect
    protocolMapper: oidc-script-based-protocol-mapper
    config:
      script: |
        token.setOtherClaims('https://aws.amazon.com/tags', {
          'principal_tags': {'uuid': user.getAttribute('uuid')[0]}
        });
```

### Error: "User test-uuid-alice was denied access to her own task"

**Cause:** IAM policy not allowing access to own resources

**Possible reasons:**
1. IAM policy condition uses wrong tag key (username instead of uuid)
2. Task not tagged with uuid
3. Session tags not propagating from JWT

**Fix:** Verify:
```bash
# Check task tags
aws ecs describe-tasks --cluster rosa-boundary-dev --tasks <task-arn> --query 'tasks[0].tags'

# Should show: [{"key": "uuid", "value": "test-uuid-alice"}]
```

### Tests skip with "No running tasks found"

**Cause:** No rosa-boundary tasks exist in ECS cluster

**Fix:** Create an investigation first:
```bash
rosa-boundary create-investigation \
  --cluster-id test-cluster \
  --investigation-id test-inv
```

## Contributing

When adding new ABAC enforcement:

1. ✅ Update IAM policies in `deploy/regional/oidc.tf`
2. ✅ Add integration test to verify enforcement
3. ✅ Test both denial (Bob→Alice) and allow (Alice→Alice)
4. ✅ Document in `tests/ABAC_INTEGRATION_TEST_PLAN.md`

## References

- [ABAC Integration Test Plan](../ABAC_INTEGRATION_TEST_PLAN.md)
- [Dev Keycloak UUID Setup](../../docs/configuration/dev-keycloak-uuid-setup.md)
- [AWS ABAC Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction_attribute-based-access-control.html)
