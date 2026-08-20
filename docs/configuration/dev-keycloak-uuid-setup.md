# Dev Keycloak UUID Configuration

## Overview

Dev Keycloak must emit the same JWT structure as production Red Hat EmployeeIDP to ensure dev and production environments behave identically. This prevents environment-specific bugs in ABAC isolation logic.

## Required JWT Structure

**Production (EmployeeIDP):**
```json
{
  "sub": "alice@redhat.com",
  "preferred_username": "alice",
  "rhatUUID": "550e8400-e29b-41d4-a716-446655440000",
  "https://aws.amazon.com/tags": {
    "principal_tags": {
      "uuid": "550e8400-e29b-41d4-a716-446655440000"
    }
  }
}
```

**Dev Keycloak (must match):**
```json
{
  "sub": "alice",
  "preferred_username": "alice",
  "uuid": "<generated-or-set-uuid>",
  "https://aws.amazon.com/tags": {
    "principal_tags": {
      "uuid": "<same-uuid>"
    }
  }
}
```

## Keycloak Configuration Steps

### 1. Add UUID User Attribute

Users must have a `uuid` attribute set. You can either:

**Option A: Auto-generate UUIDs (recommended for dev)**

Create an event listener or user attribute provider that sets a UUID on first login:

```java
// Custom EventListenerProvider example
user.setSingleAttribute("uuid", UUID.randomUUID().toString());
```

**Option B: Set manually via Admin Console**

For each user:
1. Navigate to Users → Select user → Attributes
2. Add attribute:
   - Key: `uuid`
   - Value: `550e8400-e29b-41d4-a716-446655440000` (or generate one)

**Option C: Set in KeycloakRealmImport**

```yaml
users:
  - username: "alice"
    email: "alice@example.com"
    enabled: true
    attributes:
      uuid: ["550e8400-e29b-41d4-a716-446655440000"]
```

### 2. Add UUID Claim Mapper

Add a protocol mapper to expose the `uuid` attribute as a top-level JWT claim:

```yaml
protocolMappers:
  # Existing mappers...
  
  # UUID claim mapper
  - name: uuid
    protocol: openid-connect
    protocolMapper: oidc-usermodel-attribute-mapper
    consentRequired: false
    config:
      user.attribute: "uuid"
      claim.name: "uuid"
      id.token.claim: "true"
      access.token.claim: "true"
      userinfo.token.claim: "true"
      jsonType.label: "String"
```

### 3. Add AWS Session Tags Mapper

Add a protocol mapper for the `https://aws.amazon.com/tags` claim:

```yaml
protocolMappers:
  # AWS session tags claim
  - name: aws-session-tags
    protocol: openid-connect
    protocolMapper: oidc-script-based-protocol-mapper
    consentRequired: false
    config:
      script: |
        var uuid = user.getAttribute('uuid');
        if (uuid && uuid.length > 0) {
          token.setOtherClaims('https://aws.amazon.com/tags', {
            'principal_tags': {
              'uuid': uuid[0]
            }
          });
        }
      id.token.claim: "true"
      access.token.claim: "true"
```

**Note:** The script-based mapper requires JavaScript feature to be enabled in Keycloak.

**Alternative: Static hardcoded mapper (for simple dev setups)**

If script-based mappers are unavailable, you can use a hardcoded mapper that references the uuid attribute:

```yaml
protocolMappers:
  - name: aws-principal-tag-uuid
    protocol: openid-connect
    protocolMapper: oidc-hardcoded-claim-mapper
    consentRequired: false
    config:
      claim.name: "https://aws.amazon.com/tags.principal_tags.uuid"
      claim.value: "${user.attributes.uuid[0]}"
      id.token.claim: "true"
      access.token.claim: "true"
      jsonType.label: "String"
```

**Warning:** The hardcoded mapper syntax may not support nested JSON. If unavailable, use a custom JavaScript mapper or contact Red Hat for recommended approach.

### 4. Verify JWT Token

After configuration, login with a test user and decode the JWT to verify structure:

```bash
# Get token
TOKEN=$(rosa-boundary login --keycloak-url https://keycloak.example.com)

# Decode (use jwt.io or)
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .
```

Expected output:
```json
{
  "sub": "alice",
  "preferred_username": "alice",
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "https://aws.amazon.com/tags": {
    "principal_tags": {
      "uuid": "550e8400-e29b-41d4-a716-446655440000"
    }
  }
}
```

## Testing ABAC Isolation

After configuration, test that ABAC works:

```bash
# User Alice creates investigation
alice$ rosa-boundary create-investigation --cluster-id test-cluster --investigation-id test-001

# User Bob tries to join Alice's task (should fail)
bob$ rosa-boundary join-task <alice-task-id>
# Expected: AccessDenied - task tagged with Alice's UUID

# Bob creates his own investigation (should succeed)
bob$ rosa-boundary create-investigation --cluster-id test-cluster --investigation-id test-001
# Expected: New task created with Bob's UUID, different EFS path
```

## Migration from Username-Based Dev

If your dev environment currently uses `abac_tag_key = "username"`:

1. **Add UUID attributes** to all existing users (Option A, B, or C above)
2. **Add the protocol mappers** (steps 2 and 3)
3. **Verify tokens** include `principal_tags.uuid`
4. **Update Terraform**: `abac_tag_key = "uuid"` (now the default)
5. **Redeploy Lambda** with updated environment variable
6. **Test** with existing users

**Note:** Changing ABAC tag key will invalidate existing access points and tasks. Existing investigations will become inaccessible. Plan a maintenance window for the migration.

## Troubleshooting

### Token missing `https://aws.amazon.com/tags`

- Verify script-based mapper is enabled in Keycloak
- Check mapper configuration is applied to the correct client
- Ensure user has `uuid` attribute set

### Lambda returns "Missing required ABAC claim: uuid"

- Token doesn't contain `principal_tags.uuid`
- Check JWT with: `echo $TOKEN | cut -d'.' -f2 | base64 -d | jq`
- Verify mapper configuration

### Different UUIDs for same user across logins

- UUID attribute should be persistent, not regenerated
- Use Option A (event listener) or Option B (manual) to ensure stability
- Verify attribute is saved to user profile

## Production Parity Checklist

- [x] Dev Keycloak emits `principal_tags.uuid` claim
- [x] `abac_tag_key = "uuid"` in Terraform (default)
- [x] Lambda `ABAC_TAG_KEY = "uuid"` environment variable
- [x] IAM policies reference `${var.abac_tag_key}` (already correct)
- [x] EFS path isolation uses `abac_tag_value` (already correct)
- [x] All users have persistent UUID attributes

When all items are checked, dev and production environments have identical ABAC behavior.
