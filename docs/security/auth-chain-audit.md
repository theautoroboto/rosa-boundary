# Authentication Chain Security Audit

**Audit Date**: 2026-05-20
**Commit**: 5b8a844
**Auditor**: Adversary Agent (claude-sonnet-4-6)
**Scope**: Full authentication chain — Go CLI PKCE flow, Lambda OIDC validation, STS role assumption

---

## Executive Summary

The rosa-boundary authentication chain is composed of three stages: (1) a Go CLI performing PKCE browser authentication against Keycloak, (2) Lambda-based OIDC token validation with group membership enforcement, and (3) STS-based role assumption for AWS resource access. The core PKCE implementation, JWKS validation, and ABAC session tagging are correctly implemented. However, a structural authorization gap allows any Keycloak-authenticated user (regardless of group membership) to assume the shared SRE role directly via STS without going through the Lambda's group membership check. The group check is therefore a soft application-layer control, not an IAM-enforced boundary. Additional issues include missing validation of the `sub` claim (which can be `None`), no sanitization of JWT-derived ABAC tag values before they are used in ECS/STS API calls, and information disclosure in the 403 error response that reveals a user's group memberships and the required group names to any caller whose token is stolen or replayed.

---

## Findings

### Aauth-1: Group Membership Check Is Not Enforced at IAM Layer — Any Keycloak User Can Assume SRE Role

**Severity**: High
**File**: `deploy/regional/oidc.tf:88-143`, `deploy/regional/lambda-invoker.tf:13-62`, `internal/cmd/start_task.go:149`

**Description**: The shared SRE role (`sre_shared`) trust policy conditions on `<oidc_provider_domain>:aud == oidc_client_id` only. It does not enforce group membership (`sre-team`, `platform-sre`, etc.). Group membership is checked exclusively inside the Lambda handler at `handler.py:209-215`.

The CLI's `start_task.go` line 149 calls `AssumeRoleWithWebIdentity` with the original OIDC token and the SRE role ARN **directly** — STS validates the token signature and audience, but not Keycloak group membership. The Lambda's group check at lines 209-215 is executed before `create_investigation_task()` but the CLI independently assumes the SRE role via STS whether or not the Lambda was ever called.

Similarly, `lambda_invoker.tf:13-62` shows the invoker role trust policy only constrains `aud`, not group membership.

**Exploit Scenario**: Any user with a valid Keycloak OIDC token (audience `aws-sre-access`) — including developers, contractors, or former employees whose accounts have not been fully deprovisioned — can call `sts:AssumeRoleWithWebIdentity` directly (without invoking the Lambda) and obtain `sre_shared` credentials. With those credentials, they can enumerate all running ECS tasks and task definitions (the `DescribeAndListECS` statement has no conditions), reading investigation metadata including `cluster_id`, `investigation_id`, `oidc_sub`, username, OC version, and deadlines for all active SRE investigations. The ABAC condition on `ecs:ExecuteCommand` limits exec access to tasks tagged with the attacker's own username, but enumeration of all investigations is unrestricted.

**Recommendation**: Add a group membership condition to both the `sre_shared` and `lambda_invoker` trust policies using the Keycloak groups claim. AWS IAM OIDC trust policies support conditions on custom JWT claims:

```hcl
Condition = {
  StringEquals = {
    "${local.oidc_provider_domain}:aud" = var.oidc_client_id
  }
  # Enforce group membership at IAM layer, not just application layer
  "ForAnyValue:StringLike" = {
    "${local.oidc_provider_domain}:groups" = var.required_groups
  }
}
```

Note: This requires the Keycloak OIDC client to include the `groups` claim in the token (via a groups protocol mapper), and the claim name used in the condition must match exactly. This makes group enforcement tamper-proof at the IAM layer independent of Lambda code.

---

### Aauth-2: `sub` Claim Is Not Validated for Presence Before Use as EFS/ECS Tag

**Severity**: Medium
**File**: `lambda/create-investigation/handler.py:166`, `lambda/create-investigation/handler.py:230`, `lambda/create-investigation/handler.py:625`, `lambda/create-investigation/handler.py:683`

**Description**: At line 166, `user_sub = claims.get('sub')`. If the JWT does not contain a `sub` claim (malformed or misconfigured Keycloak token), `user_sub` is `None`. This `None` value is passed through to `create_investigation_task()` as `oidc_sub=None` (line 230), and then to `efs.create_access_point()` Tags at line 625: `{'Key': 'oidc_sub', 'Value': None}`. The AWS `boto3` EFS API will reject `None` tag values with a `ValidationException`, which is caught by the outer `except ClientError as e:` block and re-raised, resulting in a 500 error. However, no meaningful error message is returned to the caller and no specific validation occurs to detect this failure mode early.

More critically, for audit integrity: `oidc_sub` is the immutable audit identifier linking a task to a specific Keycloak user. A `None` sub would make the audit record unattributable.

**Exploit Scenario**: An attacker who crafts a JWT without a `sub` claim (but valid signature and audience) would cause a 500 error rather than a 403, potentially revealing information about the validation pipeline. No actual task is created, but the error path is not properly instrumented.

**Recommendation**: Add explicit validation of `sub` immediately after token validation:

```python
user_sub = claims.get('sub')
if not user_sub or not isinstance(user_sub, str):
    logger.warning("Token missing required 'sub' claim")
    return response(401, {'error': 'Invalid token: missing sub claim'})
```

---

### Aauth-3: JWT-Derived ABAC Tag Value Has No Length or Character Sanitization

**Severity**: Medium
**File**: `lambda/create-investigation/handler.py:196`, `lambda/create-investigation/handler.py:684`

**Description**: The `abac_tag_value` is extracted from `claims['https://aws.amazon.com/tags']['principal_tags'][ABAC_TAG_KEY][0]` (line 196) without any length or character validation. AWS STS session tag values have a maximum length of 256 characters and must match the pattern `[\p{L}\p{Z}\p{N}_.:/=+\-@]+`. ECS tag values also have constraints (max 256 characters).

If a Keycloak token mapper is misconfigured to produce a tag value exceeding 256 characters or containing invalid characters (e.g., `<`, `>`, `&`, Unicode control characters), the Lambda will propagate the invalid value to both `ecs.tag_resource()` (line 684) and the ECS `run_task` tags call, causing an API error. The fallback path `abac_tag_value = username` (line 204) uses `preferred_username` or email, which are similarly unsanitized.

**Exploit Scenario**: A Keycloak administrator could configure a groups or tags mapper that produces oversized or specially-crafted claim values, causing the Lambda to fail with a 500 error on every invocation for affected users (denial of service for specific SREs). Alternatively, if a future code path uses the `abac_tag_value` in a string comparison or policy evaluation without the ECS tag constraint enforcement, unexpected values could produce unpredictable authorization behavior.

**Recommendation**: Validate and sanitize `abac_tag_value` before use:

```python
import re
def sanitize_sts_tag_value(value: str) -> str:
    """Sanitize a value for use as an STS session tag or ECS tag."""
    if not isinstance(value, str):
        raise ValueError(f"Tag value must be a string, got {type(value)}")
    # AWS tag value constraints: printable chars, max 256
    value = value[:256]
    if not re.match(r'^[\w_.:/=+\-@\s]+$', value):
        raise ValueError(f"Tag value contains invalid characters: {value[:50]}")
    return value
```

Apply this to both the JWT-derived `abac_tag_value` and the `username` fallback.

---

### Aauth-4: Token Cache Uses File Modification Time — Does Not Validate JWT `exp` Claim

**Severity**: Low
**File**: `internal/auth/token.go:34-35`

**Description**: `CachedToken()` determines cache validity by checking file modification time against a fixed 4-minute `cacheValidityPeriod` (`time.Since(info.ModTime()) >= 4*time.Minute`). The function never parses the JWT to check the actual `exp` claim. This creates two failure modes:

1. **Short-lived token submitted after expiry**: If Keycloak is configured with a token lifetime shorter than 4 minutes (e.g., 1 minute for strict environments), the CLI will serve a cached but already-expired token to the Lambda. The Lambda will reject it with 401, but the error message ("Invalid or expired token") is unhelpful — the user must force a re-login with `--force-login`.

2. **Long-lived token remains valid beyond expectation**: If Keycloak issues tokens with a 60-minute lifetime, the file mtime cache evicts the token after 4 minutes but the JWT itself remains valid for 56 more minutes. The CLI re-authenticates unnecessarily, but a token stolen from the cache file within the 4-minute window is valid for much longer against the Lambda and STS.

**Exploit Scenario**: An attacker who reads the cache file (`~/.cache/rosa-boundary/token-cache`) within 4 minutes of authentication gets a token that may remain valid for the full Keycloak token lifetime (often 5-60 minutes), not just 4 minutes. The mtime-based cache does not communicate the true validity window.

**Recommendation**: Parse the JWT `exp` claim client-side to determine actual validity. Go does not require a full JWT library for this — base64-decode the payload and parse the `exp` field:

```go
func tokenExpiry(token string) (time.Time, error) {
    parts := strings.SplitN(token, ".", 3)
    if len(parts) != 3 {
        return time.Time{}, fmt.Errorf("invalid token format")
    }
    payload, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return time.Time{}, err
    }
    var claims struct { Exp int64 `json:"exp"` }
    if err := json.Unmarshal(payload, &claims); err != nil {
        return time.Time{}, err
    }
    return time.Unix(claims.Exp, 0), nil
}
```

Use `tokenExpiry()` in `CachedToken()` with a small clock skew buffer (30 seconds) to determine if the cached token is still valid for submission.

---

### Aauth-5: 403 Response Discloses User Group Memberships and Required Group Names

**Severity**: Low
**File**: `lambda/create-investigation/handler.py:212-215`

**Description**: When a user is denied due to insufficient group membership, the 403 response body includes two pieces of information that should not be returned:

1. `'groups': groups` (line 214) — the full list of the caller's Keycloak group memberships extracted from the JWT.
2. The error message at line 213 includes `{REQUIRED_GROUPS}` — the complete list of group names that would grant access (e.g., `['sre-team', 'platform-sre', 'osd-sre']`).

**Exploit Scenario**: If an attacker obtains a valid OIDC token (via M15 replay, L12 stdout capture, or cache file theft) and the user is not in `sre-team`, the 403 response reveals: (a) the victim's complete group membership list — useful for internal reconnaissance; (b) the exact group names needed for access — reduces the effort required for social engineering or privilege escalation attacks targeting Keycloak group management.

**Recommendation**: Remove sensitive data from the 403 response:

```python
return response(403, {
    'error': 'User not authorized: insufficient group membership'
    # Remove: 'groups': groups  (remove - leaks group memberships)
    # Remove: REQUIRED_GROUPS from error string (change to generic message)
})
```

Log the group details server-side for debugging only.

---

### Aauth-6: Hardcoded AWS Account ID in Committed Configuration File

**Severity**: Low
**File**: `deploy/keycloak/overlays/dev/service-account.yaml:7`

**Description**: The file contains a hardcoded AWS account ID in the IRSA annotation:

```yaml
eks.amazonaws.com/role-arn: arn:aws:iam::641875867446:role/dev-keycloak
```

Account ID `641875867446` is committed to the repository and appears in multiple documentation files. AWS account IDs are not considered secret by AWS, but committing them into version-controlled configuration:

1. Creates a permanent audit trail linking the account ID to the project and organization.
2. Makes the account a more identifiable target for account-level enumeration attacks.
3. Violates the principle of separating infrastructure configuration from code — account IDs should be injected via environment variables or Kustomize substitutions, not hardcoded.

**Recommendation**: Use Kustomize configmap generator or variable substitution:

```yaml
# service-account.yaml
metadata:
  annotations:
    eks.amazonaws.com/role-arn: $(AWS_ACCOUNT_ARN)
```

Or use a Kustomize `vars` section to inject the account ID from a configmap. At minimum, document that this is a dev account ID and not sensitive.

---

### Aauth-7: `_validate_with_jwks()` Missing `issuer=` Parameter in `jwt.decode()` Call

**Severity**: Medium (already tracked as M19, expanding evidence)
**File**: `lambda/create-investigation/handler.py:315-325`

**Note**: This is already tracked as M19. New code evidence is provided here for completeness.

The `jwt.decode()` call at line 315 does not pass `issuer=` or `verify_iss=True`. The pre-routing check in `validate_oidc_token()` (lines 374-388) does verify the unverified `iss` against configured issuers before dispatching to `_validate_with_jwks()`, but `_validate_with_jwks()` itself is designed as a reusable generic function that accepts any `jwks_url` and `client_id`. If called from a context other than `validate_oidc_token()` (test fixtures, future code paths, or a monkey-patching attack in the Lambda environment), the `iss` claim is not independently verified by the PyJWT library.

The fix (add `issuer=` parameter to `_validate_with_jwks()`) is documented in M19.

---

### Aauth-8: Lambda Never Performs STS `AssumeRoleWithWebIdentity` — Group Check Can Be Bypassed by Direct STS Call

**Severity**: High (related to Aauth-1, distinct mechanism)
**File**: `lambda/create-investigation/handler.py:222-223`, `internal/cmd/start_task.go:149`

**Description**: The Lambda handler at line 222-223 sets `role_arn = SHARED_ROLE_ARN` and returns it in the response body. The Lambda never calls `sts:AssumeRoleWithWebIdentity` itself. The CLI (`start_task.go:149`) calls `AssumeRoleWithWebIdentity` using the original OIDC token directly with the SRE role ARN.

This means the SRE role assumption is entirely independent of the Lambda invocation. An attacker with a valid OIDC token who knows the SRE role ARN (disclosed in CLI output, documentation, or Lambda response body) can:

1. Skip calling the Lambda entirely.
2. Call `sts:AssumeRoleWithWebIdentity` directly with the OIDC token and the SRE role ARN.
3. Obtain `sre_shared` credentials without the Lambda's group membership check having been executed.

The STS trust policy (oidc.tf:88-143) only validates `aud` — not group membership. The group check exists only in Lambda application code.

**Note**: This is architecturally distinct from Aauth-1, which focuses on the policy design. Aauth-8 highlights the specific code path: the Lambda's validation is not a prerequisite for SRE role assumption because the CLI calls STS independently after the Lambda call, using the same token.

**Recommendation**: The root fix is Aauth-1 (add group condition to the trust policy). Additionally, consider whether the Lambda should perform the STS assumption itself and return scoped short-lived credentials rather than returning the role ARN for the CLI to assume independently. This would make the Lambda the mandatory authorization checkpoint.

---

## Coverage Map

| Component | Location | Status | Notes |
|-----------|----------|--------|-------|
| PKCE code verifier generation | `internal/auth/oidc.go:110-119` | Pass | `crypto/rand`, S256 challenge, correct |
| PKCE state CSRF protection | `internal/auth/callback.go:73-76` | Pass | State verified before accepting code |
| Callback server binding | `internal/auth/callback.go:87` | Pass | Binds to `127.0.0.1` only |
| Callback HTML injection | `internal/auth/callback.go:60` | Pass | `html.EscapeString` + `sanitizeOAuthParam` |
| Token exchange (PKCE) | `internal/auth/oidc.go:146-180` | Pass | Code + verifier exchange, error handling |
| Token cache file permissions | `internal/auth/token.go:62` | Pass | `0o600` on cache file, `0o700` on cache dir |
| Token cache validity (mtime) | `internal/auth/token.go:34-35` | Issue | Does not check JWT `exp` — see Aauth-4 |
| OIDC token to Lambda (transport) | `internal/lambda/client.go:86-89` | Pass | SDK invocation (SigV4), no plaintext |
| OIDC token in Lambda header | `lambda/create-investigation/handler.py:96-103` | Pass | Supports `x-oidc-token` + Bearer fallback |
| JWT signature verification | `lambda/create-investigation/handler.py:315-325` | Pass | `verify_signature=True`, RS256 only |
| `exp` claim verification | `lambda/create-investigation/handler.py:317-325` | Pass | `verify_exp=True` |
| `aud` claim verification | `lambda/create-investigation/handler.py:317-325` | Pass | `verify_aud=True`, audience=client_id |
| `iss` claim verification (pre-routing) | `lambda/create-investigation/handler.py:374-388` | Pass | Exact match before dispatch |
| `iss` claim verification (post-decode) | `lambda/create-investigation/handler.py:315-325` | Issue | Missing `issuer=` kwarg — see M19 |
| `nbf` claim verification | `lambda/create-investigation/handler.py:315-325` | Info | Not explicitly checked; PyJWT verifies by default if present |
| Algorithm restriction (no `alg:none`) | `lambda/create-investigation/handler.py:318` | Pass | `algorithms=["RS256"]` only |
| JWKS key selection | `lambda/create-investigation/handler.py:314` | Pass | `get_signing_key_from_jwt()` (kid-based) |
| JWKS fetch failure behavior | `lambda/create-investigation/handler.py:337-339` | Pass | Returns `None` on `RequestException` (fail-closed) |
| Multi-issuer routing (stage/prod) | `lambda/create-investigation/handler.py:374-388` | Pass | Exact `token_iss` match, fail-closed for unknown issuers |
| Cross-issuer validation prevention | `lambda/create-investigation/handler.py:374-388` | Pass | Each issuer uses its own JWKS URL |
| `sub` claim validation | `lambda/create-investigation/handler.py:166` | Issue | Not validated for presence/non-null — see Aauth-2 |
| `preferred_username` validation | `lambda/create-investigation/handler.py:168` | Issue | No length/char validation, falls back to email then 'unknown' |
| Group membership enforcement (app layer) | `lambda/create-investigation/handler.py:209-215` | Pass | Lambda enforces correctly |
| Group membership enforcement (IAM layer) | `deploy/regional/oidc.tf:88-143` | Issue | Not enforced — see Aauth-1, Aauth-8 |
| ABAC tag extraction | `lambda/create-investigation/handler.py:183-204` | Partial | Correct extraction, but no value sanitization — see Aauth-3 |
| ABAC tag value sanitization | `lambda/create-investigation/handler.py:196,204` | Issue | No length/char validation — see Aauth-3 |
| STS `TransitiveTagKeys` | `deploy/regional/oidc.tf:98-101` | Pass | `sts:TagSession` in trust policy; propagation from JWT |
| STS role assumption (CLI) | `internal/aws/sts.go:21-46` | Pass | Correct anonymous credentials, error handling |
| jti replay protection | Lambda handler | Issue | Not implemented — M15 |
| Token replay window | Lambda handler | Issue | `exp` is the only replay gate — M15 |
| JWKS caching | Lambda handler | Issue | Per-invocation instantiation — M17 |
| CORS policy | Lambda function URL | Issue | Wildcard origin — M7 |
| Lambda function URL auth | `deploy/regional/lambda-create-investigation.tf:163` | Pass | `authorization_type = "AWS_IAM"` |
| TLS for Lambda invocation | `internal/lambda/client.go:72` | Pass | AWS SDK uses HTTPS by default |
| TLS for JWKS fetch | Python `requests` library | Pass | Default HTTPS; no `verify=False` |
| 403 information disclosure | `lambda/create-investigation/handler.py:213-214` | Issue | Leaks group names and user's groups — see Aauth-5 |
| Error response sanitization | `lambda/create-investigation/handler.py:273-275` | Pass | Generic 500 message, details only in logs |
| Hardcoded account ID | `deploy/keycloak/overlays/dev/service-account.yaml:7` | Issue | See Aauth-6 |
| Lambda not in VPC | `deploy/regional/lambda-create-investigation.tf:114-158` | Issue | JWKS over public internet — H2 |

---

## New Items for `adversary-findings.json`

The following findings from this audit are net-new (not in existing M1-M21, L1-L14, H1-H6):

| Finding ID | Severity | Title | File | Lines |
|------------|----------|-------|------|-------|
| H7 | High | Group membership check bypassed by direct STS role assumption | `deploy/regional/oidc.tf`, `deploy/regional/lambda-invoker.tf`, `internal/cmd/start_task.go` | 88-143, 13-62, 149 |
| M22 | Medium | `sub` claim not validated for presence — `None` propagates to audit tags | `lambda/create-investigation/handler.py` | 166, 230, 625, 683 |
| M23 | Medium | ABAC tag value from JWT has no length or character validation | `lambda/create-investigation/handler.py` | 196, 684 |
| L15 | Low | Token cache uses file mtime, not JWT `exp` — expiry not checked client-side | `internal/auth/token.go` | 34-35 |
| L16 | Low | 403 response leaks user group memberships and required group names | `lambda/create-investigation/handler.py` | 212-215 |
| L17 | Low | Hardcoded AWS account ID in committed Keycloak overlay | `deploy/keycloak/overlays/dev/service-account.yaml` | 7 |

