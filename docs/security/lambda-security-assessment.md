# Lambda Security Assessment

**Date:** 2026-06-01
**Branch:** `security_assessment`
**Scope:** `create-investigation` handler (input validation, injection risks, privilege escalation), Lambda execution role IAM (least privilege), `reap-tasks` handler (deadline correctness).
**Machine-readable findings:** `adversary-findings.json` (IDs: H10, M19, M22)
**Jira:** [ROSAENG-304](https://redhat.atlassian.net/browse/ROSAENG-304)

---

## create-investigation Handler

### HIGH — Cross-User EFS Data Access (H10)

**File:** `lambda/create-investigation/handler.py:586–644`

`find_existing_access_point()` runs unconditionally before any ownership check. When a caller supplies a `cluster_id`+`investigation_id` pair belonging to another SRE, the Lambda finds that user's existing EFS access point and reuses it at lines 601–603 with no verification that the access point's `username` tag matches the requesting user's identity. The ownership tags set at creation time (lines 625–626) are written but never read back for authorization.

Two exploitation variants exist:

**Variant A — Information disclosure via `skip_task=True`:**
The Lambda returns immediately at lines 640–644 with the victim's `accessPointId` in the HTTP 200 body (line 256). No ownership check is ever reached.

**Variant B — EFS data access via `skip_task=False`:**
The Lambda reuses the victim's access point, registers a new task definition mounting `/{cluster_id}/{investigation_id}/` (the victim's EFS directory), and launches a task tagged with the *attacker's* `username` ABAC value (line 684). Because the task bears the attacker's ABAC tag, the shared SRE role's `${aws:PrincipalTag/username}` condition is satisfied and the attacker can `ecs:ExecuteCommand` into their own task — which has the victim's `/home/sre` data mounted.

`investigation_id` and `cluster_id` are human-readable strings (`[a-zA-Z0-9_-]`, max 64 chars, validated at line 299), not UUIDs. They are routinely communicated in tickets and Slack channels.

**Fix:** After `find_existing_access_point()` returns a match, compare `existing_ap['Tags']['username']` (or `oidc_sub`) against the requesting user's identity before reusing the access point. Return 403 if the owner differs.

```python
if existing_ap:
    ap_owner = next(
        (t['Value'] for t in existing_ap.get('Tags', []) if t['Key'] == 'oidc_sub'),
        None
    )
    if ap_owner and ap_owner != oidc_sub:
        raise PermissionError(
            f"Access point for investigation '{investigation_id}' belongs to a different user"
        )
    access_point_id = existing_ap['AccessPointId']
```

---

### MEDIUM — JWT `issuer=` Not Validated by PyJWT (M19)

**File:** `lambda/create-investigation/handler.py:315`

`jwt.decode()` verifies signature (`verify_signature=True`) and audience (`verify_aud=True`) but does not pass the `issuer=` keyword argument. The `iss` claim is only validated by pre-routing logic at lines 374–388, which compares the *unverified* `token_iss` string to configured issuer URLs. If routing has a future bug or a whitespace/trailing-slash mismatch in a configured issuer URL, a token signed by an unintended issuer's private key could pass PyJWT validation.

PyJWT's `issuer=` parameter is the cryptographically-enforced backstop that makes issuer validation independent of routing correctness.

**Fix:** Pass `issuer=expected_iss` to each `jwt.decode()` call in `_validate_with_jwks`:

```python
claims = jwt.decode(
    token,
    signing_key.key,
    algorithms=["RS256"],
    audience=client_id,
    issuer=expected_iss,        # add this
    options={"verify_signature": True, "verify_exp": True, "verify_aud": True}
)
```

---

### MEDIUM — `sub` Claim Not Validated for Presence (M22)

**File:** `lambda/create-investigation/handler.py:166`

`user_sub = claims.get('sub')` can return `None` if the JWT omits the `sub` claim. `user_sub` propagates to the `oidc_sub` ECS task tag (line 683) and EFS access point tag (line 625). If `None` reaches boto3's tag serializer, ECS stores the literal string `"None"` as the tag value — corrupting audit records and making all no-sub tasks share an identical `oidc_sub` tag.

**Fix:** Reject tokens missing `sub` immediately after line 166:

```python
user_sub = claims.get('sub')
if not user_sub:
    return response(401, {'error': 'Token missing required sub claim'})
```

---

## Lambda Execution Role — Least Privilege

### MEDIUM — Create-Investigation Lambda Has Wildcard ECS Resource

**File:** `deploy/regional/lambda-create-investigation.tf:44–55`

The `ecs-task-management` policy grants `ecs:RunTask`, `ecs:StopTask`, `ecs:ListTasks`, `ecs:DescribeTasks`, `ecs:TagResource`, `ecs:RegisterTaskDefinition`, and `ecs:DeregisterTaskDefinition` on `Resource = "*"` with no cluster condition. The reap-tasks Lambda correctly scopes equivalent permissions to `arn:aws:ecs:{region}:{account}:task/{cluster}/*` with a `StringEquals: ecs:cluster` condition.

A compromised create-investigation Lambda could stop tasks in any ECS cluster in the account or deregister task definitions from any project.

**Fix:** Mirror the reaper's pattern — add a `StringEquals: ecs:cluster` condition to RunTask, StopTask, ListTasks, and TagResource; scope DescribeTasks to the cluster task ARN prefix:

```hcl
Condition = {
  StringEquals = {
    "ecs:cluster" = aws_ecs_cluster.main.arn
  }
}
```

Note: `ecs:RegisterTaskDefinition` and `ecs:DeregisterTaskDefinition` cannot be scoped by resource ARN (AWS limitation); `iam:PassRole` is already correctly scoped to the two project roles and is the effective constraint for those actions.

---

## reap-tasks Handler — Deadline Correctness

### Behavior on Malformed or Missing Deadline Tags

The reaper is **fail-safe (permissive)** on all malformed inputs — tasks are never terminated prematurely, but may persist beyond their deadline:

| Input condition | Code path | Consequence |
|---|---|---|
| `deadline` tag absent | Lines 99–102: `if not deadline_str` → `skipped += 1` | Task runs indefinitely (by design for `task_timeout=0`) |
| `deadline` tag is `""` | Same as absent | Task runs indefinitely |
| `deadline` tag is non-ISO (`"never"`, `"none"`) | Line 132: `ValueError` caught → `skipped += 1` | Task runs indefinitely |
| `deadline` tag is valid future ISO (naive UTC) | `now > deadline` is false → `skipped += 1` | Correct |
| `deadline` tag is valid past ISO (naive UTC) | `now > deadline` is true → `ecs.stop_task()` | Correctly stopped |

**Timezone edge case (non-exploitable):** The `deadline.replace(tzinfo=None)` branch at lines 109–110 strips timezone offset without converting to UTC first — a latent bug. However, `create_investigation_task` always writes naive UTC strings via `datetime.utcnow().isoformat()`, so this branch is dead in production. Container users cannot modify task tags (`ecs:TagResource` is not in the task IAM role). This is a code hygiene issue, not a current vulnerability.

---

### HIGH — Reaper IAM Condition Exempts All No-Deadline Tasks (H5)

**File:** `deploy/regional/lambda-reap-tasks.tf:68–72`

The reaper's `ecs:StopTask` permission includes a condition:

```hcl
"ForAnyValue:StringLike" = {
  "ecs:ResourceTag/deadline" = "*"
}
```

This means the reaper IAM role is **denied** `ecs:StopTask` for any task without a `deadline` tag — not just skipped in application logic, but blocked at the IAM level. Tasks created with `task_timeout=0` never receive a deadline tag (handler.py line 694), making them permanently exempt from all reaper enforcement. An operator manually invoking the reaper cannot stop these tasks either.

The only principal that can stop a no-deadline task is one with unconditional `ecs:StopTask` — currently only the create-investigation Lambda itself.

**Fix options:**

1. **Document as intentional:** If `task_timeout=0` is a deliberate operator escape hatch, document it clearly and add a warning to the `close-investigation` runbook.
2. **Add a floor:** Reject `task_timeout=0` in Lambda input validation (currently accepted at line 108) and enforce a maximum via a `TASK_TIMEOUT_MAX` env var. Remove the IAM condition and rely solely on application-layer skip logic.
3. **Hybrid:** Keep the IAM condition but add an operator-accessible IAM policy (separate from the reaper role) with unconditional `ecs:StopTask` scoped to the project cluster.

---

## Filtered Non-Findings

The following were investigated and determined not to be exploitable vulnerabilities:

| ID | Title | Reason dismissed |
|---|---|---|
| M30 | Deadline timezone strip without UTC conversion | Dead code path — production always writes naive UTC; container users lack `ecs:TagResource` |
| M31 | `ecs:RegisterTaskDefinition` not scoped by family | `iam:PassRole` already constrains blast radius to project roles; AWS does not support resource-ARN scoping for this action |
| M32 | `abac_values[0]` not type-checked as string | boto3 raises `ParamValidationError` on non-string tag values before any ABAC tag is set; failure mode is a 500, not an auth bypass |
