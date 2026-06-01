# Tamper Resistance Audit

**Date:** 2026-06-01
**Scope:** Task tag tamper resistance, reaper Lambda edge cases, S3 sync reliability
**Branch:** `security_assessment`
**Files reviewed:**
- `entrypoint.sh`
- `lambda/reap-tasks/handler.py`
- `lambda/create-investigation/handler.py`
- `deploy/regional/iam.tf`
- `deploy/regional/lambda-reap-tasks.tf`
- `deploy/regional/ecs.tf`
- `deploy/regional/main.tf`
- `deploy/regional/kms.tf`
- `deploy/regional/efs.tf`
- `deploy/regional/s3.tf`
- `deploy/regional/oidc.tf`
- `deploy/regional/lambda-create-investigation.tf`
- `Containerfile`

Cross-reference: `adversary-findings.json` (H4, H5, M30, M8) and `docs/security/lambda-security-assessment.md`

---

## Task Tag Tamper Resistance

### Summary

The core security claim is: ECS task tags (`deadline`, `oidc_sub`, `username`) are set by the create-investigation Lambda at task launch time and cannot be modified by the container user, making the timeout deadline tamper-proof. This section evaluates that claim.

### IAM Permissions on the ECS Task Role

The task role (`aws_iam_role.task` in `iam.tf`) grants the following permissions:

| Policy | Actions |
|---|---|
| `s3-audit-access` | `s3:PutObject`, `s3:PutObjectAcl`, `s3:GetObject`, `s3:ListBucket` on audit bucket |
| `bedrock-access` | `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`, `bedrock:ListInferenceProfiles` |
| `ecs-exec-access` | `ssmmessages:CreateControlChannel`, `ssmmessages:CreateDataChannel`, `ssmmessages:OpenControlChannel`, `ssmmessages:OpenDataChannel` on `*` |
| `ssm-session-logging` | `logs:CreateLogStream`, `logs:PutLogEvents`, `logs:DescribeLogGroups`, `logs:DescribeLogStreams` on the SSM sessions log group |
| `kms-exec-session` | `kms:Decrypt`, `kms:GenerateDataKey` on the exec session KMS key |

**The task role does NOT have `ecs:TagResource`, `ecs:UntagResource`, or `ecs:StopTask`.** This means a container process running with the task role cannot modify or delete any ECS task tag via the ECS API. This is the primary tamper resistance mechanism.

### Can the Container User Reach the ECS API?

Yes — Fargate tasks have outbound internet access via NAT gateway (the Fargate security group has an unrestricted egress rule at `ecs.tf:47-52`). The ECS API is reachable from inside the container over the public internet. However, the task role's lack of `ecs:TagResource` / `ecs:UntagResource` means any `aws ecs tag-resource` or `aws ecs untag-resource` call from inside the container will receive an `AccessDeniedException`. The task role's STS credentials are what govern what API calls succeed, not network reachability.

**Verdict: The `deadline`, `oidc_sub`, and `username` ECS task tags cannot be modified from inside the container. The IAM boundary is correctly enforced.**

### Can the Container User Modify EFS Access Point Tags?

The task role does not have `elasticfilesystem:TagResource`, `elasticfilesystem:CreateAccessPoint`, `elasticfilesystem:DeleteAccessPoint`, or any EFS management action. The EFS IAM policies are exclusively on the Lambda execution role and the EFS access point's IAM authorization config.

**Verdict: EFS access point tags (`oidc_sub`, `username`, `ClusterID`, `InvestigationID`) cannot be modified by the container user.**

### Is the ABAC Tag Writable After Task Launch?

The ABAC tag (`username` or equivalent, set by the Lambda at `handler.py:684`) is applied via `ecs:TagResource` at task launch (`handler.py:739`). After that, the task role holds no `ecs:TagResource` permission. The shared SRE role (`aws_iam_role.sre_shared`) also has no `ecs:TagResource` permission — its policy covers only `ecs:ExecuteCommand`, `ecs:DescribeTasks`, `ecs:ListTasks`, `ecs:DescribeTaskDefinition`, `ssm:StartSession`, `kms:Decrypt`, and `kms:GenerateDataKey`.

**Verdict: The ABAC tag is immutable after task launch for all principals available inside the container.**

### FINDING: Authenticated SREs Can Request task_timeout=0 — No Deadline Tag Set, Reaper Cannot Act

**Severity: HIGH (pre-existing, documented as H5 in adversary-findings.json)**

Summarized here for completeness: any SRE can submit `task_timeout=0` in the create-investigation request body. The Lambda accepts it (validation at `handler.py:141-147` allows `0 <= task_timeout <= 86400`). When `task_timeout == 0`, the `deadline` tag is not added (line 694: `if task_timeout > 0`). The reaper's IAM policy (`lambda-reap-tasks.tf:68-72`) requires `ForAnyValue:StringLike: {ecs:ResourceTag/deadline: "*"}` for `ecs:StopTask`, actively blocking the reaper from stopping any no-deadline task.

This is the only functional way the timeout enforcement is bypassed from inside the SRE trust boundary. Existing-entry; see H5.

---

## Reaper Lambda Edge Cases

### Lambda Timeout Mid-Batch

The reaper Lambda has a 120-second timeout (`lambda-reap-tasks.tf:93`). The main processing loop iterates over all running tasks in batches of 100. For each batch, it calls `ecs.describe_tasks()` (one API call) then processes each task and potentially calls `ecs.stop_task()`.

**What happens when the Lambda times out mid-batch?**

When the Lambda runtime exceeds its timeout, AWS forcibly terminates the execution. The `lambda_handler` function receives no signal, no exception, and no opportunity to clean up — the process is killed at the OS level. The Lambda returns no response to the EventBridge trigger (EventBridge does not inspect the return value for schedule triggers). The Lambda will be invoked again at the next schedule interval.

**Impact:** Any tasks processed before the timeout cutoff are correctly handled (stopped if past deadline, skipped if not). Tasks in batches not yet reached continue running until the next invocation. The maximum additional dwell time is one full reaper schedule interval (default: 15 minutes, configurable 1-1440 minutes). This is not a security bypass because:

1. The Lambda processes tasks in order — not in order of deadline urgency. A cluster with 1,000 running tasks could have the Lambda time out before reaching tasks in later batches.
2. If `reaper_schedule_minutes` is set to the default 15 minutes and the Lambda processes 90 batches of 100 (9,000 tasks) but times out at batch 80, tasks in batches 81-90 are not checked until 15 minutes later. Those tasks could run up to 15 minutes past their deadline.

**FINDING: No Priority Ordering of Tasks Near Deadline**

**Severity: LOW**

The reaper iterates task ARNs in the order returned by `ecs.list_tasks()` (which is arbitrary, not deadline-ordered). At high task volumes, tasks closest to their deadline are processed in an arbitrary order. A task 1 second past its deadline could be processed after all 999 other tasks. Combined with the Lambda 120-second timeout, tasks in a high-volume cluster can overstay their deadline by up to one full schedule interval.

**Concrete failure mode:** Cluster has 1,200 running investigation tasks. The reaper processes batches 1-12 in 110 seconds (network calls, describe/stop API latency). At 120 seconds, the Lambda is killed. Batches 13-12 (tasks 1,201-1,200) are not checked. Any tasks with expired deadlines in those batches continue running for another 15 minutes. An SRE who started a 1-hour investigation that is 61 minutes old could continue working for up to 75 minutes.

**Recommendation:** Sort `task_arns` by deadline after describing the first batch, or implement pagination with a deadline-based priority queue. More practically, reduce Lambda timeout sensitivity by decreasing `reaper_schedule_minutes` to 5 minutes for high-volume environments.

---

### Reaper Lambda Timeout and `now` Timestamp Drift

The timestamp `now = datetime.utcnow()` is computed once at the start of `lambda_handler` (`handler.py:54`). Processing all batches can take seconds to minutes. A task with `deadline == now + 30s` at lambda start time will correctly not be stopped on this invocation. However, if processing takes longer than 30 seconds, that task's actual deadline passes during the Lambda execution, but the pre-computed `now` is stale and the task is skipped.

**Impact:** This is inherent to batch processing and bounded by one schedule interval (15 minutes default). It is architecturally acceptable — the deadline is a soft enforcement point, not a hard real-time cutoff. The comment in the code does not address this, but it is not a security vulnerability since the over-run is bounded.

**Verdict: Not a security finding. Documented for completeness.**

---

### What If `ecs:StopTask` Returns a Non-ClientError Exception?

The reaper's inner exception handling at `handler.py:125-127` catches only `ClientError`:

```python
except ClientError as e:
    logger.error(f"Failed to stop task {task_id}: {str(e)}")
    errors += 1
```

If `ecs.stop_task()` raises a non-ClientError exception (e.g., `botocore.exceptions.EndpointConnectionError`, `botocore.exceptions.ReadTimeoutError`, `botocore.exceptions.ConnectTimeoutError`, or a `socket.timeout`), this exception is **not caught** at the per-task level. It propagates to the outer try/except at `handler.py:56-148`, which catches `Exception` and returns an error response. Processing of the remaining tasks in the current batch — and all subsequent batches — is **aborted**.

**FINDING: Network Exception in ecs.stop_task() Aborts All Remaining Task Processing**

**Severity: MEDIUM**

**File:** `lambda/reap-tasks/handler.py`, line 117-127

**Issue:**

```python
try:
    ecs.stop_task(
        cluster=ECS_CLUSTER,
        task=task_arn,
        reason=f'Task deadline exceeded (deadline: {deadline_str})'
    )
    stopped += 1
    ...
except ClientError as e:
    logger.error(f"Failed to stop task {task_id}: {str(e)}")
    errors += 1
```

A network-level exception (`EndpointConnectionError`, `ReadTimeoutError`, `ConnectTimeoutError`) is not a `ClientError` — it is a subclass of `botocore.exceptions.BotoCoreError`. This exception propagates to the outer `except Exception as e` at line 140, which returns immediately with `{'error': 'Unexpected error during task reaping', ...}`. All unprocessed tasks (including those with expired deadlines) are skipped for this invocation.

**Impact:** A transient network connectivity issue to the ECS endpoint during a `stop_task` call causes the reaper to fail silently for all remaining tasks that invocation. Tasks past their deadline continue running for another full schedule interval. In a cluster with many expired tasks, this could cascade: the first `stop_task` call for the first expired task fails with a network error, all other expired tasks in the batch escape enforcement for 15 minutes.

**Recommendation:**

```python
try:
    ecs.stop_task(
        cluster=ECS_CLUSTER,
        task=task_arn,
        reason=f'Task deadline exceeded (deadline: {deadline_str})'
    )
    stopped += 1
    logger.info(f"Stopped task {task_id} (owner: {owner_username} / {oidc_sub})")
except Exception as e:   # Catch ALL exceptions, not just ClientError
    logger.error(f"Failed to stop task {task_id}: {str(e)}")
    errors += 1
```

Broaden the inner except to catch all exceptions, ensuring that a transient failure on one task does not abort processing of all remaining tasks.

---

### What If `ecs.describe_tasks()` Returns Tasks in a Partial/Degraded State?

When `ecs.describe_tasks()` is called, tasks may be in a state where required fields are absent (e.g., a task that is STOPPING but still returned by `list_tasks(desiredStatus='RUNNING')`). The reaper accesses `task['taskArn']` directly without a `.get()` default — if this key is missing, `KeyError` propagates to the outer except and aborts all remaining processing.

In practice, `taskArn` is always present in ECS describe_tasks responses. The `tags` field is accessed via `task.get('tags', [])` which is correctly defensive. This is a low-probability code path.

**Verdict: Not a concrete security finding but a code robustness gap. Documented.**

---

### Clock Skew Between Lambda and Task Creation Time

`now = datetime.utcnow()` inside the Lambda and `created_at = datetime.utcnow()` in the create-investigation Lambda are both naive UTC datetimes. Lambda execution environments use the Amazon Time Sync Service and maintain high clock accuracy. AWS publishes that the time sync service provides sub-millisecond accuracy across EC2/Lambda environments.

For a task created with `task_timeout=3600` (1 hour), the deadline is `created_at + 3600s`. The reaper checks `now > deadline`. If there is 1-2 seconds of clock skew between the two Lambda execution environments:

- A task with a 1-hour timeout will be stopped at most 1-2 seconds early or late. This is operationally negligible.
- No SRE action can exploit this clock skew — they cannot control which Lambda execution environment is used.

**Verdict: Clock skew is not exploitable and within acceptable operational tolerance. Not a security finding.**

---

## Container Exit and S3 Sync Reliability

### Signal Handling Analysis

The entrypoint traps `SIGTERM`, `SIGINT`, and `SIGHUP` at line 46:

```bash
trap cleanup SIGTERM SIGINT SIGHUP
```

The `cleanup()` function runs `sync_to_s3()` and then kills the background child process.

**What signals does ECS send when stopping a task?**

When ECS stops a Fargate task (whether via `ecs:StopTask`, a deadline stop, or normal task lifecycle), it sends `SIGTERM` to PID 1 and waits for `stopTimeout` seconds. The `rosa-boundary` container definition sets `stopTimeout = 120` (`ecs.tf:98`). After 120 seconds, ECS sends `SIGKILL`. The entrypoint correctly traps `SIGTERM`.

**Does the entrypoint have enough time for S3 sync?**

The `aws s3 sync /home/sre "${S3_AUDIT_ESCROW}"` call at line 28 of `sync_to_s3()` has no timeout. For large `/home/sre` directories (investigation artifacts, cluster data, must-gather output), the sync could take more than 120 seconds. After `stopTimeout = 120` seconds, ECS sends `SIGKILL` and the sync is interrupted mid-transfer.

**FINDING: S3 Sync Has No Timeout or Progress Guard — Large /home/sre Directories May Not Fully Sync Before SIGKILL**

**Severity: MEDIUM**

**File:** `entrypoint.sh`, lines 28-29

**Issue:** `aws s3 sync /home/sre "${S3_AUDIT_ESCROW}" --quiet` runs without a timeout. For an SRE who accumulates large files (downloaded cluster logs, must-gather output, container image layers) in `/home/sre`, the sync may take several minutes. ECS will send `SIGKILL` 120 seconds after `SIGTERM`, interrupting the sync mid-transfer. Partially uploaded multipart objects are not cleaned up automatically (there is no lifecycle rule for incomplete multipart uploads on the audit bucket — `s3.tf:102-119` defines only `expired_object_delete_marker` and `abort_incomplete_multipart_upload` with `days_after_initiation = 7`, which does clean this up after 7 days but still results in incomplete audit evidence).

**Impact:** An SRE with a large investigation workspace may have incomplete audit evidence in S3 even without any malicious intent. For forensic integrity, a truncated audit upload is effectively no audit upload for those files. An insider threat aware of this behavior could deliberately accumulate large files to ensure the sync never completes.

**Recommendation:**

1. Add `--no-progress` and a file size check before sync to detect and warn about large directories.
2. Implement a sidecar container or background sync loop (e.g., `while true; do aws s3 sync /home/sre "${S3_AUDIT_ESCROW}"; sleep 60; done`) that continuously syncs rather than relying on exit-time sync alone.
3. As an immediate mitigation, add `timeout 90` before the sync command to guarantee it exits before SIGKILL:

```bash
timeout 90 aws s3 sync /home/sre "${S3_AUDIT_ESCROW}" --quiet ||
    echo "Warning: S3 sync failed or timed out" >&2
```

---

### SIGKILL Cannot Be Trapped — Complete Bypass of S3 Sync

**Severity: HIGH (pre-existing, documented as H4 in adversary-findings.json)**

`SIGKILL` cannot be trapped by any signal handler in bash or any other user-space program. The entrypoint's `trap cleanup SIGTERM SIGINT SIGHUP` provides no protection against:

1. `ECS SIGKILL` after `stopTimeout` expires — the OS forcibly terminates the process with no cleanup.
2. `sudo kill -9 1` from within an SRE ECS Exec session (the SRE has `NOPASSWD: ALL` sudo, see M8).

When the entrypoint (PID 1) receives SIGKILL, the container terminates instantly. The `sync_to_s3()` function never runs. All investigation artifacts in `/home/sre` not yet synced to S3 are lost.

This is the primary S3 sync reliability gap. See H4 in `adversary-findings.json` for the full exploitation path. Not duplicated further here.

---

### Normal Exit Path — S3 Sync Does Run

At line 143-144 of `entrypoint.sh`:

```bash
sync_to_s3
exit ${EXIT_CODE}
```

This runs after `wait ${CHILD_PID}` at line 139 returns (when the background process exits normally). For the default `CMD ["sleep", "infinity"]`, the only way the child exits normally is if it is explicitly terminated, which triggers `SIGTERM` to the entrypoint from ECS (not from the child). If the child process (the command in `"${@:-sleep infinity}"`) exits with any exit code — including via a crash — the entrypoint reaches line 143 and `sync_to_s3()` runs.

**Verdict: Normal exit (including child process crash) correctly triggers S3 sync.**

---

### Can an SRE Prevent S3 Sync Without SIGKILL?

An SRE with interactive access (via ECS Exec, which connects as the `sre` user via `runuser -u sre -- bash`) has the following avenues, evaluated:

**1. Kill the entrypoint with SIGTERM:**
`kill -TERM 1` — the entrypoint's SIGTERM trap fires `cleanup()`, which runs `sync_to_s3()` and then exits. This actually triggers the sync. This approach works against the SRE's goal of bypassing sync.

**2. Kill the entrypoint with SIGKILL:**
`sudo kill -9 1` — SIGKILL cannot be trapped. Sync does not run. This is the H4 finding. Requires `NOPASSWD: ALL` sudo (M8).

**3. Modify the entrypoint script:**
The entrypoint is located at `/usr/local/bin/entrypoint.sh` on the container filesystem, which is writable (no `readonlyRootFilesystem` — see L14 in adversary-findings.json). An SRE with sudo can overwrite the entrypoint with a no-op version. However, the entrypoint is already running as PID 1 — changing the file on disk does not affect the currently executing process. Any future task launch (if the container is somehow reused, which Fargate does not do) would use the modified script, but the current session already has the original code in memory.

**4. Consume `/home/sre` with a large sparse file:**
`dd if=/dev/zero bs=1M count=50000 of=/home/sre/bigfile` — creates a 50 GB file that makes `aws s3 sync` take longer than `stopTimeout=120`, ensuring the sync is killed mid-transfer. No sudo required; the `sre` user has write access to `/home/sre`. This is a practical partial-bypass that ensures audit completeness is degraded rather than eliminated.

**5. Remove S3 environment variables:**
`unset S3_AUDIT_ESCROW S3_AUDIT_BUCKET CLUSTER_ID INVESTIGATION_ID` — unsets the S3 destination. However, these are process-level environment variables of the ECS Exec bash session, not of the entrypoint process (PID 1). The entrypoint already resolved these from the task definition at startup. The `unset` only affects the current ECS Exec shell, not the entrypoint. The sync still runs on SIGTERM/exit.

**Verdict: Without `NOPASSWD: ALL` sudo, an SRE cannot prevent S3 sync via signal manipulation. They can degrade sync completeness via large file creation (no privilege required). With sudo, SIGKILL is the clean bypass.**

---

### Is There a Race Condition Between Signal Delivery and Sync?

**Scenario:** ECS sends SIGTERM to the container. The entrypoint's `cleanup()` function starts. Simultaneously, the SRE is still writing files to `/home/sre` in their ECS Exec session.

The S3 sync runs `aws s3 sync /home/sre "${S3_AUDIT_ESCROW}"` as a point-in-time snapshot. Files written to EFS after the sync starts (but before it completes) may or may not be captured depending on how far through the directory walk the `s3 sync` has progressed. This is a fundamental limitation of sync-on-exit versus continuous sync. If the ECS Exec session continues writing after SIGTERM (the ECS Exec session is not immediately terminated when the container receives SIGTERM — it runs until the session disconnects or the container terminates), some late-written files may be missed.

**Impact:** This race window is operationally small (the ECS Exec session becomes unusable shortly after SIGTERM as the container stops accepting new exec sessions). It is not exploitable by the SRE to bypass audit, only to potentially have a few late-written files missed.

**Verdict: The race condition is real but not exploitable as an intentional bypass. Low impact.**

---

### No Retry Logic on S3 Sync Failure

If `aws s3 sync` fails (network error, credentials expired, S3 throttle), the entrypoint logs a warning and exits:

```bash
aws s3 sync /home/sre "${S3_AUDIT_ESCROW}" --quiet ||
    echo "Warning: S3 sync failed" >&2
```

There is no retry. For transient failures (momentary network interruption, S3 throttle during a large upload), the audit sync silently fails and the warning appears in CloudWatch Logs, but the task exits and the evidence is lost.

**FINDING: No Retry on S3 Sync Failure — Single Transient Error Causes Audit Loss**

**Severity: LOW**

**File:** `entrypoint.sh`, lines 28-29

**Issue:** The `aws s3 sync` command is run exactly once with no retry. A transient network error or S3 service blip causes complete audit loss for that session with only a CloudWatch warning.

**Impact:** Transient infrastructure failures at task exit time silently lose investigation artifacts. This is not exploitable by an SRE (they cannot cause S3 throttling or network disruption on demand in a controlled way), but it is a reliability gap for audit evidence preservation.

**Recommendation:** Add retry logic with exponential backoff:

```bash
sync_to_s3() {
    # ...path building logic...
    if [ -n "${S3_AUDIT_ESCROW}" ]; then
        local max_attempts=3
        local attempt=0
        while [ $attempt -lt $max_attempts ]; do
            attempt=$((attempt + 1))
            if aws s3 sync /home/sre "${S3_AUDIT_ESCROW}" --quiet --no-follow-symlinks; then
                echo "S3 sync completed (attempt ${attempt})"
                return 0
            fi
            echo "Warning: S3 sync attempt ${attempt} failed" >&2
            [ $attempt -lt $max_attempts ] && sleep $((attempt * 5))
        done
        echo "Error: S3 sync failed after ${max_attempts} attempts" >&2
    fi
}
```

Note: Given the `stopTimeout = 120` constraint, three retries with 5/10-second sleeps must complete within ~90 seconds to avoid SIGKILL.

---

### S3 Sync Follows Symlinks — Sensitive File Exfiltration

**Severity: MEDIUM (pre-existing, documented as M29 in adversary-findings.json)**

`aws s3 sync` follows symlinks by default. An SRE can create symlinks in `/home/sre` pointing to sensitive container files (e.g., `/proc/1/environ` for the entrypoint's environment variables), which are then uploaded to the audit bucket on sync. The SRE can read them back via the task role's `s3:GetObject`. This is documented in M29; not duplicated here.

---

## Non-Findings

The following items were explicitly checked and determined not to be exploitable vulnerabilities with confidence above 80%:

| Item checked | Conclusion |
|---|---|
| Can the task role call `ecs:TagResource` to modify deadline tag? | No — task role has no ECS tag actions. IAM boundary confirmed in `iam.tf`. |
| Can the task role call `ecs:UntagResource` to remove deadline tag? | No — same as above. |
| Can the task role call `ecs:StopTask` to self-terminate before sync? | No — not in task role policy. Only the reaper Lambda and create-investigation Lambda have `ecs:StopTask`. |
| Can the task role modify EFS access point tags to change ABAC values? | No — task role has no EFS management permissions. |
| Can an SRE set `preferred_username` to match another user's ABAC tag? | Tracked as M18; depends on Keycloak configuration. Out of scope for this audit. |
| Clock skew causing early task termination | Lambda execution environments use AWS Time Sync Service; sub-millisecond accuracy. 1-2 second grace period makes this non-exploitable. |
| `now = datetime.utcnow()` computed once at Lambda start causing stale comparisons | Bounded by one schedule interval (15 min default). Not a security issue. |
| `replace(tzinfo=None)` without UTC conversion in reaper (M30) | Dead code path in production — `create-investigation` always generates naive UTC deadline strings. Container users lack `ecs:TagResource`. Confirmed non-exploitable; documented in `lambda-security-assessment.md`. |
| Reaper Lambda invoked concurrently by EventBridge | EventBridge scheduled rules invoke Lambda at most once per schedule event. Concurrent duplicate invocations would double-attempt `stop_task` on the same task ARN, which is idempotent (AWS returns success for already-stopped tasks). Not a safety issue. |
| `ECS_CONTAINER_METADATA_URI_V4` in entrypoint — SSRF risk? | The metadata endpoint is only accessible from within the container network namespace. An SRE can query it directly without needing the entrypoint. No additional attack surface introduced. |
| Can an SRE unset `S3_AUDIT_ESCROW` from the entrypoint's environment? | No — environment variables in a running process cannot be modified by another process (even with root access to the same container). The ECS Exec session runs as a separate process. The entrypoint has already evaluated the variable at startup. |
| `curl` in sync_to_s3 for ECS metadata — injection via `ECS_CONTAINER_METADATA_URI_V4`? | The URI is set by ECS at task start from the task definition. It is not user-controllable. Not an injection vector. |
