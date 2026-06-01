# Container Security Audit — rosa-boundary

**Audit Area 3: Container Security**
**Date**: 2026-05-20
**Commit**: 5b8a844
**Auditor**: Adversary Agent (claude-sonnet-4-6)
**Files reviewed**: `Containerfile`, `entrypoint.sh`, `skel/sre/.claude/settings.json`, `skel/sre/.claude/CLAUDE.md`, `deploy/regional/ecs.tf`, `deploy/regional/iam.tf`, `deploy/regional/lambda-create-investigation.tf`, `lambda/create-investigation/handler.py`, `.github/workflows/localstack-tests.yml`, `Makefile`, `go.mod`

---

## Executive Summary

The rosa-boundary container image has a well-structured two-phase privilege model (root for entrypoint initialization, sre user for ECS Exec sessions), but several supply chain gaps undermine the integrity of the tooling baked into the image. The official AWS CLI v2 and all seven OpenShift CLI versions are downloaded from their respective CDNs without checksum or signature verification, meaning a compromised CDN endpoint at build time would silently bake a backdoored binary into all investigation sessions. The container image itself is deployed via a mutable tag with no Terraform-enforced digest requirement, allowing a compromised CI push to the ECR repository to affect all investigations created after the push. At runtime, the `aws s3 sync` command used for audit evidence collection follows symbolic links by default; combined with the SRE's unrestricted sudo access, this creates a path to exfiltrate container environment data and sensitive filesystem content to the audit S3 bucket where the task role can read it back. The ECS task definition lacks `noNewPrivileges` and any capability drop, and the Containerfile has no `USER` directive, meaning the default container runtime user is root. When combined with the six new findings identified in this audit, the container presents a meaningful supply chain and privilege-escalation attack surface for the ephemeral investigation sessions it hosts.

---

## Findings

### Acont-1 (Medium) — Official AWS CLI Downloaded Without Checksum or Signature Verification

**Severity**: Medium
**File**: `Containerfile:32–36`
**Finding ID**: M26

The official AWS CLI v2 is fetched from `awscli.amazonaws.com` with `curl -o /tmp/awscliv2.zip` and immediately unzipped and installed. AWS publishes both a SHA256 checksum file (`awscliv2.zip.sha256`) and a PGP signature alongside every release at the same base URL. Neither is fetched or verified. A DNS hijack, BGP route injection, or compromised CDN serving the `awscli.amazonaws.com` domain during an image build would deliver a malicious archive that gets baked into every investigation container.

**Exploit scenario**: An attacker who compromises the CDN or BGP routes to `awscli.amazonaws.com` during a CI build serves a backdoored `aws` binary. The binary is installed to `/opt/aws-cli-official/v2/current/bin/aws` and registered as the high-priority (`20`) alternative. Every subsequent SRE session runs the compromised binary with task role IAM credentials, Bedrock access, and S3 write access to the audit bucket. Since the binary is the default `aws` command, the SRE's audit sync itself routes through the compromised binary.

**Recommendation**:

```dockerfile
RUN AWS_CLI_ARCH=$(cat /tmp/aws_cli_arch) && \
    curl -fSL -o /tmp/awscliv2.zip \
      "https://awscli.amazonaws.com/awscli-exe-linux-${AWS_CLI_ARCH}.zip" && \
    curl -fSL -o /tmp/awscliv2.zip.sha256 \
      "https://awscli.amazonaws.com/awscli-exe-linux-${AWS_CLI_ARCH}.zip.sha256" && \
    sha256sum -c /tmp/awscliv2.zip.sha256 && \
    unzip -q /tmp/awscliv2.zip -d /tmp && \
    /tmp/aws/install --install-dir /opt/aws-cli-official --bin-dir /usr/local/bin/aws-cli-bin && \
    rm -rf /tmp/awscliv2.zip /tmp/awscliv2.zip.sha256 /tmp/aws
```

---

### Acont-2 (Medium) — OpenShift CLI Tarballs Downloaded and Piped to tar Without Integrity Verification

**Severity**: Medium
**File**: `Containerfile:42–48`
**Finding ID**: M27

Seven OpenShift CLI versions (4.14–4.20) are downloaded from `mirror.openshift.com` and piped directly to `tar -xzf -` in a single pipeline: `curl -sL "..." | tar -xzf - -C /opt/openshift/${version} oc`. Three compounding problems:

1. No checksum verification — Red Hat publishes `sha256sum.txt` alongside each tarball.
2. The shell pipeline exit code reflects `tar`, not `curl`. A curl failure (404, TLS error, truncated response) produces a zero exit code if tar succeeds on whatever it received, so `set -e` does not catch the error.
3. `-sL` follows redirects silently — a redirect attack could send the download to an attacker-controlled server.

**Exploit scenario**: A BGP hijack of `mirror.openshift.com` during a rebuild serves malicious tarballs for all seven versions. The compromised `oc` binary is installed for every version, meaning the SRE cannot escape the compromise by selecting an alternate version via `OC_VERSION`. Since `oc` is used for ROSA cluster access, a backdoored binary can exfiltrate kubeconfig credentials, API tokens, and cluster data during investigations.

**Recommendation**:

```dockerfile
RUN OC_SUFFIX=$(cat /tmp/oc_suffix) && \
    for version in 4.14 4.15 4.16 4.17 4.18 4.19 4.20; do \
      mkdir -p /opt/openshift/${version} && \
      BASE_URL="https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-${version}" && \
      curl -fSL -o /tmp/oc-${version}.tar.gz \
        "${BASE_URL}/openshift-client-linux${OC_SUFFIX}.tar.gz" && \
      curl -fSL -o /tmp/oc-${version}.sha256 "${BASE_URL}/sha256sum.txt" && \
      grep "openshift-client-linux${OC_SUFFIX}.tar.gz" /tmp/oc-${version}.sha256 | sha256sum -c - && \
      tar -xzf /tmp/oc-${version}.tar.gz -C /opt/openshift/${version} oc && \
      chmod +x /opt/openshift/${version}/oc && \
      rm -f /tmp/oc-${version}.tar.gz /tmp/oc-${version}.sha256; \
    done
```

---

### Acont-3 (Medium) — Container Image URI Has No Digest Enforcement — Mutable Tag Allows Silent Image Substitution

**Severity**: Medium
**File**: `deploy/regional/variables.tf:29–32`, `deploy/regional/ecs.tf:96`
**Finding ID**: M28

The `container_image` Terraform variable has no validation rule requiring a `@sha256:` digest suffix. The ECS base task definition uses the variable directly, and the Lambda's `register_investigation_task_definition()` inherits it without modification. This means all per-investigation task definitions reference whatever tag is currently pointed to in ECR at the time of launch — not a pinned digest.

**Exploit scenario**: An attacker who compromises the CI pipeline pushes a modified container image to ECR with the same tag. The next SRE who runs `start-task` receives a task definition referencing the compromised image. The SRE's investigation session runs in the attacker's container, which exfiltrates IAM credentials, audit data, and kubeconfig secrets while presenting a normal-looking shell.

**Recommendation**: Add a Terraform validation requiring a digest:

```hcl
variable "container_image" {
  description = "Container image URI for rosa-boundary (must include @sha256: digest)"
  type        = string

  validation {
    condition     = can(regex("@sha256:[a-f0-9]{64}$", var.container_image))
    error_message = "container_image must be pinned to a digest (e.g., image:tag@sha256:abc123...)"
  }
}
```

In CI, capture the digest after `podman push` or `skopeo inspect` and pass it as `TF_VAR_container_image`.

---

### Acont-4 (Medium) — aws s3 sync Follows Symlinks by Default — Sensitive Files Exfiltrated via /home/sre

**Severity**: Medium
**File**: `entrypoint.sh:28–29`
**Finding ID**: M29

The audit sync function runs `aws s3 sync /home/sre "${S3_AUDIT_ESCROW}" --quiet` without `--no-follow-symlinks`. The AWS CLI `s3 sync` command follows symbolic links by default, uploading the content of the symlink target rather than the symlink itself. The entrypoint runs as root (PID 1), and the S3 sync runs as root, meaning it can follow symlinks to any root-readable file on the container filesystem. The SRE user has unrestricted sudo (M8), enabling creation of symlinks to arbitrary paths.

**Exploit scenario**:
1. SRE connects via ECS Exec and runs `ln -s /proc/1/environ /home/sre/.proc-environ`
2. Container exits or receives SIGTERM
3. Entrypoint's `sync_to_s3()` uploads the content of `/proc/1/environ` (the entrypoint's full environment) to the audit bucket
4. SRE uses task role credentials (`s3:GetObject` scoped to whole bucket per C1) to retrieve the entrypoint's environment variables

More impactful paths include symlinks to `/etc/sudoers.d/sre` or the entrypoint script itself for reconnaissance.

**Recommendation**: Add `--no-follow-symlinks` to the sync command:

```bash
aws s3 sync /home/sre "${S3_AUDIT_ESCROW}" --quiet --no-follow-symlinks \
    --exclude '.*' || echo "Warning: S3 sync failed" >&2
```

---

### Acont-5 (Low) — No USER Directive in Containerfile — Default Runtime User Is root

**Severity**: Low
**File**: `Containerfile:88` (end of file)
**Finding ID**: L20

The Containerfile has no `USER` directive. The final image default user is `root` (UID 0). ECS Exec sessions connect as `sre` because the default ECS Exec command uses `runuser -u sre -- bash`, but any invocation that does not specify this wrapper results in a root shell. The default CMD `sleep infinity` runs as root. Image scanning tools enforcing `runAsNonRoot` (OpenShift SCCs, ECR enhanced scanning with CIS checks) will flag this image.

**Recommendation**: Add `USER sre` as the final Containerfile directive. Coordinate with M8 fix (restrict sudo to `alternatives` only) so that entrypoint initialization uses `sudo alternatives --set` instead of running as root. This makes the entrypoint start as `sre`, elevating only for `alternatives` calls.

---

### Acont-6 (Low) — ECS Task Definition Missing noNewPrivileges and Capability Drop

**Severity**: Low
**File**: `deploy/regional/ecs.tf:137–139`
**Finding ID**: L21

The `rosa-boundary` container's `linuxParameters` block sets only `initProcessEnabled = true`. It does not set `dockerSecurityOptions: ["no-new-privileges"]` and does not drop any Linux capabilities. On AWS Fargate, the default capability set includes `NET_RAW` (raw socket access), `SYS_CHROOT`, `MKNOD`, `AUDIT_WRITE`, `SETPCAP`, and others. Without `noNewPrivileges`, setuid binaries installed by DNF packages (e.g., `/usr/bin/su`, `/usr/bin/newgrp`) could be used by the `sre` user to gain elevated privileges. `NET_RAW` enables port scanning and packet injection to internal VPC endpoints accessible from the Fargate task's network.

**Recommendation**:

```hcl
linuxParameters = {
  initProcessEnabled = true
  capabilities = {
    drop = ["NET_RAW", "SYS_CHROOT", "MKNOD", "AUDIT_WRITE", "SETPCAP", "FSETID"]
  }
}
dockerSecurityOptions = ["no-new-privileges"]
```

---

## Supply Chain Risk Matrix

| Artifact | Source URL | Version Pinning | Integrity Check | Verdict |
|----------|-----------|-----------------|-----------------|---------|
| Fedora base image | `registry.fedoraproject.org` | Tag only (`fedora:43`) | None (no digest) | ISSUE (L6) |
| DNF system packages | Fedora package repos | No version pins | GPG (Fedora default) | ACCEPTABLE |
| Official AWS CLI v2 | `awscli.amazonaws.com` | Latest stable (no pinned version) | None | ISSUE (M26) |
| OpenShift CLI 4.14–4.20 | `mirror.openshift.com` | Minor-version stable (`stable-4.xx`) | None | ISSUE (M27) |
| Claude Code | `claude.ai/install.sh` | No (installer decides version) | None | ISSUE (L7) |
| Container image (ECR) | ECR repository | Mutable tag | None enforced by Terraform | ISSUE (M28) |
| Go modules (CLI tool) | Go module proxy | Exact (go.sum lockfile committed) | go.sum SHA256 checksums | PASS |
| Python Lambda deps | PyPI via uv | Exact via uv.lock | uv.lock hashes | ACCEPTABLE (Lambda, not container) |

**Notes**:
- DNF uses Fedora's GPG-signed repos by default; `--nogpgcheck` is not present anywhere in the Containerfile.
- The Go CLI binary is not bundled into the container image; it is built as a workstation tool with `go.sum` verification.
- No Python packages are installed in the container.
- No third-party DNF repositories are added.

---

## Container Hardening Checklist

| Control | Verdict | File:Line Evidence |
|---------|---------|-------------------|
| Non-root runtime user (USER directive) | ISSUE | `Containerfile:88` — no USER directive; default user is root (L20) |
| `readonlyRootFilesystem` on rosa-boundary | ISSUE | `ecs.tf:137–139` — field absent on main container (L14) |
| `noNewPrivileges` | ISSUE | `ecs.tf:137–139` — `dockerSecurityOptions` not set (L21) |
| Linux capability drop | ISSUE | `ecs.tf:137–139` — no `capabilities.drop` in `linuxParameters` (L21) |
| Passwordless sudo scope | ISSUE | `Containerfile:66` — `NOPASSWD: ALL` (M8) |
| S3 sync symlink protection | ISSUE | `entrypoint.sh:28` — no `--no-follow-symlinks` (M29) |
| AWS CLI integrity verification | ISSUE | `Containerfile:32–36` — no checksum check (M26) |
| OpenShift CLI integrity verification | ISSUE | `Containerfile:42–48` — no checksum, piped to tar (M27) |
| Claude Code integrity verification | ISSUE | `Containerfile:72` — `curl \| bash` without hash check (L7) |
| Container image digest pinning | ISSUE | `variables.tf:29–32` / `ecs.tf:96` — mutable tag (M28) |
| Fedora base image digest pinning | ISSUE | `Containerfile:3` — `fedora:43` without `@sha256:` (L6) |
| No build-time secrets (ARG/ENV) | PASS | No credential ARGs or ENVs in Containerfile |
| No hardcoded AWS credentials | PASS | No `.aws/` directory, access keys, or tokens in image layers |
| Skeleton Claude Code — auto-update disabled | PASS | `skel/sre/.claude/settings.json:4` — `DISABLE_AUTOUPDATER: "1"` |
| Skeleton config — no hardcoded credentials | PASS | `settings.json` contains only mode flags; CLAUDE.md uses `[TODO]` placeholders |
| EFS transit encryption | PASS | `ecs.tf:77` — `transitEncryption = "ENABLED"` |
| EFS IAM authorization | PASS | `ecs.tf:79` — `iam = "ENABLED"` on access point |
| awsvpc network isolation | PASS | `ecs.tf:64` — `network_mode = "awsvpc"` |
| Fargate SG — no inbound rules | PASS | `ecs.tf:42–58` — security group has egress only |
| ECS Exec KMS session encryption | PASS | `ecs.tf:12` — `kms_key_id = aws_kms_key.exec_session.arn` |
| initProcessEnabled (zombie reaping) | PASS | `ecs.tf:138` — `initProcessEnabled = true` |
| Container Insights enabled | PASS | `ecs.tf:5–9` — `containerInsights = "enabled"` |
| ECS task stopTimeout | PASS | `ecs.tf:98` — `stopTimeout = 120` |
| OC_VERSION injection protection | PASS | `entrypoint.sh:50` — path-existence check prevents metacharacter injection |
| AWS_CLI injection protection | PASS | `entrypoint.sh:58–69` — `case` statement with explicit allowlist |
| ECS metadata parsing injection | PASS | `entrypoint.sh:16,109` — narrow grep/cut patterns; no eval |
| No eval or unquoted user input | PASS | `entrypoint.sh` — no `eval` calls; variables quoted in critical paths |
| S3 path injection protection | PASS | `handler.py:299` — `validate_identifier()` restricts CLUSTER_ID/INVESTIGATION_ID to `[a-zA-Z0-9_-]` |
| Execution role Secrets Manager scope | PASS | `iam.tf:99` — scoped to `${project}/*` prefix only |
| Kubeconfig via Secrets Manager | PASS | `handler.py:506–527` — kubeconfig injected via `secrets[].valueFrom`, not plaintext env var |

---

## New Items for adversary-findings.json

Six new findings appended (total: 69 findings, up from 63):

| Finding ID | Title | Severity | File |
|-----------|-------|----------|------|
| M26 | Official AWS CLI Downloaded Without Checksum or Signature Verification | medium | `Containerfile:32` |
| M27 | OpenShift CLI Tarballs Downloaded and Piped to tar Without Integrity Verification | medium | `Containerfile:42` |
| M28 | Container Image URI Has No Digest Enforcement — Mutable Tag Allows Silent Image Substitution | medium | `deploy/regional/variables.tf:29` |
| M29 | aws s3 sync Follows Symlinks by Default — Sensitive Files Can Be Exfiltrated via /home/sre | medium | `entrypoint.sh:28` |
| L20 | No USER Directive in Containerfile — Default Runtime User Is root | low | `Containerfile:88` |
| L21 | ECS Task Definition Missing noNewPrivileges and Capability Drop | low | `deploy/regional/ecs.tf:137` |
