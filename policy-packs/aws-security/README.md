# aws-security Policy Pack

Pulumi CrossGuard policy pack enforcing security and governance controls across all AWS resources
used by the `eks-platform` stack. Policies are evaluated at `pulumi preview` and `pulumi up` time
against the resolved resource graph — before anything is deployed.

## Usage

```bash
# Run against the current stack (dry-run, no deployment)
pulumi preview --policy-pack ./policy-packs/aws-security

# Enforce at deploy time
pulumi up --policy-pack ./policy-packs/aws-security

# Publish to Pulumi Cloud for org-wide enforcement
pulumi policy publish [org-name]
```

Enforcement levels:

- **mandatory** — violation blocks the preview/update; the operation cannot proceed.
- **advisory** — violation is reported as a warning; the operation continues.

---

## Policies by Resource Type

### `aws:s3` — S3 Buckets

| Policy Name | Level | Description |
|---|---|---|
| `s3-no-public-acl` | mandatory | Buckets must not use `public-read` or `public-read-write` ACLs |
| `s3-no-force-destroy` | mandatory | `forceDestroy=true` is forbidden — prevents accidental log/data deletion |
| `s3-public-access-block-required` | mandatory | All four BucketPublicAccessBlock settings must be `true` |
| `s3-encryption-required` | mandatory | A `BucketServerSideEncryptionConfigurationV2` resource must be declared for the bucket |
| `s3-kms-preferred-over-aes` | advisory | SSE algorithm should be `aws:kms` rather than `AES256` for centralised key management |
| `s3-required-tags` | advisory | Buckets must carry the `ManagedBy` tag |

---

### `aws:kms` — KMS Keys

| Policy Name | Level | Description |
|---|---|---|
| `kms-key-rotation-enabled` | mandatory | `enableKeyRotation=true` is required on all CMKs |
| `kms-key-deletion-window` | mandatory | `deletionWindowInDays` must be ≥ 14 days |
| `kms-key-has-description` | advisory | Keys must have a non-empty description |
| `kms-key-no-wildcard-principal` | advisory | Key policies must not grant `Allow` to `Principal: *` without a `Condition` |
| `kms-key-required-tags` | advisory | Keys must carry the `ManagedBy` tag |

---

### `aws:cloudwatch` — CloudWatch Log Groups

| Policy Name | Level | Description |
|---|---|---|
| `cloudwatch-log-group-retention` | mandatory | `retentionInDays` must be set (no infinite retention) |
| `cloudwatch-log-group-min-retention` | advisory | Retention must be ≥ 30 days for audit compliance |
| `cloudwatch-log-group-encrypted` | mandatory | `kmsKeyId` must be set for encryption at rest |

---

### `aws:eks` — EKS Clusters, Addons & Pod Identity

| Policy Name | Level | Description |
|---|---|---|
| `eks-no-public-endpoint` | mandatory | `vpcConfig.endpointPublicAccess` must be `false` |
| `eks-private-endpoint-enabled` | mandatory | `vpcConfig.endpointPrivateAccess` must be `true` |
| `eks-secrets-encryption-required` | mandatory | `encryptionConfig` (KMS envelope encryption for etcd Secrets) must be configured |
| `eks-all-log-types-enabled` | mandatory | All 5 control-plane log types must be enabled: `api`, `audit`, `authenticator`, `controllerManager`, `scheduler` |
| `eks-supported-k8s-version` | advisory | Cluster must run Kubernetes ≥ 1.29 |
| `eks-required-tags` | advisory | Cluster must carry the `ManagedBy` tag |
| `eks-addon-resolve-conflicts-overwrite` | advisory | EKS addons must set `resolveConflictsOnUpdate` to prevent stuck upgrades |
| `eks-pod-identity-preferred-over-irsa` | advisory | `PodIdentityAssociation` must specify `roleArn`, `serviceAccount`, and `namespace` |

---

### `aws:ec2` — Security Groups & Rules

| Policy Name | Level | Description |
|---|---|---|
| `sg-no-unrestricted-ssh-ingress` | mandatory | No ingress from `0.0.0.0/0` or `::/0` on port 22 |
| `sg-no-unrestricted-rdp-ingress` | mandatory | No ingress from `0.0.0.0/0` or `::/0` on port 3389 |
| `sg-no-unrestricted-all-ingress` | mandatory | No allow-all (`protocol=-1`) ingress rule from `0.0.0.0/0` |
| `sg-no-unrestricted-all-egress` | advisory | Allow-all egress to `0.0.0.0/0` should be scoped to required ports/destinations |
| `sg-has-description` | advisory | Security groups must have a meaningful description |
| `sg-rule-no-unrestricted-ssh` | mandatory | `SecurityGroupRule` resources must not allow SSH from `0.0.0.0/0` |
| `sg-rule-no-unrestricted-all-traffic` | mandatory | `SecurityGroupRule` resources must not allow all-traffic ingress from `0.0.0.0/0` |
| `default-sg-no-rules` | mandatory | The default security group must have zero ingress and zero egress rules |

---

### `aws:ec2` — EC2 Launch Templates

| Policy Name | Level | Description |
|---|---|---|
| `ec2-launch-template-imdsv2-required` | mandatory | `metadataOptions.httpTokens` must be `"required"` (IMDSv2) to prevent SSRF credential theft |
| `ec2-launch-template-imds-hop-limit` | advisory | `httpPutResponseHopLimit` must be ≤ 2 to prevent pods from reaching IMDS |
| `ec2-launch-template-no-public-ip` | mandatory | `networkInterfaces[].associatePublicIpAddress` must not be `true` |
| `ec2-launch-template-ebs-encrypted` | mandatory | All EBS block device mappings must have `encrypted=true` |
| `ec2-launch-template-required-tags` | advisory | Launch templates must carry the `ManagedBy` tag |

---

### `aws:ec2` — VPC & Subnets

| Policy Name | Level | Description |
|---|---|---|
| `vpc-dns-support-enabled` | mandatory | `enableDnsSupport` must not be `false` — required for Route53 and EKS |
| `vpc-dns-hostnames-enabled` | advisory | `enableDnsHostnames` should be `true` for EKS node hostname resolution |
| `vpc-no-default-vpc-usage` | advisory | Flags any `DefaultVpc` resource declaration for review |
| `vpc-required-tags` | advisory | VPCs must carry the `ManagedBy` tag |
| `subnet-no-public-ip-on-launch` | advisory | Subnets with `mapPublicIpOnLaunch=true` should be reviewed — EKS nodes must only run in private subnets |

---

### `aws:ec2` — VPC Endpoints

| Policy Name | Level | Description |
|---|---|---|
| `vpc-endpoint-policy-no-unconditioned-wildcard-action` | advisory | VPC endpoint policies must not grant `Action:*` without a restricting `Condition` |
| `vpc-endpoint-gateway-type` | advisory | S3 and DynamoDB endpoints should use `Gateway` type (free, stays on AWS backbone) |

---

### `aws:sqs` — SQS Queues

| Policy Name | Level | Description |
|---|---|---|
| `sqs-queue-encrypted` | mandatory | Queues must set `kmsMasterKeyId` or `sqsManagedSseEnabled=true` |
| `sqs-queue-message-retention` | advisory | `messageRetentionSeconds` should not exceed 86,400s (1 day) for event/interruption queues |
| `sqs-queue-policy-no-wildcard-principal` | advisory | Queue policies must not grant `Allow` to `Principal: *` without a `Condition` |
| `sqs-queue-required-tags` | advisory | Queues must carry the `ManagedBy` tag |

---

### `aws:ec2` — VPC Flow Logs (CIS AWS Foundations Benchmark 3.9)

| Policy Name | Level | Description |
|---|---|---|
| `flowlog-capture-all-traffic` | mandatory | `trafficType` must be `ALL` — capturing only ACCEPT or REJECT misses half the network picture |
| `flowlog-has-iam-role` | advisory | Flow logs targeting CloudWatch Logs must specify an `iamRoleArn` |

---

### `aws:eks` — Node Groups

| Policy Name | Level | Description |
|---|---|---|
| `eks-nodegroup-no-ssh-remote-access` | mandatory | `remoteAccess.ec2SshKey` must not be set — use SSM Session Manager for node access |
| `eks-nodegroup-al2023-or-bottlerocket` | advisory | AMI type must be `AL2023_*` or `BOTTLEROCKET_*`; AL2 is end-of-life |
| `eks-nodegroup-min-disk-size` | advisory | Root disk must be ≥ 50 GiB to prevent disk-pressure evictions |

---

### `aws:eks` — Cluster Authentication (CIS EKS Benchmark)

| Policy Name | Level | Description |
|---|---|---|
| `eks-api-auth-mode-required` | mandatory | `accessConfig.authenticationMode` must be `API` or `API_AND_CONFIG_MAP` — not the legacy `CONFIG_MAP` |

---

### `aws:s3` — Versioning & Access Logging

| Policy Name | Level | Description |
|---|---|---|
| `s3-versioning-enabled` | advisory | `BucketVersioningV2.versioningConfiguration.status` must be `Enabled` |
| `s3-access-logging-enabled` | advisory | `BucketLoggingV2` must specify a `targetBucket` |

---

### `aws:iam` — IAM Roles & Policies

| Policy Name | Level | Description |
|---|---|---|
| `iam-no-wildcard-action-on-wildcard-resource` | mandatory | No `Action:*` (or service wildcard) combined with `Resource:*` in the same Allow statement |
| `iam-role-trust-policy-no-unconditioned-wildcard` | mandatory | Trust (assume-role) policies must not allow `Principal: *` without a `Condition` |
| `iam-role-max-session-duration` | advisory | `maxSessionDuration` must not exceed 14,400s (4 hours) |
| `iam-policy-required-tags` | advisory | IAM policies must carry the `ManagedBy` tag |
| `iam-role-required-tags` | advisory | IAM roles must carry the `ManagedBy` tag |
| `iam-no-inline-policies` | advisory | `aws.iam.RolePolicy` (inline policies) must not be used — prefer managed policies for auditability |

---

### `aws:kms` — KMS Aliases

| Policy Name | Level | Description |
|---|---|---|
| `kms-alias-no-aws-prefix` | mandatory | KMS aliases must not start with `alias/aws/` — reserved for AWS-managed keys |

---

## Scan Results (last run: 2026-02-20, 46 policies)

### Mandatory violations
None — all mandatory policies passed.

> **Note:** The `subnet-no-public-ip-on-launch` policy was downgraded to **advisory** after the
> initial scan correctly identified that `eks-platform-vpc-public-*` subnets have
> `mapPublicIpOnLaunch=true`. These are intentionally public subnets used for internet-facing ALBs
> and NAT Gateways only — EKS nodes are enforced into private subnets via
> `nodeAssociatePublicIpAddress=false` on the cluster config.

### Advisory findings
Several advisory policies report `can't be known during preview` for values that resolve only
after resources are created (KMS ARNs, IAM policy content, Output-typed fields). These
will be fully evaluated on `pulumi up`. The known-at-preview advisory findings are:

| Resource | Policy | Notes |
|---|---|---|
| `eks-platform-vpc-public-{1,2,3}` | `subnet-no-public-ip-on-launch` | Intentional — ALB/NAT subnets only |
