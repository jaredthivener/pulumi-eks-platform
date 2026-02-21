import * as aws from "@pulumi/aws";
import { PolicyPack, validateResourceOfType } from "@pulumi/policy";

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Parse a policy document that may arrive as a string or plain object. */
function parsePolicy(raw: unknown): { Statement: any[] } | undefined {
    if (!raw) return undefined;
    try {
        return typeof raw === "string" ? JSON.parse(raw) : (raw as any);
    } catch {
        return undefined;
    }
}

/** Return true if the given principal value is a wildcard. */
function isWildcardPrincipal(principal: unknown): boolean {
    if (principal === "*") return true;
    if (typeof principal === "object" && principal !== null) {
        return Object.values(principal as Record<string, unknown>).some(
            v => v === "*" || (Array.isArray(v) && v.includes("*")),
        );
    }
    return false;
}

// ─── Mandatory tag keys that every taggable resource must carry ──────────────
const REQUIRED_TAGS = ["ManagedBy"];

function checkRequiredTags(tags: Record<string, string> | undefined, reportViolation: (msg: string) => void): void {
    for (const key of REQUIRED_TAGS) {
        if (!tags || !tags[key]) {
            reportViolation(`Resource is missing required tag: '${key}'.`);
        }
    }
}

// ─── Policy Pack ─────────────────────────────────────────────────────────────

new PolicyPack("aws-security", {
    policies: [

        // ══════════════════════════════════════════════════════════════════════
        // S3
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "s3-no-public-acl",
            description: "S3 buckets must not use public-read or public-read-write ACLs.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.s3.Bucket, (bucket, _args, reportViolation) => {
                if (bucket.acl === "public-read" || bucket.acl === "public-read-write") {
                    reportViolation("S3 bucket ACL must not be public-read or public-read-write.");
                }
            }),
        },
        {
            name: "s3-no-force-destroy",
            description: "S3 buckets must not enable forceDestroy — prevents accidental log/data loss.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.s3.Bucket, (bucket, _args, reportViolation) => {
                if (bucket.forceDestroy === true) {
                    reportViolation("S3 bucket has forceDestroy=true. Set to false to prevent accidental data loss.");
                }
            }),
        },
        {
            name: "s3-required-tags",
            description: "S3 buckets must carry required governance tags.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.s3.Bucket, (bucket, _args, reportViolation) => {
                checkRequiredTags(bucket.tags as Record<string, string>, reportViolation);
            }),
        },
        {
            name: "s3-public-access-block-required",
            description: "Every S3 BucketPublicAccessBlock must enable all four settings.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.s3.BucketPublicAccessBlock, (block, _args, reportViolation) => {
                if (!block.blockPublicAcls)       reportViolation("blockPublicAcls must be true.");
                if (!block.blockPublicPolicy)     reportViolation("blockPublicPolicy must be true.");
                if (!block.ignorePublicAcls)      reportViolation("ignorePublicAcls must be true.");
                if (!block.restrictPublicBuckets) reportViolation("restrictPublicBuckets must be true.");
            }),
        },
        {
            name: "s3-encryption-required",
            description: "S3 buckets must have server-side encryption configured.",
            enforcementLevel: "mandatory",
            // Existence of this resource (mandatory) is the enforcement mechanism.
            validateResource: validateResourceOfType(aws.s3.BucketServerSideEncryptionConfigurationV2, (_sse, _args, _report) => {
                // No-op: presence of the resource is the check.
            }),
        },
        {
            name: "s3-kms-preferred-over-aes",
            description: "S3 SSE should use aws:kms rather than AES256 for stronger key management.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.s3.BucketServerSideEncryptionConfigurationV2, (sse, _args, reportViolation) => {
                for (const rule of sse.rules ?? []) {
                    if (rule.applyServerSideEncryptionByDefault?.sseAlgorithm === "AES256") {
                        reportViolation("SSE algorithm is AES256; prefer aws:kms for centralized key management.");
                    }
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // KMS
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "kms-key-rotation-enabled",
            description: "KMS keys must have automatic annual key rotation enabled.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.kms.Key, (key, _args, reportViolation) => {
                if (!key.enableKeyRotation) {
                    reportViolation("KMS key must set enableKeyRotation = true.");
                }
            }),
        },
        {
            name: "kms-key-deletion-window",
            description: "KMS keys must have a deletion window of at least 14 days.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.kms.Key, (key, _args, reportViolation) => {
                const window = key.deletionWindowInDays ?? 30;
                if (window < 14) {
                    reportViolation(`KMS key deletionWindowInDays=${window}; must be >= 14 to allow recovery.`);
                }
            }),
        },
        {
            name: "kms-key-has-description",
            description: "KMS keys must have a description explaining their purpose.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.kms.Key, (key, _args, reportViolation) => {
                if (!key.description || key.description.trim() === "") {
                    reportViolation("KMS key is missing a description — add one for operational clarity.");
                }
            }),
        },
        {
            name: "kms-key-required-tags",
            description: "KMS keys must carry required governance tags.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.kms.Key, (key, _args, reportViolation) => {
                checkRequiredTags(key.tags as Record<string, string>, reportViolation);
            }),
        },
        {
            name: "kms-key-no-wildcard-principal",
            description: "KMS key policies must not grant any action to a wildcard (*) principal without a condition.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.kms.Key, (key, _args, reportViolation) => {
                const doc = parsePolicy(key.policy);
                for (const stmt of doc?.Statement ?? []) {
                    if (stmt.Effect !== "Allow") continue;
                    if (isWildcardPrincipal(stmt.Principal) && !stmt.Condition) {
                        reportViolation(
                            "KMS key policy has an Allow statement with wildcard principal and no Condition — " +
                            "scope to specific principals or add a Condition.",
                        );
                    }
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // CloudWatch
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "cloudwatch-log-group-retention",
            description: "CloudWatch Log Groups must set a retention policy (never retain forever).",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.cloudwatch.LogGroup, (lg, _args, reportViolation) => {
                if (!lg.retentionInDays) {
                    reportViolation("CloudWatch Log Group must set retentionInDays to prevent unbounded storage.");
                }
            }),
        },
        {
            name: "cloudwatch-log-group-min-retention",
            description: "CloudWatch Log Groups must retain logs for at least 30 days for audit purposes.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.cloudwatch.LogGroup, (lg, _args, reportViolation) => {
                const days = lg.retentionInDays ?? 0;
                if (days > 0 && days < 30) {
                    reportViolation(`Log group retention is ${days} days — policy requires >= 30 days for audit.`);
                }
            }),
        },
        {
            name: "cloudwatch-log-group-encrypted",
            description: "CloudWatch Log Groups must be encrypted with a KMS key.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.cloudwatch.LogGroup, (lg, _args, reportViolation) => {
                if (!lg.kmsKeyId) {
                    reportViolation("CloudWatch Log Group must specify a kmsKeyId for encryption at rest.");
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // EC2 — LaunchTemplate (used by Karpenter node pools)
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "ec2-launch-template-imdsv2-required",
            description: "EC2 LaunchTemplates must require IMDSv2 (httpTokens=required) to prevent SSRF credential theft.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.LaunchTemplate, (lt, _args, reportViolation) => {
                const meta = lt.metadataOptions;
                if (!meta || meta.httpTokens !== "required") {
                    reportViolation(
                        "LaunchTemplate must set metadataOptions.httpTokens='required' (IMDSv2). " +
                        "IMDSv1 is vulnerable to SSRF attacks that can exfiltrate node IAM credentials.",
                    );
                }
            }),
        },
        {
            name: "ec2-launch-template-imds-hop-limit",
            description: "EC2 LaunchTemplates must set httpPutResponseHopLimit <= 2 to prevent container metadata exfiltration.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.ec2.LaunchTemplate, (lt, _args, reportViolation) => {
                const limit = lt.metadataOptions?.httpPutResponseHopLimit ?? 1;
                if (limit > 2) {
                    reportViolation(
                        `LaunchTemplate httpPutResponseHopLimit=${limit}. Keep <= 2 to prevent pods from reaching IMDS.`,
                    );
                }
            }),
        },
        {
            name: "ec2-launch-template-no-public-ip",
            description: "EC2 LaunchTemplates must not associate public IP addresses with instances.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.LaunchTemplate, (lt, _args, reportViolation) => {
                for (const ni of lt.networkInterfaces ?? []) {
                    if (ni.associatePublicIpAddress === "true" || (ni.associatePublicIpAddress as unknown) === true) {
                        reportViolation("LaunchTemplate must not set networkInterfaces[].associatePublicIpAddress=true.");
                    }
                }
            }),
        },
        {
            name: "ec2-launch-template-ebs-encrypted",
            description: "All EBS volumes declared in EC2 LaunchTemplates must be encrypted.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.LaunchTemplate, (lt, _args, reportViolation) => {
                for (const bdm of lt.blockDeviceMappings ?? []) {
                    if (bdm.ebs && !bdm.ebs.encrypted) {
                        reportViolation(
                            `LaunchTemplate blockDeviceMapping '${bdm.deviceName ?? "unknown"}' has ebs.encrypted != true.`,
                        );
                    }
                }
            }),
        },
        {
            name: "ec2-launch-template-data-volume-min-size",
            description:
                "EC2 LaunchTemplates that configure a data volume (/dev/xvdb) must set volumeSize >= 50 GiB. " +
                "Bottlerocket separates the OS partition (/dev/xvda, dm-verity protected) from the container " +
                "data partition (/dev/xvdb). Undersized data partitions cause disk-pressure evictions.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.ec2.LaunchTemplate, (lt, _args, reportViolation) => {
                for (const bdm of lt.blockDeviceMappings ?? []) {
                    if (!bdm.ebs) continue;
                    const size = (bdm.ebs as any).volumeSize as number | undefined;
                    if (size !== undefined && size < 50) {
                        reportViolation(
                            `LaunchTemplate blockDeviceMapping '${bdm.deviceName ?? "unknown"}' ` +
                            `has volumeSize=${size} GiB (< 50 GiB minimum). ` +
                            "Increase the data partition to avoid disk-pressure node evictions.",
                        );
                    }
                }
            }),
        },
        {
            name: "ec2-launch-template-required-tags",
            description: "EC2 LaunchTemplates must carry required governance tags.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.ec2.LaunchTemplate, (lt, _args, reportViolation) => {
                checkRequiredTags(lt.tags as Record<string, string>, reportViolation);
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // VPC / Networking
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "vpc-endpoint-policy-no-unconditioned-wildcard-action",
            description: "VPC endpoint policies must not grant Action:* without a restricting Condition.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.ec2.VpcEndpoint, (endpoint, _args, reportViolation) => {
                const doc = parsePolicy(endpoint.policy);
                for (const stmt of doc?.Statement ?? []) {
                    if (stmt.Effect !== "Allow") continue;
                    const actions: string[] = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action ?? ""];
                    const hasWildcardAction = actions.some((a: string) => a === "*");
                    if (hasWildcardAction && !stmt.Condition) {
                        reportViolation(
                            "VPC endpoint policy grants Action='*' with no Condition — restrict to required actions.",
                        );
                    }
                }
            }),
        },
        {
            name: "vpc-endpoint-gateway-type",
            description: "S3/DynamoDB VPC endpoints should use Gateway type (free, stays on AWS backbone).",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.ec2.VpcEndpoint, (endpoint, _args, reportViolation) => {
                const svc = endpoint.serviceName ?? "";
                const isS3OrDdb = svc.includes(".s3") || svc.includes(".dynamodb");
                if (isS3OrDdb && endpoint.vpcEndpointType !== "Gateway") {
                    reportViolation(
                        `VPC endpoint for '${svc}' uses type '${endpoint.vpcEndpointType}' — use 'Gateway' (free).`,
                    );
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // SQS
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "sqs-queue-encrypted",
            description: "SQS queues must be encrypted — either with a CMK or SQS-managed SSE.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.sqs.Queue, (queue, _args, reportViolation) => {
                if (!queue.kmsMasterKeyId && !queue.sqsManagedSseEnabled) {
                    reportViolation("SQS queue must specify kmsMasterKeyId or set sqsManagedSseEnabled=true.");
                }
            }),
        },
        {
            name: "sqs-queue-message-retention",
            description: "SQS queue message retention must be set and not exceed 1 hour for interruption queues (security hygiene).",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.sqs.Queue, (queue, _args, reportViolation) => {
                const retention = queue.messageRetentionSeconds ?? 345600; // AWS default = 4 days
                if (retention > 86400) {
                    reportViolation(
                        `SQS queue messageRetentionSeconds=${retention} (>${86400}s/1 day). ` +
                        "Interruption/event queues should retain messages briefly.",
                    );
                }
            }),
        },
        {
            name: "sqs-queue-policy-no-wildcard-principal",
            description: "SQS queue policies must not grant permissions to wildcard (*) principal without a Condition.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.sqs.QueuePolicy, (qp, _args, reportViolation) => {
                const doc = parsePolicy(qp.policy);
                for (const stmt of doc?.Statement ?? []) {
                    if (stmt.Effect !== "Allow") continue;
                    if (isWildcardPrincipal(stmt.Principal) && !stmt.Condition) {
                        reportViolation(
                            "SQS queue policy grants Allow to wildcard principal with no Condition — " +
                            "scope to a specific service or add an aws:SourceArn condition.",
                        );
                    }
                }
            }),
        },
        {
            name: "sqs-queue-required-tags",
            description: "SQS queues must carry required governance tags.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.sqs.Queue, (queue, _args, reportViolation) => {
                checkRequiredTags(queue.tags as Record<string, string>, reportViolation);
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // IAM
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "iam-no-wildcard-action-on-wildcard-resource",
            description: "IAM policies must not grant wildcard action (*) on wildcard resource (*) in the same statement.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.iam.Policy, (policy, _args, reportViolation) => {
                const doc = parsePolicy(policy.policy);
                for (const stmt of doc?.Statement ?? []) {
                    if (stmt.Effect !== "Allow") continue;
                    const resources: string[] = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource ?? ""];
                    const actions: string[]   = Array.isArray(stmt.Action)   ? stmt.Action   : [stmt.Action ?? ""];
                    const isAdminAction = actions.some((a: string) => a === "*" || a.endsWith(":*"));
                    if (isAdminAction && resources.includes("*")) {
                        reportViolation(
                            `IAM policy grants '${JSON.stringify(actions)}' on '*' — restrict Resource to specific ARNs.`,
                        );
                    }
                }
            }),
        },
        {
            name: "iam-policy-required-tags",
            description: "IAM policies must carry required governance tags.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.iam.Policy, (policy, _args, reportViolation) => {
                checkRequiredTags(policy.tags as Record<string, string>, reportViolation);
            }),
        },
        {
            name: "iam-role-trust-policy-no-unconditioned-wildcard",
            description: "IAM role trust (assume-role) policies must not allow wildcard (*) principal without a Condition.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.iam.Role, (role, _args, reportViolation) => {
                const doc = parsePolicy(role.assumeRolePolicy);
                for (const stmt of doc?.Statement ?? []) {
                    if (stmt.Effect !== "Allow") continue;
                    if (isWildcardPrincipal(stmt.Principal) && !stmt.Condition) {
                        reportViolation(
                            "IAM role trust policy allows '*' principal with no Condition — " +
                            "scope to specific services or add a Condition to prevent privilege escalation.",
                        );
                    }
                }
            }),
        },
        {
            name: "iam-role-max-session-duration",
            description: "IAM role max session duration must not exceed 4 hours (14400s) to limit exposure from token theft.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.iam.Role, (role, _args, reportViolation) => {
                const duration = role.maxSessionDuration ?? 3600;
                if (duration > 14400) {
                    reportViolation(
                        `IAM role maxSessionDuration=${duration}s exceeds 4 hours — reduce to limit blast radius of stolen tokens.`,
                    );
                }
            }),
        },
        {
            name: "iam-role-required-tags",
            description: "IAM roles must carry required governance tags.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.iam.Role, (role, _args, reportViolation) => {
                checkRequiredTags(role.tags as Record<string, string>, reportViolation);
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // EKS
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "eks-no-public-endpoint",
            description: "EKS cluster API server endpoint must not be publicly accessible.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.eks.Cluster, (cluster, _args, reportViolation) => {
                if (cluster.vpcConfig?.endpointPublicAccess !== false) {
                    reportViolation(
                        "EKS cluster vpcConfig.endpointPublicAccess must be false. " +
                        "A public endpoint exposes the Kubernetes API to the internet.",
                    );
                }
            }),
        },
        {
            name: "eks-private-endpoint-enabled",
            description: "EKS cluster must enable private endpoint access so nodes can reach the API server.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.eks.Cluster, (cluster, _args, reportViolation) => {
                if (cluster.vpcConfig?.endpointPrivateAccess !== true) {
                    reportViolation(
                        "EKS cluster vpcConfig.endpointPrivateAccess must be true — " +
                        "without it, nodes cannot reach the API server when the public endpoint is disabled.",
                    );
                }
            }),
        },
        {
            name: "eks-secrets-encryption-required",
            description: "EKS cluster must configure KMS envelope encryption for Kubernetes Secrets.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.eks.Cluster, (cluster, _args, reportViolation) => {
                if (!cluster.encryptionConfig) {
                    reportViolation(
                        "EKS cluster must set encryptionConfig with a KMS key for etcd Secrets encryption. " +
                        "Without this, Secrets are stored in plaintext in etcd.",
                    );
                }
            }),
        },
        {
            name: "eks-all-log-types-enabled",
            description: "EKS cluster must enable all 5 control-plane log types for full audit coverage.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.eks.Cluster, (cluster, _args, reportViolation) => {
                const required = ["api", "audit", "authenticator", "controllerManager", "scheduler"];
                const enabled = (cluster.enabledClusterLogTypes ?? []) as string[];
                const missing = required.filter(t => !enabled.includes(t));
                if (missing.length > 0) {
                    reportViolation(
                        `EKS cluster is missing control-plane log types: ${missing.join(", ")}. ` +
                        "All 5 types (api, audit, authenticator, controllerManager, scheduler) are required.",
                    );
                }
            }),
        },
        {
            name: "eks-supported-k8s-version",
            description: "EKS cluster must run a supported Kubernetes version (>= 1.29).",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.eks.Cluster, (cluster, _args, reportViolation) => {
                const version = cluster.version ?? "0";
                const [major, minor] = version.split(".").map(Number);
                if (major < 1 || (major === 1 && minor < 29)) {
                    reportViolation(
                        `EKS cluster version ${version} is end-of-life or near EOL. Upgrade to >= 1.29.`,
                    );
                }
            }),
        },
        {
            name: "eks-required-tags",
            description: "EKS clusters must carry required governance tags.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.eks.Cluster, (cluster, _args, reportViolation) => {
                checkRequiredTags(cluster.tags as Record<string, string>, reportViolation);
            }),
        },
        {
            name: "eks-addon-resolve-conflicts-overwrite",
            description: "EKS addons should set resolveConflictsOnUpdate='OVERWRITE' to prevent stuck upgrades.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.eks.Addon, (addon, _args, reportViolation) => {
                if (!addon.resolveConflictsOnUpdate) {
                    reportViolation(
                        "EKS addon should set resolveConflictsOnUpdate='OVERWRITE' or 'PRESERVE' to handle " +
                        "config drift between addon updates.",
                    );
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // EC2 — Security Groups
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "sg-no-unrestricted-ssh-ingress",
            description: "Security groups must not allow unrestricted ingress on port 22 (SSH).",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.SecurityGroup, (sg, _args, reportViolation) => {
                for (const rule of sg.ingress ?? []) {
                    const cidrOpen = (rule.cidrBlocks ?? []).includes("0.0.0.0/0") ||
                                     (rule.ipv6CidrBlocks ?? []).includes("::/0");
                    const coversPort22 = rule.fromPort <= 22 && rule.toPort >= 22;
                    if (cidrOpen && coversPort22) {
                        reportViolation("Security group allows unrestricted ingress on port 22 (SSH). Restrict to known CIDRs.");
                    }
                }
            }),
        },
        {
            name: "sg-no-unrestricted-rdp-ingress",
            description: "Security groups must not allow unrestricted ingress on port 3389 (RDP).",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.SecurityGroup, (sg, _args, reportViolation) => {
                for (const rule of sg.ingress ?? []) {
                    const cidrOpen = (rule.cidrBlocks ?? []).includes("0.0.0.0/0") ||
                                     (rule.ipv6CidrBlocks ?? []).includes("::/0");
                    const coversPort3389 = rule.fromPort <= 3389 && rule.toPort >= 3389;
                    if (cidrOpen && coversPort3389) {
                        reportViolation("Security group allows unrestricted ingress on port 3389 (RDP). Restrict to known CIDRs.");
                    }
                }
            }),
        },
        {
            name: "sg-no-unrestricted-all-ingress",
            description: "Security groups must not allow all traffic (-1) from 0.0.0.0/0 on ingress.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.SecurityGroup, (sg, _args, reportViolation) => {
                for (const rule of sg.ingress ?? []) {
                    const cidrOpen = (rule.cidrBlocks ?? []).includes("0.0.0.0/0") ||
                                     (rule.ipv6CidrBlocks ?? []).includes("::/0");
                    const allPorts = rule.fromPort === 0 && rule.toPort === 0 && rule.protocol === "-1";
                    if (cidrOpen && allPorts) {
                        reportViolation("Security group has an allow-all ingress rule from 0.0.0.0/0. Use specific port ranges and sources.");
                    }
                }
            }),
        },
        {
            name: "sg-no-unrestricted-all-egress",
            description: "Security groups should not permit all outbound traffic — scope egress to required destinations.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.ec2.SecurityGroup, (sg, _args, reportViolation) => {
                for (const rule of sg.egress ?? []) {
                    const cidrOpen = (rule.cidrBlocks ?? []).includes("0.0.0.0/0") ||
                                     (rule.ipv6CidrBlocks ?? []).includes("::/0");
                    const allPorts = rule.fromPort === 0 && rule.toPort === 0 && rule.protocol === "-1";
                    if (cidrOpen && allPorts) {
                        reportViolation(
                            "Security group allows all egress to 0.0.0.0/0. " +
                            "Consider restricting to required ports/destinations to limit blast radius.",
                        );
                    }
                }
            }),
        },
        {
            name: "sg-has-description",
            description: "Security groups must have a meaningful description (not the AWS default).",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.ec2.SecurityGroup, (sg, _args, reportViolation) => {
                const desc = sg.description ?? "";
                if (!desc || desc === "Managed by Terraform" || desc === "") {
                    reportViolation("Security group must have a meaningful description explaining its purpose.");
                }
            }),
        },
        {
            name: "sg-rule-no-unrestricted-ssh",
            description: "SecurityGroupRule resources must not allow unrestricted ingress on port 22.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.SecurityGroupRule, (rule, _args, reportViolation) => {
                if (rule.type !== "ingress") return;
                const cidrOpen = (rule.cidrBlocks ?? []).includes("0.0.0.0/0") ||
                                 (rule.ipv6CidrBlocks ?? []).includes("::/0");
                const coversPort22 = (rule.fromPort ?? 0) <= 22 && (rule.toPort ?? 0) >= 22;
                if (cidrOpen && coversPort22) {
                    reportViolation("SecurityGroupRule allows unrestricted SSH ingress from 0.0.0.0/0 — restrict the source CIDR.");
                }
            }),
        },
        {
            name: "sg-rule-no-unrestricted-all-traffic",
            description: "SecurityGroupRule resources must not allow all traffic from 0.0.0.0/0 on ingress.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.SecurityGroupRule, (rule, _args, reportViolation) => {
                if (rule.type !== "ingress") return;
                const cidrOpen = (rule.cidrBlocks ?? []).includes("0.0.0.0/0") ||
                                 (rule.ipv6CidrBlocks ?? []).includes("::/0");
                const allPorts = (rule.fromPort ?? 0) === 0 && (rule.toPort ?? 0) === 0 && rule.protocol === "-1";
                if (cidrOpen && allPorts) {
                    reportViolation("SecurityGroupRule grants all-traffic ingress from 0.0.0.0/0 — specify port ranges and restrict source.");
                }
            }),
        },
        {
            name: "default-sg-no-rules",
            description: "The default security group must not allow any ingress or egress traffic.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.DefaultSecurityGroup, (sg, _args, reportViolation) => {
                if ((sg.ingress ?? []).length > 0) {
                    reportViolation("Default security group has ingress rules — remove all rules to prevent unintended access.");
                }
                if ((sg.egress ?? []).length > 0) {
                    reportViolation("Default security group has egress rules — remove all rules to prevent unintended access.");
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // VPC
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "vpc-dns-hostnames-enabled",
            description: "VPCs must enable DNS hostnames so EC2/EKS nodes can resolve hostnames within the VPC.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.ec2.Vpc, (vpc, _args, reportViolation) => {
                if (vpc.enableDnsHostnames === false) {
                    reportViolation("VPC must have enableDnsHostnames=true for EKS node registration and service discovery.");
                }
            }),
        },
        {
            name: "vpc-dns-support-enabled",
            description: "VPCs must enable DNS support (enableDnsSupport) — required for Route53 and EKS.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.Vpc, (vpc, _args, reportViolation) => {
                if (vpc.enableDnsSupport === false) {
                    reportViolation("VPC must have enableDnsSupport=true — disabling it breaks Route53 Resolver and EKS control-plane communication.");
                }
            }),
        },
        {
            name: "vpc-no-default-vpc-usage",
            description: "Do not use or modify the default VPC — workloads should run in purpose-built VPCs.",
            enforcementLevel: "advisory",
            // The presence of an aws.ec2.DefaultVpc resource means someone is managing the default VPC.
            // This advisory flags that decision for review.
            validateResource: validateResourceOfType(aws.ec2.DefaultVpc, (_vpc, _args, reportViolation) => {
                reportViolation(
                    "A DefaultVpc resource is declared. Workloads should use purpose-built VPCs, not the default VPC. " +
                    "Ensure this is intentional (e.g., locking it down) rather than using it for workloads.",
                );
            }),
        },
        {
            name: "vpc-required-tags",
            description: "VPCs must carry required governance tags.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.ec2.Vpc, (vpc, _args, reportViolation) => {
                checkRequiredTags(vpc.tags as Record<string, string>, reportViolation);
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // EC2 — Subnets
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "subnet-no-public-ip-on-launch",
            description:
                "Subnets should not auto-assign public IPs. " +
                "Public subnets used solely for ALBs/NAT Gateways may legitimately require this — " +
                "verify that EKS nodes are placed only in private subnets (nodeAssociatePublicIpAddress=false).",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.ec2.Subnet, (subnet, _args, reportViolation) => {
                if (subnet.mapPublicIpOnLaunch === true) {
                    reportViolation(
                        "Subnet has mapPublicIpOnLaunch=true. Confirm this is a public-ALB subnet only — " +
                        "EKS nodes must run in private subnets with nodeAssociatePublicIpAddress=false on the cluster.",
                    );
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // EKS — Pod Identity / IRSA — covered via IAM policies above.
        // Additional: EKS addon integrity
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "eks-pod-identity-preferred-over-irsa",
            description: "EKS PodIdentityAssociations should use the EKS Pod Identity agent (not IRSA annotations) for credential injection.",
            enforcementLevel: "advisory",
            // Validated indirectly: if a PodIdentityAssociation exists, the correct path is in use.
            // This check ensures the role ARN is set (malformed associations are caught early).
            validateResource: validateResourceOfType(aws.eks.PodIdentityAssociation, (pia, _args, reportViolation) => {
                if (!pia.roleArn) {
                    reportViolation("EKS PodIdentityAssociation must specify a roleArn.");
                }
                if (!pia.serviceAccount) {
                    reportViolation("EKS PodIdentityAssociation must specify a serviceAccount.");
                }
                if (!pia.namespace) {
                    reportViolation("EKS PodIdentityAssociation must specify a namespace.");
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // EKS — Authentication mode (CIS EKS Benchmark)
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "eks-api-auth-mode-required",
            description:
                "EKS cluster accessConfig.authenticationMode must be 'API' or 'API_AND_CONFIG_MAP'. " +
                "CONFIG_MAP-only auth uses the legacy aws-auth ConfigMap which is error-prone and " +
                "lacks the audit trail of the EKS Access Entries API.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.eks.Cluster, (cluster, _args, reportViolation) => {
                const mode = (cluster.accessConfig as any)?.authenticationMode as string | undefined;
                // undefined means AWS default (CONFIG_MAP) — flag it
                if (!mode || mode === "CONFIG_MAP") {
                    reportViolation(
                        `EKS cluster accessConfig.authenticationMode='${mode ?? "CONFIG_MAP (default)"}'. ` +
                        "Set to 'API' or 'API_AND_CONFIG_MAP' to use the Access Entries API.",
                    );
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // EKS — Node Groups (aws:eks:NodeGroup)
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "eks-nodegroup-no-ssh-remote-access",
            description:
                "EKS Node Groups must not define remoteAccess.ec2SshKey. " +
                "SSH access to nodes should be replaced by SSM Session Manager, which provides " +
                "a full audit trail without opening port 22.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.eks.NodeGroup, (ng, _args, reportViolation) => {
                if ((ng.remoteAccess as any)?.ec2SshKey) {
                    reportViolation(
                        "EKS NodeGroup has remoteAccess.ec2SshKey set — remove it and use SSM Session Manager instead.",
                    );
                }
            }),
        },
        {
            name: "eks-nodegroup-al2023-or-bottlerocket",
            description:
                "EKS Node Groups should use AL2023 or Bottlerocket AMI types. " +
                "AL2 is end-of-life. Bottlerocket provides an immutable, minimal OS with built-in " +
                "SELinux and dm-verity for node integrity.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.eks.NodeGroup, (ng, _args, reportViolation) => {
                const ami = ng.amiType ?? "";
                const approved = [
                    "AL2023_x86_64_STANDARD", "AL2023_ARM_64_STANDARD",
                    "AL2023_x86_64_NEURON", "AL2023_x86_64_NVIDIA",
                    "BOTTLEROCKET_x86_64", "BOTTLEROCKET_ARM_64",
                    "BOTTLEROCKET_x86_64_NVIDIA", "BOTTLEROCKET_ARM_64_NVIDIA",
                    "BOTTLEROCKET_x86_64_FIPS", "BOTTLEROCKET_ARM_64_FIPS",
                    // Windows not flagged — out of scope for this cluster
                ];
                if (ami && !approved.some(a => ami.startsWith(a.split("_")[0]) && (ami.includes("AL2023") || ami.includes("BOTTLEROCKET")))) {
                    reportViolation(
                        `EKS NodeGroup amiType='${ami}'. Use AL2023_* or BOTTLEROCKET_* — AL2 is end-of-life.`,
                    );
                }
            }),
        },
        {
            name: "eks-nodegroup-min-disk-size",
            description:
                "EKS Node Group root disk must be at least 50 GiB (or a launch template must be provided " +
                "that configures the data partition). Small disks cause disk-pressure evictions.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.eks.NodeGroup, (ng, _args, reportViolation) => {
                // When a launch template is attached, disk layout is fully controlled by the LT
                // (e.g. Bottlerocket /dev/xvdb data partition).  Skip the diskSize check —
                // a separate policy on aws.ec2.LaunchTemplate enforces the volume size there.
                if ((ng as any).launchTemplate) {
                    return;
                }
                const disk = ng.diskSize ?? 20; // AWS default is 20 GiB
                if (disk < 50) {
                    reportViolation(
                        `EKS NodeGroup diskSize=${disk} GiB is below the 50 GiB minimum. ` +
                        "Small disks cause OOMKill cascades when image layers and logs accumulate. " +
                        "Either set diskSize ≥ 50 or attach a launch template that configures the data volume.",
                    );
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // VPC Flow Logs (CIS AWS Foundations Benchmark 3.9)
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "flowlog-capture-all-traffic",
            description:
                "VPC Flow Logs must capture ALL traffic (trafficType='ALL'). " +
                "Capturing only ACCEPT or REJECT misses half the network picture and violates " +
                "CIS AWS Foundations Benchmark 3.9.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.ec2.FlowLog, (fl, _args, reportViolation) => {
                if (fl.trafficType && fl.trafficType !== "ALL") {
                    reportViolation(
                        `VPC FlowLog trafficType='${fl.trafficType}'. Must be 'ALL' to satisfy CIS Benchmark 3.9.`,
                    );
                }
            }),
        },
        {
            name: "flowlog-has-iam-role",
            description: "VPC Flow Logs that deliver to CloudWatch must specify an IAM role ARN.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.ec2.FlowLog, (fl, _args, reportViolation) => {
                const dest = (fl as any).logDestinationType ?? "cloud-watch-logs";
                if (dest === "cloud-watch-logs" && !fl.iamRoleArn) {
                    reportViolation(
                        "VPC FlowLog targeting CloudWatch Logs must specify iamRoleArn for the delivery role.",
                    );
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // S3 — Versioning & Access Logging
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "s3-versioning-enabled",
            description:
                "S3 buckets should have versioning enabled to protect against accidental overwrites " +
                "and enable point-in-time recovery of objects (log data, audit trails).",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.s3.BucketVersioningV2, (v, _args, reportViolation) => {
                const status = (v.versioningConfiguration as any)?.status;
                if (status && status !== "Enabled") {
                    reportViolation(
                        `S3 BucketVersioningV2 status='${status}'. Set to 'Enabled' to protect against data loss.`,
                    );
                }
            }),
        },
        {
            name: "s3-access-logging-enabled",
            description:
                "S3 buckets storing sensitive data should enable access logging " +
                "(BucketLoggingV2) to provide a full audit trail of object-level API calls.",
            enforcementLevel: "advisory",
            // Existence of a BucketLoggingV2 resource for the bucket is the enforcement.
            // This advisory fires only when a logging config omits a target bucket.
            validateResource: validateResourceOfType(aws.s3.BucketLoggingV2, (log, _args, reportViolation) => {
                if (!log.targetBucket) {
                    reportViolation(
                        "S3 BucketLoggingV2 must specify targetBucket — where access logs are delivered.",
                    );
                }
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // IAM — Inline policies (prefer managed for auditability)
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "iam-no-inline-policies",
            description:
                "Inline IAM policies (aws.iam.RolePolicy) should not be used. " +
                "Prefer managed policies (aws.iam.Policy + RolePolicyAttachment) — they appear in " +
                "IAM Access Advisor, can be version-controlled, and are visible in the console.",
            enforcementLevel: "advisory",
            validateResource: validateResourceOfType(aws.iam.RolePolicy, (_rp, _args, reportViolation) => {
                reportViolation(
                    "Inline policy (aws.iam.RolePolicy) detected. Refactor to aws.iam.Policy + " +
                    "aws.iam.RolePolicyAttachment for better auditability and reuse.",
                );
            }),
        },

        // ══════════════════════════════════════════════════════════════════════
        // KMS — Alias must not use default aws/ prefix (customer-managed only)
        // ══════════════════════════════════════════════════════════════════════
        {
            name: "kms-alias-no-aws-prefix",
            description:
                "KMS aliases must not start with 'alias/aws/' — that prefix is reserved for " +
                "AWS-managed keys. All platform keys must be customer-managed CMKs.",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.kms.Alias, (alias, _args, reportViolation) => {
                if ((alias.name ?? "").startsWith("alias/aws/")) {
                    reportViolation(
                        `KMS alias '${alias.name}' starts with 'alias/aws/' which is reserved for AWS-managed keys.`,
                    );
                }
            }),
        },
    ],
});
