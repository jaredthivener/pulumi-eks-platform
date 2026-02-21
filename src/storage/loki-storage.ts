/**
 * Loki storage – S3 bucket + IAM (Pod Identity)
 *
 * Loki's SimpleScalable deployment uses S3 for:
 *   - Chunks (raw log data)
 *   - Index (TSDB)
 *   - Ruler (alerting rules)
 *
 * The Loki Helm chart (gitops/apps/observability.yaml) uses Pod Identity to
 * assume this role — no IRSA annotation or long-lived credentials needed.
 *
 * Two-phase:
 *   1. `pulumi up` creates the bucket + IAM role + Pod Identity association
 *   2. ArgoCD installs Loki; it authenticates to S3 via the injected token
 */
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import { cluster } from "../cluster/eks";

const config = new pulumi.Config();
const clusterName = config.get("clusterName") ?? "eks-platform";
const region = aws.getRegionOutput().name;
const accountId = aws.getCallerIdentityOutput().accountId;

// ---------------------------------------------------------------------------
// S3 bucket – single bucket for all Loki backends (chunks, ruler, admin)
// ---------------------------------------------------------------------------
export const lokiBucket = new aws.s3.Bucket(`${clusterName}-loki`, {
    bucket: `${clusterName}-loki-chunks`,
    forceDestroy: false,   // prevent accidental deletion of logs
    tags: { ManagedBy: "Pulumi", Component: "loki" },
});

// Block all public access – logs are internal-only
new aws.s3.BucketPublicAccessBlock(`${clusterName}-loki-public-access-block`, {
    bucket: lokiBucket.id,
    blockPublicAcls: true,
    blockPublicPolicy: true,
    ignorePublicAcls: true,
    restrictPublicBuckets: true,
});

// Server-side encryption with KMS
const lokiKmsKey = new aws.kms.Key(`${clusterName}-loki-key`, {
    description: "KMS key for Loki S3 bucket encryption",
    enableKeyRotation: true,
    tags: { ManagedBy: "Pulumi", Component: "loki" },
});

new aws.kms.Alias(`${clusterName}-loki-key-alias`, {
    name: `alias/${clusterName}-loki`,
    targetKeyId: lokiKmsKey.id,
});

new aws.s3.BucketServerSideEncryptionConfiguration(`${clusterName}-loki-sse`, {
    bucket: lokiBucket.id,
    rules: [{
        applyServerSideEncryptionByDefault: {
            sseAlgorithm: "aws:kms",
            kmsMasterKeyId: lokiKmsKey.arn,
        },
        bucketKeyEnabled: true,
    }],
});

// Lifecycle rule – expire old chunks automatically (matches Loki 31-day retention)
new aws.s3.BucketLifecycleConfiguration(`${clusterName}-loki-lifecycle`, {
    bucket: lokiBucket.id,
    rules: [{
        id: "loki-chunks-expiry",
        status: "Enabled",
        filter: { prefix: "" },
        expiration: { days: 32 },   // 1 day grace period past Loki retention
        noncurrentVersionExpiration: { noncurrentDays: 1 },
    }],
});

// ---------------------------------------------------------------------------
// IAM role – Pod Identity trust (Loki controller SA in loki namespace)
// ---------------------------------------------------------------------------
export const lokiRole = new aws.iam.Role(`${clusterName}-loki-role`, {
    name: `LokiRole-${clusterName}`,
    assumeRolePolicy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Effect: "Allow",
            Principal: { Service: "pods.eks.amazonaws.com" },
            Action: ["sts:AssumeRole", "sts:TagSession"],
        }],
    }),
    tags: { ManagedBy: "Pulumi" },
});

const lokiPolicy = new aws.iam.Policy(`${clusterName}-loki-policy`, {
    name: `LokiPolicy-${clusterName}`,
    policy: lokiBucket.arn.apply(bucketArn => JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                // Read/write chunks and index into the bucket
                Effect: "Allow",
                Action: [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:DeleteObject",
                    "s3:GetObjectAttributes",
                ],
                Resource: `${bucketArn}/*`,
            },
            {
                // List bucket (required for compactor and TSDB index)
                Effect: "Allow",
                Action: [
                    "s3:ListBucket",
                    "s3:GetBucketLocation",
                ],
                Resource: bucketArn,
            },
        ],
    })),
    tags: { ManagedBy: "Pulumi" },
});

new aws.iam.RolePolicyAttachment(`${clusterName}-loki-policy-attach`, {
    role: lokiRole.name,
    policyArn: lokiPolicy.arn,
});

// Pod Identity association – maps loki SA → loki IAM role
// SA name "loki" matches serviceAccount.name in loki.yaml Helm values
new aws.eks.PodIdentityAssociation(`${clusterName}-loki-pod-identity`, {
    clusterName: cluster.eksCluster.name,
    namespace: "loki",
    serviceAccount: "loki",
    roleArn: lokiRole.arn,
});

export const lokiBucketName = lokiBucket.bucket;
