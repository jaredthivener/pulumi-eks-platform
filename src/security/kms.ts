/**
 * KMS keys for EKS data-at-rest encryption.
 *
 * Two separate keys follow least-privilege / separation-of-duties:
 *
 *  secretsKmsKey  – envelope-encrypts Kubernetes Secrets via EKS KMS provider.
 *                   Referenced directly by the cluster's encryptionConfig.
 *
 *  cwKmsKey       – encrypts the EKS control-plane CloudWatch log group.
 *                   CloudWatch Logs requires a resource-based key policy granting
 *                   the logs service principal access — it cannot reuse the secrets
 *                   key without broadening that key's policy.
 *
 * Both keys have automatic annual rotation enabled and a 30-day deletion window.
 * Both are protected from accidental Pulumi destroy (protect: true).
 */
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

const config = new pulumi.Config();
const clusterName = config.get("clusterName") ?? "eks-platform";
const region = config.get("awsRegion") ?? "us-east-1";

// ---------------------------------------------------------------------------
// Secrets encryption key
// ---------------------------------------------------------------------------
export const secretsKmsKey = new aws.kms.Key(`${clusterName}-secrets-kms`, {
    description: "EKS secrets encryption key",
    enableKeyRotation: true,
    deletionWindowInDays: 30,
    tags: { ManagedBy: "Pulumi", Environment: pulumi.getStack() },
}, { protect: true });

export const secretsKmsAlias = new aws.kms.Alias(`${clusterName}-secrets-alias`, {
    name: `alias/${clusterName}-secrets`,
    targetKeyId: secretsKmsKey.id,
});

// ---------------------------------------------------------------------------
// CloudWatch Logs encryption key
// ---------------------------------------------------------------------------
const callerIdentity = pulumi.output(aws.getCallerIdentity({}));

const cwKmsKeyPolicy = pulumi.all([callerIdentity, region]).apply(
    ([identity, reg]) => JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            // Allow the account root to administer the key
            {
                Sid: "EnableRootAccess",
                Effect: "Allow",
                Principal: { AWS: `arn:aws:iam::${identity.accountId}:root` },
                Action: "kms:*",
                Resource: "*",
            },
            // Allow CloudWatch Logs to encrypt / decrypt log data
            {
                Sid: "AllowCloudWatchLogs",
                Effect: "Allow",
                Principal: { Service: `logs.${reg}.amazonaws.com` },
                Action: [
                    "kms:Encrypt*",
                    "kms:Decrypt*",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                ],
                Resource: "*",
                Condition: {
                    ArnLike: {
                        "kms:EncryptionContext:aws:logs:arn":
                            `arn:aws:logs:${reg}:${identity.accountId}:log-group:/aws/eks/${clusterName}/cluster`,
                    },
                },
            },
        ],
    }),
);

export const cwKmsKey = new aws.kms.Key(`${clusterName}-cw-kms`, {
    description: "EKS control-plane log encryption key",
    enableKeyRotation: true,
    deletionWindowInDays: 30,
    policy: cwKmsKeyPolicy,
    tags: { ManagedBy: "Pulumi", Environment: pulumi.getStack() },
}, { protect: true });
