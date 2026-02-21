/**
 * External Secrets Operator – IAM (Pod Identity)
 *
 * ESO needs AWS credentials to call secretsmanager:GetSecretValue (and
 * optionally ssm:GetParameter / ssm:GetParametersByPath for SSM backend).
 *
 * This file owns only the AWS resources:
 *   - IAM role with Pod Identity trust
 *   - IAM policy (Secrets Manager read)
 *   - Pod Identity association → ESO controller ServiceAccount
 *
 * The ESO Helm chart lives in gitops/apps/platform.yaml.
 * The ClusterSecretStore lives in gitops/config/monitoring/alertmanager-credentials.yaml.
 */
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import { cluster } from "../cluster/eks";

const config = new pulumi.Config();
const clusterName = config.get("clusterName") ?? "eks-platform";
const accountId = aws.getCallerIdentityOutput().accountId;
const region = aws.getRegionOutput().name;

// ---------------------------------------------------------------------------
// ESO IAM Role – Pod Identity
// ---------------------------------------------------------------------------
export const esoRole = new aws.iam.Role("external-secrets-role", {
    name: `ExternalSecretsRole-${clusterName}`,
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

new aws.eks.PodIdentityAssociation("eso-pod-identity", {
    clusterName: cluster.eksCluster.name,
    namespace: "external-secrets",
    serviceAccount: "external-secrets",         // ESO controller SA name (chart default)
    roleArn: esoRole.arn,
});

// Scoped policy – read-only access to secrets prefixed with the cluster name
const esoPolicy = new aws.iam.Policy("external-secrets-policy", {
    name: `ExternalSecretsPolicy-${clusterName}`,
    policy: pulumi.all([accountId, region]).apply(([account, reg]) => JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                // Read secrets scoped to this cluster's path
                Effect: "Allow",
                Action: [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                ],
                Resource: `arn:aws:secretsmanager:${reg}:${account}:secret:${clusterName}/*`,
            },
            {
                // List secrets so ClusterSecretStore can validate connectivity
                Effect: "Allow",
                Action: ["secretsmanager:ListSecrets"],
                Resource: "*",
            },
        ],
    })),
    tags: { ManagedBy: "Pulumi" },
});

new aws.iam.RolePolicyAttachment("external-secrets-policy-attach", {
    role: esoRole.name,
    policyArn: esoPolicy.arn,
});
