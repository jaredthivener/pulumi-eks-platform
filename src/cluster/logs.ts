/**
 * EKS control-plane CloudWatch log group.
 *
 * All 5 log types are enabled on the cluster (see src/cluster/eks.ts):
 *   api, audit, authenticator, controllerManager, scheduler
 *
 * Logs are retained for 90 days and encrypted with a dedicated KMS key
 * (cwKmsKey from src/security/kms.ts) — CloudWatch Logs requires a
 * resource-based key policy that cannot be shared with the secrets key.
 */
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import { cwKmsKey } from "../security/kms";

const config = new pulumi.Config();
const clusterName = config.get("clusterName") ?? "eks-platform";

export const controlPlaneLogs = new aws.cloudwatch.LogGroup(`${clusterName}-cp-logs`, {
    name: `/aws/eks/${clusterName}/cluster`,
    retentionInDays: 90,
    kmsKeyId: cwKmsKey.arn,
    tags: { ManagedBy: "Pulumi", Environment: pulumi.getStack() },
});
