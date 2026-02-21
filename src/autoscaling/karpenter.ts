/**
 * Karpenter – AWS-side infrastructure (IAM + Pod Identity + SQS + EventBridge)
 *
 * This file owns only the AWS resources that cannot be expressed as static YAML:
 *   - IAM role + controller policy + Pod Identity association
 *   - SQS interruption queue
 *   - EventBridge rules for Spot interruption / rebalance / state-change / health
 *
 * Helm chart  → gitops/apps/karpenter.yaml               (ArgoCD, wave 2)
 * NodePool    → gitops/config/karpenter/nodepool.yaml     (ArgoCD, wave 3)
 * EC2NodeClass → gitops/config/karpenter/ec2nodeclass.yaml (ArgoCD, wave 3)
 */
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import { cluster } from "../cluster/eks";

const config = new pulumi.Config();
const clusterName = config.get("clusterName") ?? "eks-platform";
const accountId = aws.getCallerIdentityOutput().accountId;

// ---------------------------------------------------------------------------
// Karpenter IAM Role — Pod Identity (replaces IRSA)
//
// Pod Identity lets EKS inject AWS credentials via a projected token without
// any SA annotation, so the Helm chart can live in static ArgoCD YAML.
// ---------------------------------------------------------------------------
export const karpenterRole = new aws.iam.Role("karpenter-controller-role", {
    name: `KarpenterControllerRole-${clusterName}`,
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

new aws.eks.PodIdentityAssociation("karpenter-pod-identity", {
    clusterName: cluster.eksCluster.name,
    namespace: "karpenter",
    serviceAccount: "karpenter",
    roleArn: karpenterRole.arn,
});

// Karpenter controller policy – allows EC2 fleet operations
const karpenterControllerPolicy = new aws.iam.Policy("karpenter-controller-policy", {
    name: `KarpenterControllerPolicy-${clusterName}`,
    policy: accountId.apply(account => JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                Effect: "Allow",
                Action: [
                    "ec2:CreateLaunchTemplate",
                    "ec2:CreateFleet",
                    "ec2:RunInstances",
                    "ec2:CreateTags",
                    "ec2:TerminateInstances",
                    "ec2:DescribeLaunchTemplates",
                    "ec2:DescribeLaunchTemplateVersions",   // required for LT version resolution
                    "ec2:DescribeImages",                   // required for amiSelectorTerms alias resolution
                    "ec2:DescribeInstances",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeInstanceTypes",
                    "ec2:DescribeInstanceTypeOfferings",
                    "ec2:DescribeAvailabilityZones",
                    "ec2:DescribeSpotPriceHistory",
                    "ec2:DeleteLaunchTemplate",
                ],
                Resource: "*",
            },
            {
                // Karpenter v1 creates/manages instance profiles from EC2NodeClass.role
                Effect: "Allow",
                Action: [
                    "iam:CreateInstanceProfile",
                    "iam:DeleteInstanceProfile",
                    "iam:GetInstanceProfile",
                    "iam:AddRoleToInstanceProfile",
                    "iam:RemoveRoleFromInstanceProfile",
                    "iam:TagInstanceProfile",
                ],
                Resource: `arn:aws:iam::${account}:instance-profile/*`,
            },
            {
                Effect: "Allow",
                Action: ["iam:PassRole"],
                Resource: `arn:aws:iam::${account}:role/${clusterName}-node-role`,
            },
            {
                Effect: "Allow",
                Action: ["eks:DescribeCluster"],
                Resource: `arn:aws:eks:*:${account}:cluster/${clusterName}`,
            },
            {
                // Karpenter uses SQS for interruption handling
                Effect: "Allow",
                Action: [
                    "sqs:DeleteMessage",
                    "sqs:GetQueueUrl",
                    "sqs:GetQueueAttributes",
                    "sqs:ReceiveMessage",
                ],
                Resource: `arn:aws:sqs:*:${account}:${clusterName}`,
            },
        ],
    })),
    tags: { ManagedBy: "Pulumi" },
});

new aws.iam.RolePolicyAttachment("karpenter-controller-policy-attach", {
    role: karpenterRole.name,
    policyArn: karpenterControllerPolicy.arn,
});

// ---------------------------------------------------------------------------
// SQS queue for Spot interruption handling (2-minute notice → graceful drain)
// ---------------------------------------------------------------------------
export const interruptionQueue = new aws.sqs.Queue("karpenter-interruption", {
    name: clusterName,
    messageRetentionSeconds: 300,
    sqsManagedSseEnabled: true,
    tags: { ManagedBy: "Pulumi" },
});

// EventBridge rules → SQS for Spot interruption and scheduled maintenance
const eventRules = [
    { name: "spot-interruption",     source: "aws.ec2", detail: "EC2 Spot Instance Interruption Warning" },
    { name: "rebalance",             source: "aws.ec2", detail: "EC2 Instance Rebalance Recommendation" },
    { name: "state-change",          source: "aws.ec2", detail: "EC2 Instance State-change Notification" },
    { name: "scheduled-change",      source: "aws.health", detail: "AWS Health Event" },
];

eventRules.forEach(({ name, source, detail }) => {
    const rule = new aws.cloudwatch.EventRule(`karpenter-${name}`, {
        name: `Karpenter-${clusterName}-${name}`,
        eventPattern: JSON.stringify({
            source: [source],
            "detail-type": [detail],
        }),
        tags: { ManagedBy: "Pulumi" },
    });
    new aws.cloudwatch.EventTarget(`karpenter-${name}-target`, {
        rule: rule.name,
        arn: interruptionQueue.arn,
    });
});

// Allow EventBridge to write to SQS
new aws.sqs.QueuePolicy("karpenter-interruption-policy", {
    queueUrl: interruptionQueue.url,
    policy: pulumi.jsonStringify({
        Version: "2012-10-17",
        Statement: [
            {
                Effect: "Allow",
                Principal: { Service: "events.amazonaws.com" },
                Action: "sqs:SendMessage",
                Resource: interruptionQueue.arn,
            },
        ],
    }),
});

// Helm chart, NodePool, and EC2NodeClass are managed by ArgoCD.
// See gitops/apps/karpenter.yaml and gitops/config/karpenter/.
//
// Intentional end of file – all Karpenter Kubernetes resources live in git.
export {}; // make tsc treat this as a module
