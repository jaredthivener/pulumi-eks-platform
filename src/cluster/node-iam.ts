/**
 * IAM role for EKS node groups (shared by managed node groups + Karpenter).
 *
 * Extracted from nodegroups.ts so it can be referenced by both:
 *  - eks.ts   → passed as instanceRole to eks.Cluster (suppresses the
 *               auto-created eks:index:ServiceRole)
 *  - nodegroups.ts → attached to each ManagedNodeGroup
 *
 * Policies attached:
 *  - AmazonEKSWorkerNodePolicy          – node registration with the cluster
 *  - AmazonEKS_CNI_Policy               – Cilium/VPC CNI networking
 *  - AmazonEC2ContainerRegistryReadOnly – pull images from ECR
 *  - AmazonSSMManagedInstanceCore       – SSM Session Manager (no SSH required)
 */
import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";

const clusterName = new pulumi.Config().get("clusterName") ?? "eks-platform";

export const nodeRole = new aws.iam.Role(`${clusterName}-node-role`, {
    assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
        Service: "ec2.amazonaws.com",
    }),
    tags: { ManagedBy: "Pulumi" },
});

const nodePolicies: [string, aws.types.enums.iam.ManagedPolicy][] = [
    ["worker", aws.iam.ManagedPolicy.AmazonEKSWorkerNodePolicy],
    ["cni",    aws.iam.ManagedPolicy.AmazonEKS_CNI_Policy],
    ["ecr",    aws.iam.ManagedPolicy.AmazonEC2ContainerRegistryReadOnly],
    ["ssm",    aws.iam.ManagedPolicy.AmazonSSMManagedInstanceCore],
];

nodePolicies.forEach(([suffix, policyArn]) =>
    new aws.iam.RolePolicyAttachment(`${clusterName}-node-${suffix}`, {
        role: nodeRole,
        policyArn,
    }),
);
