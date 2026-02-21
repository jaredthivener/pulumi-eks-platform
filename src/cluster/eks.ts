import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as eks from "@pulumi/eks";
import { vpc } from "../networking/vpc";
import { secretsKmsKey } from "../security/kms";
import { controlPlaneLogs } from "./logs";
import { nodeRole } from "./node-iam";
export { vpc, secretsKmsKey, controlPlaneLogs };

const config = new pulumi.Config();
const clusterName = config.get("clusterName") ?? "eks-platform";
const k8sVersion = config.get("k8sVersion") ?? "1.35";

// ---------------------------------------------------------------------------
// EKS Cluster IAM role
// ---------------------------------------------------------------------------
const clusterRole = new aws.iam.Role(`${clusterName}-cluster-role`, {
    assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
        Service: "eks.amazonaws.com",
    }),
    tags: { ManagedBy: "Pulumi" },
});

new aws.iam.RolePolicyAttachment(`${clusterName}-cluster-policy`, {
    role: clusterRole,
    policyArn: aws.iam.ManagedPolicy.AmazonEKSClusterPolicy,
});

new aws.iam.RolePolicyAttachment(`${clusterName}-vpc-resource-controller`, {
    role: clusterRole,
    policyArn: aws.iam.ManagedPolicy.AmazonEKSVPCResourceController,
});

// ---------------------------------------------------------------------------
// EKS cluster (security hardened)
// ---------------------------------------------------------------------------
// Additional IAM roles that need cluster access can be added here via config.
const adminRoleArn = config.get("adminRoleArn");

export const cluster = new eks.Cluster(clusterName, {
    vpcId: vpc.vpcId,
    publicSubnetIds: vpc.publicSubnetIds,
    privateSubnetIds: vpc.privateSubnetIds,
    version: k8sVersion,

    // Use our explicitly-created roles (prevents @pulumi/eks from creating duplicates)
    serviceRole: clusterRole,
    instanceRole: nodeRole,

    // Disable public endpoint access; all API traffic stays private
    endpointPublicAccess: false,
    endpointPrivateAccess: true,

    // Envelope-encrypt all Secrets with our KMS key
    encryptionConfigKeyArn: secretsKmsKey.arn,

    // Control-plane logging (all 5 log types for full audit visibility)
    enabledClusterLogTypes: [
        "api",
        "audit",
        "authenticator",
        "controllerManager",
        "scheduler",
    ],

    // Nodes in private subnets only
    nodeAssociatePublicIpAddress: false,

    // Skip creating the default node group; we manage node groups explicitly
    skipDefaultNodeGroup: true,

    // Cilium replaces kube-proxy with eBPF (kubeProxyReplacement=true in cilium.ts).
    // Running both would cause a conflict — kube-proxy and Cilium both racing to
    // write iptables/eBPF rules for every Service. Disable the managed addon here.
    kubeProxyAddonOptions: { enabled: false },

    // Use IRSA (IAM Roles for Service Accounts)
    createOidcProvider: true,

    // Use the EKS Access Entries API in addition to the legacy aws-auth ConfigMap.
    // API_AND_CONFIG_MAP enables both paths during migration; switch to "API" once
    // all aws-auth entries are migrated to Access Entries.
    // Required by eks-api-auth-mode-required policy (CIS EKS Benchmark).
    authenticationMode: "API_AND_CONFIG_MAP",

    // Map additional IAM roles into aws-auth for cluster access
    // adminRoleArn is optional; if set, grants system:masters to that role
    roleMappings: adminRoleArn
        ? [{ roleArn: adminRoleArn, username: "admin", groups: ["system:masters"] }]
        : undefined,

    // Cluster tags required by Karpenter & ALB controller
    tags: {
        Name: clusterName,
        Environment: pulumi.getStack(),
        ManagedBy: "Pulumi",
        "karpenter.sh/discovery": clusterName,
    },
});

export { clusterName };
export const kubeconfig = cluster.kubeconfigJson;
export const clusterOidcProvider = cluster.core.oidcProvider;
export const clusterOidcProviderArn = pulumi.output(cluster.core.oidcProvider).apply(p => p?.arn);
export const clusterOidcIssuerUrl  = pulumi.output(cluster.core.oidcProvider).apply(p => p?.url);
