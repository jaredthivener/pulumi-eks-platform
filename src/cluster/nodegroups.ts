/**
 * Node groups: one critical on-demand group for system workloads,
 * plus cost-optimised spot capacity for application workloads.
 *
 * OS: Bottlerocket (aws-k8s-1.x variant)
 *  Bottlerocket is a container-optimised, security-hardened Linux OS built by AWS.
 *  Key advantages over AL2023 for EKS:
 *   - Immutable root filesystem (dm-verity / SELinux enforcing)
 *   - Shell-less host: no sshd, no package manager attack surface
 *   - Atomic in-place OS updates via dual-partition A/B scheme
 *   - API-driven configuration via TOML user data (merged with EKS bootstrap)
 *   - Separate OS (/dev/xvda) and data (/dev/xvdb) partitions;
 *     we size the data partition for container images + ephemeral storage
 *
 * Bottlerocket API settings used here (settings.kubernetes.*, settings.kernel.*):
 *   - Resource reservations (system-reserved, kube-reserved)
 *   - Hard / soft eviction thresholds
 *   - Graceful node shutdown timing
 *   - Log rotation (container-log-max-size / max-files)
 *   - seccomp-default (RuntimeDefault on all pods without explicit profile)
 *   - kernel.sysctl tuning for high-throughput container workloads
 *
 * Cost-optimisation highlights (from /cost-optimization):
 *  - Spot instances for non-critical pods (up to 90% savings vs On-Demand)
 *  - x86-64 instance families in each node group (homogeneous architecture required)
 *  - Karpenter (see src/autoscaling/karpenter.ts) for just-in-time provisioning with
 *    multi-arch (Graviton + x86) NodePool support
 */
import * as fs from "fs";
import * as path from "path";
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as eks from "@pulumi/eks";
import { cluster } from "./eks";
import { vpc } from "../networking/vpc";
import { nodeRole } from "./node-iam";
export { nodeRole };

const clusterName = new pulumi.Config().get("clusterName") ?? "eks-platform";

// ---------------------------------------------------------------------------
// Bottlerocket user data (TOML, base64-encoded)
//
// EKS Managed Node Groups automatically inject the required bootstrap settings
// (cluster-name, api-server, cluster-certificate). User data provided here is
// MERGED with that generated config, so we only need additive tuning.
//
// Reference: https://bottlerocket.dev/en/os/latest/api/settings/
// ---------------------------------------------------------------------------
// Shared Bottlerocket TOML — base64-encoded for the EKS launch template.
// Edit src/cluster/bottlerocket-userdata.toml to update settings across all node groups.
const bottlerocketUserData = Buffer.from(
    fs.readFileSync(path.join(__dirname, "bottlerocket-userdata.toml"), "utf-8"),
).toString("base64");

// ---------------------------------------------------------------------------
// Security-hardened launch template (applied to all node groups)
//
// Bottlerocket partition layout:
//   /dev/xvda – OS root partition (Bottlerocket manages this; do NOT touch it
//               in the launch template or you'll conflict with dm-verity)
//   /dev/xvdb – Data partition: container images, overlayfs, ephemeral storage
//               This is where we need space; 50 GB encrypted gp3.
// ---------------------------------------------------------------------------
const launchTemplate = new aws.ec2.LaunchTemplate(`${clusterName}-lt`, {
    namePrefix: `${clusterName}-`,
    metadataOptions: {
        // Enforce IMDSv2 (prevents SSRF attacks against the metadata service)
        httpTokens: "required",
        httpPutResponseHopLimit: 1,
        httpEndpoint: "enabled",
    },
    // Disable public IPs – nodes live in private subnets
    networkInterfaces: [{ associatePublicIpAddress: "false" }],
    // /dev/xvdb is the Bottlerocket data volume (container images, logs, etc.)
    // Do NOT map /dev/xvda – Bottlerocket's dm-verity protects the OS partition.
    blockDeviceMappings: [
        {
            deviceName: "/dev/xvdb",
            ebs: {
                volumeSize: 50,
                volumeType: "gp3",
                encrypted: "true",
                deleteOnTermination: "true",
            },
        },
    ],
    // Bottlerocket TOML user data (merged by EKS with cluster bootstrap config)
    userData: bottlerocketUserData,
    tags: { ManagedBy: "Pulumi", "karpenter.sh/discovery": clusterName },
    tagSpecifications: [
        { resourceType: "instance", tags: { ManagedBy: "Pulumi" } },
        { resourceType: "volume", tags: { ManagedBy: "Pulumi" } },
    ],
});

// ---------------------------------------------------------------------------
// System node group – On-Demand, tainted for system workloads only
// Runs: CoreDNS, kube-proxy, Karpenter, ArgoCD, kube-prometheus-stack
// ---------------------------------------------------------------------------
export const systemNodeGroup = new eks.ManagedNodeGroup(`${clusterName}-system`, {
    cluster: cluster.core,
    nodeGroupName: "system",
    nodeRoleArn: nodeRole.arn,
    subnetIds: vpc.privateSubnetIds,

    // arm64 Graviton3 (m7g) — consistent architecture across both node groups.
    // m7g.xlarge provides 4 vCPU / 16 GB; m7g.large as a fallback for On-Demand
    // capacity if xlarge is constrained in the target AZ.
    instanceTypes: ["m7g.xlarge", "m7g.large"],
    // Bottlerocket: immutable OS, SELinux enforcing, no shell, A/B updates
    amiType: "BOTTLEROCKET_ARM_64",
    scalingConfig: { minSize: 3, desiredSize: 3, maxSize: 6 },

    // Taint: only system pods tolerate this node group
    taints: [
        {
            key: "node.eks.aws/nodegroup",
            value: "system",
            effect: "NO_SCHEDULE",
        },
        // Cilium bootstrap taint: prevents ANY pod from scheduling on this node
        // until the Cilium agent starts, manages the node's networking, and
        // automatically removes this taint.  See src/networking/cilium.ts.
        {
            key: "node.cilium.io/agent-not-ready",
            value: "true",
            effect: "NO_EXECUTE",
        },
    ],

    labels: {
        role: "system",
        "eks.amazonaws.com/nodegroup": "system",
    },

    launchTemplate: {
        id: launchTemplate.id,
        version: pulumi.interpolate`${launchTemplate.latestVersion}`,
    },

    tags: {
        Name: `${clusterName}-system`,
        ManagedBy: "Pulumi",
        NodeGroup: "system",
        "karpenter.sh/discovery": clusterName,
    },
});

// ---------------------------------------------------------------------------
// Application node group – Mixed On-Demand + Spot, for application workloads
// Cost-optimised: Spot brings up to 90% savings for interruptible workloads
// ---------------------------------------------------------------------------
export const appNodeGroup = new eks.ManagedNodeGroup(`${clusterName}-app`, {
    cluster: cluster.core,
    nodeGroupName: "app",
    nodeRoleArn: nodeRole.arn,
    subnetIds: vpc.privateSubnetIds,

    // arm64 Graviton3 (m7g) Spot diversity pool — multiple sizes give AWS more
    // Spot capacity to draw from while keeping a homogeneous arm64 architecture.
    // Graviton3 delivers ~25% better price-performance than x86 equivalents and
    // ~20% improvement over Graviton2.
    instanceTypes: [
        "m7g.large",    // 2 vCPU / 8 GB
        "m7g.xlarge",   // 4 vCPU / 16 GB
        "m7g.2xlarge",  // 8 vCPU / 32 GB
        "m7g.4xlarge",  // 16 vCPU / 64 GB
    ],
    // Bottlerocket: immutable OS, SELinux enforcing, no shell, A/B updates
    amiType: "BOTTLEROCKET_ARM_64",

    scalingConfig: { minSize: 2, desiredSize: 3, maxSize: 20 },

    labels: {
        role: "application",
        "eks.amazonaws.com/nodegroup": "app",
        "eks.amazonaws.com/capacityType": "SPOT",
    },

    launchTemplate: {
        id: launchTemplate.id,
        version: pulumi.interpolate`${launchTemplate.latestVersion}`,
    },

    // Cilium bootstrap taint: prevents pods scheduling until Cilium agent
    // is running and manages pod networking on this node.
    taints: [
        {
            key: "node.cilium.io/agent-not-ready",
            value: "true",
            effect: "NO_EXECUTE",
        },
    ],

    capacityType: "SPOT",

    tags: {
        Name: `${clusterName}-app`,
        ManagedBy: "Pulumi",
        NodeGroup: "app",
        "karpenter.sh/discovery": clusterName,
    },
});
