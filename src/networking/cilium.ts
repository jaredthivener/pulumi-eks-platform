/**
 * Cilium – eBPF-based CNI replacing the default AWS VPC CNI (aws-node)
 *
 * Why Cilium over aws-node / vpc-cni:
 *  - eBPF-based dataplane: lower latency, higher throughput than iptables
 *  - NetworkPolicy enforcement at L3–L7 (HTTP, gRPC-aware policies)
 *  - Built-in Hubble observability: per-flow network visibility
 *  - kube-proxy replacement (no iptables scaling bottleneck)
 *  - Native ENI IPAM on AWS: each pod gets a real VPC IP, no overlay needed
 *  - Encryption: WireGuard node-to-node at L3 with near-zero overhead
 *
 * Bootstrap sequence (important – order matters):
 *  1. EKS creates the cluster; aws-node DaemonSet is provisioned automatically
 *  2. Node groups launch with taint `node.cilium.io/agent-not-ready:NoExecute`
 *     so pods cannot schedule until Cilium is ready (see nodegroups.ts)
 *  3. This module patches aws-node to a non-matching nodeSelector → 0 running pods
 *  4. Cilium Helm chart is installed (uses ENI IPAM to manage pod IPs directly)
 *  5. Cilium agent starts on each node, removes the not-ready taint, pods schedule
 *
 * IPAM mode: ENI (recommended for EKS)
 *  - Cilium operator manages AWS ENIs and secondary IPs directly
 *  - No overlay / VXLAN tunnel: packets traverse the native VPC network
 *  - Prefix delegation enabled: each ENI can host 16 IPs vs the default 3-4
 *
 * References:
 *  - https://docs.cilium.io/en/stable/installation/k8s-install-helm/
 *  - https://docs.cilium.io/en/stable/network/concepts/ipam/eni/
 */
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as k8s from "@pulumi/kubernetes";
import { cluster, clusterOidcProviderArn, clusterOidcIssuerUrl } from "../cluster/eks";
import { systemNodeGroup, appNodeGroup } from "../cluster/nodegroups";

const config = new pulumi.Config();
const clusterName = config.get("clusterName") ?? "eks-platform";

// Shared toleration/selector for system node placement
const systemToleration = {
    key: "node.eks.aws/nodegroup",
    operator: "Equal",
    value: "system",
    effect: "NoSchedule",
};

// ---------------------------------------------------------------------------
// Step 1: Disable aws-node (VPC CNI)
//
// EKS provisions the aws-node DaemonSet automatically. We patch it to a
// nodeSelector that no node satisfies, so it runs zero Pods.  Cilium's ENI
// IPAM takes over IP allocation directly via the AWS EC2 API.
//
// Using DaemonSetPatch (strategic merge) keeps the resource in Pulumi state
// and is idempotent on repeated deploys.
// ---------------------------------------------------------------------------
export function disableAwsNode(provider: k8s.Provider): k8s.apps.v1.DaemonSetPatch {
    return new k8s.apps.v1.DaemonSetPatch("disable-aws-node", {
        metadata: {
            name: "aws-node",
            namespace: "kube-system",
            annotations: {
                // Tell Pulumi not to replace if aws-node was already patched
                "pulumi.com/patchForce": "true",
            },
        },
        spec: {
            template: {
                spec: {
                    // labelSelector that matches no node; DaemonSet runs 0 pods
                    nodeSelector: {
                        "io.cilium/aws-node-managed": "false",
                    },
                },
            },
        },
    }, {
        provider,
        // Ignore any subsequent drift that EKS tries to undo
        ignoreChanges: ["status"],
    });
}

// ---------------------------------------------------------------------------
// Step 2: IAM Role for Cilium Operator (IRSA)
//
// In ENI IPAM mode the Cilium Operator calls AWS EC2 APIs to:
//  - Enumerate VPC subnets & security groups
//  - Create, attach, and tag secondary ENIs on nodes
//  - Assign / un-assign secondary private IPv4 addresses
//
// The Cilium DaemonSet (agent) doesn't need AWS credentials; only the operator
// pod requires IRSA. We follow least-privilege: no Resource wildcards for
// destructive operations (terminate, delete) – Cilium doesn't need those.
//
// NOTE: .apply() is used ONLY to derive the assume-role policy JSON string.
// The IAM resources themselves are created at the top level (not inside apply)
// to avoid the Pulumi anti-pattern of resource creation inside callbacks.
// ---------------------------------------------------------------------------
const ciliumAssumeRolePolicy = pulumi.all([
    clusterOidcProviderArn,
    clusterOidcIssuerUrl,
]).apply(([oidcArn, oidcUrl]) => {
    if (!oidcArn || !oidcUrl) return "{}";
    const oidcProvider = oidcUrl.replace("https://", "");
    return JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Effect: "Allow",
            Principal: { Federated: oidcArn },
            Action: "sts:AssumeRoleWithWebIdentity",
            Condition: {
                StringEquals: {
                    [`${oidcProvider}:aud`]: "sts.amazonaws.com",
                    [`${oidcProvider}:sub`]: "system:serviceaccount:kube-system:cilium-operator",
                },
            },
        }],
    });
});

export const ciliumOperatorRole = new aws.iam.Role("cilium-operator-role", {
    name: `CiliumOperatorRole-${clusterName}`,
    assumeRolePolicy: ciliumAssumeRolePolicy,
    tags: { ManagedBy: "Pulumi", Component: "cilium" },
});

// ENI IPAM permissions – scoped to our VPC/cluster tags where possible
const ciliumOperatorPolicy = new aws.iam.Policy("cilium-operator-policy", {
    name: `CiliumOperatorPolicy-${clusterName}`,
    policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                Sid: "CiliumReadOnly",
                Effect: "Allow",
                Action: [
                    "ec2:DescribeInstances",
                    "ec2:DescribeInstanceTypes",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeVpcs",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:DescribeNetworkInterfaceAttribute",
                    "ec2:DescribeRouteTables",
                    "ec2:DescribeInternetGateways",
                    "ec2:DescribeAvailabilityZones",
                ],
                Resource: "*",
            },
            {
                Sid: "CiliumENIManagement",
                Effect: "Allow",
                Action: [
                    "ec2:CreateNetworkInterface",
                    "ec2:AttachNetworkInterface",
                    "ec2:DetachNetworkInterface",
                    "ec2:DeleteNetworkInterface",
                    "ec2:ModifyNetworkInterfaceAttribute",
                    "ec2:AssignPrivateIpAddresses",
                    "ec2:UnassignPrivateIpAddresses",
                ],
                Resource: "*",
                Condition: {
                    StringEquals: {
                        [`aws:ResourceTag/karpenter.sh/discovery`]: clusterName,
                    },
                },
            },
            {
                Sid: "CiliumENITagging",
                Effect: "Allow",
                Action: ["ec2:CreateTags"],
                Resource: "arn:aws:ec2:*:*:network-interface/*",
                Condition: {
                    StringEquals: {
                        "ec2:CreateAction": "CreateNetworkInterface",
                    },
                },
            },
        ],
    }),
    tags: { ManagedBy: "Pulumi" },
});

new aws.iam.RolePolicyAttachment("cilium-operator-policy-attach", {
    role: ciliumOperatorRole.name,
    policyArn: ciliumOperatorPolicy.arn,
});

// ---------------------------------------------------------------------------
// Step 3: Cilium Helm Release – eBPF CNI in ENI IPAM mode
// ---------------------------------------------------------------------------
export function deployCilium(
    provider: k8s.Provider,
    awsNodePatch: k8s.apps.v1.DaemonSetPatch,
): k8s.helm.v3.Release {
    // ciliumOperatorRole is now a top-level resource; access .arn directly.
    const operatorRoleArn = ciliumOperatorRole.arn;

    // Node group readiness is expressed via dependsOn (not via .apply wrapping)
    // to keep resource creation at the top level.
    return new k8s.helm.v3.Release("cilium", {
            name: "cilium",
            chart: "cilium",
            version: "1.19.1",
            namespace: "kube-system",
            repositoryOpts: { repo: "https://helm.cilium.io/" },
            // kube-system is created by EKS; do not recreate
            createNamespace: false,

            values: {
                // -----------------------------------------------------------------
                // ENI IPAM mode – Cilium operator manages AWS ENIs directly
                // No overlay, no VXLAN; pods get native VPC IPs.
                // -----------------------------------------------------------------
                ipam: {
                    mode: "eni",
                },
                eni: {
                    enabled: true,
                    // Prefix delegation: each ENI prefix = /28 = 16 IPs vs ~4
                    // Significantly increases pod density per node
                    awsEnablePrefixDelegation: true,
                },

                // Run in native routing (no tunnel), matching ENI mode
                routingMode: "native",

                // Mask pod-to-external traffic with the primary interface IP
                // eth0 is the primary ENI on EKS AL2023 nodes
                egressMasqueradeInterfaces: "eth0",

                // -----------------------------------------------------------------
                // kube-proxy replacement
                // Cilium handles all Service routing via eBPF; kube-proxy can be
                // left running but will be a no-op. Setting "strict" mode here
                // for maximum efficiency – if kube-proxy addon is removed later
                // this is already in place.
                // -----------------------------------------------------------------
                kubeProxyReplacement: "true",

                // Required for kube-proxy replacement: the Kubernetes API server
                // address (internal endpoint since no public access)
                k8sServiceHost: cluster.core.endpoint.apply(ep =>
                    ep.replace("https://", ""),
                ),
                k8sServicePort: "443",

                // -----------------------------------------------------------------
                // HA Operator (2 replicas on system nodes)
                // The operator holds the IRSA annotation for ENI management
                // -----------------------------------------------------------------
                operator: {
                    replicas: 2,
                    rollOutPods: true,
                    tolerations: [systemToleration],
                    nodeSelector: { role: "system" },
                    podAntiAffinity: {
                        preferredDuringSchedulingIgnoredDuringExecution: [
                            {
                                weight: 100,
                                podAffinityTerm: {
                                    labelSelector: {
                                        matchLabels: { "app.kubernetes.io/name": "cilium-operator" },
                                    },
                                    topologyKey: "topology.kubernetes.io/zone",
                                },
                            },
                        ],
                    },
                    // IRSA – annotate the cilium-operator ServiceAccount
                    serviceAccountAnnotations: {
                        "eks.amazonaws.com/role-arn": operatorRoleArn,
                    },
                    resources: {
                        requests: { cpu: "100m", memory: "128Mi" },
                        limits: { cpu: "500m", memory: "256Mi" },
                    },
                },

                // -----------------------------------------------------------------
                // Cilium Agent DaemonSet – runs on every node
                // Tolerates the not-ready taint we applied in nodegroups.ts
                // Also tolerates the system node taint (agent must run everywhere)
                // -----------------------------------------------------------------
                tolerations: [
                    // Allow onto system-tainted nodes (runs infra workloads)
                    systemToleration,
                    // Critical: allows Cilium to run before it removes this taint
                    {
                        key: "node.cilium.io/agent-not-ready",
                        operator: "Exists",
                        effect: "NoExecute",
                    },
                    // Allow scheduling on not-yet-ready nodes
                    {
                        operator: "Exists",
                        effect: "NoSchedule",
                    },
                ],

                resources: {
                    requests: { cpu: "100m", memory: "512Mi" },
                    limits: { cpu: "500m", memory: "1Gi" },
                },

                // -----------------------------------------------------------------
                // Hubble – in-cluster network observability (L3–L7 flow logs)
                // -----------------------------------------------------------------
                hubble: {
                    enabled: true,
                    relay: {
                        enabled: true,
                        replicas: 2,
                        tolerations: [systemToleration],
                        nodeSelector: { role: "system" },
                        resources: {
                            requests: { cpu: "50m", memory: "64Mi" },
                            limits: { cpu: "200m", memory: "128Mi" },
                        },
                    },
                    ui: {
                        enabled: true,
                        replicas: 1,
                        tolerations: [systemToleration],
                        nodeSelector: { role: "system" },
                    },
                    // Expose Hubble metrics to Prometheus
                    metrics: {
                        enabled: [
                            "dns",
                            "drop",
                            "tcp",
                            "flow",
                            "port-distribution",
                            "icmp",
                            "httpV2:exemplars=true;labelsContext=source_ip,source_namespace,source_workload,destination_ip,destination_namespace,destination_workload,traffic_direction",
                        ],
                        serviceMonitor: {
                            enabled: true,
                            labels: { release: "kube-prometheus-stack" },
                        },
                    },
                },

                // -----------------------------------------------------------------
                // Prometheus metrics – scraped by kube-prometheus-stack
                // -----------------------------------------------------------------
                prometheus: {
                    enabled: true,
                    serviceMonitor: {
                        enabled: true,
                        labels: { release: "kube-prometheus-stack" },
                    },
                },

                // -----------------------------------------------------------------
                // Security: encrypt node-to-node traffic with WireGuard
                // ~5% overhead, transparent to applications
                // -----------------------------------------------------------------
                encryption: {
                    enabled: true,
                    type: "wireguard",
                    nodeEncryption: true,
                },

                // -----------------------------------------------------------------
                // Mutual exclusion: tell Cilium to ignore kyverno webhook namespace
                // so policy enforcement doesn't deadlock if Kyverno is down
                // -----------------------------------------------------------------
                policyEnforcementMode: "default",
            },
        }, {
            provider,
            dependsOn: [
                awsNodePatch,
                systemNodeGroup.nodeGroup,
                appNodeGroup.nodeGroup,
            ],
        });
}
