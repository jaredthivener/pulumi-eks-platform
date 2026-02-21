/**
 * EKS Managed Add-ons
 *
 * Managed add-ons are maintained by AWS:
 *  - Security patches applied automatically (or via Pulumi update)
 *  - Versioned independently of the cluster; pinned here for reproducibility
 *  - resolveConflictsOnUpdate: "OVERWRITE" lets AWS reconcile any config drift
 *
 * Add-ons installed:
 *  1. coredns               – Cluster-internal DNS resolution
 *  2. metrics-server        – Aggregates node/pod resource metrics for HPA & `kubectl top`
 *  3. eks-pod-identity-agent – Modern workload identity (replaces IRSA annotation
 *                              pattern for new workloads)
 *
 * NOT installed (kube-proxy): Cilium's kubeProxyReplacement=true installs eBPF
 *  programs that fully replace kube-proxy's iptables rules. Running both would
 *  be redundant and kube-proxy would lose the race on every Service update.
 *
 * NOT installed here (managed elsewhere):
 *  - vpc-cni / aws-node → replaced by Cilium ENI mode (see src/networking/cilium.ts)
 *
 * Add-on versions: omitting addonVersion lets EKS install the default (latest
 * compatible) version for the cluster's Kubernetes minor version.  Pin by
 * setting addonVersion to the output of:
 *   aws eks describe-addon-versions \
 *     --addon-name <name> \
 *     --kubernetes-version 1.35 \
 *     --query 'addons[0].addonVersions[0].addonVersion' --output text
 */
import * as aws from "@pulumi/aws";
import { cluster } from "./eks";
import { systemNodeGroup, appNodeGroup } from "./nodegroups";

// dependsOn targets – EKS add-on Pods need schedulable nodes before they
// reach Running state.  The AWS API call itself succeeds without nodes,
// but the reconciliation loop won't complete until nodes are available.
const nodeDeps = [systemNodeGroup.nodeGroup, appNodeGroup.nodeGroup];

// ---------------------------------------------------------------------------
// CoreDNS – cluster DNS
//
// Tuning rationale:
//
//  Lame duck (health.lameduck):
//    When a CoreDNS pod receives SIGTERM it enters lame-duck mode for 5s.
//    During that window every DNS query returns SERVFAIL so resolvers
//    immediately retry against a healthy replica.  Without this, in-flight
//    queries to a terminating pod silently time out (default 5s stub-resolver
//    timeout before the client retries).  Critical for zero-downtime deploys
//    and Bottlerocket node drains.
//    Ref: https://coredns.io/plugins/health/
//
//  Cache (30s positive, 5s negative):
//    Positive TTL reduces upstream query rate to kube-apiserver.
//    Negative TTL caps NXDOMAIN caching so newly created Services surface
//    quickly without blowing the cache hit rate.
//    prefetch 10 0.1 * triggers background refresh for frequently-used names
//    before TTL expiry, eliminating cold-cache latency spikes.
//
//  ready plugin:
//    Separate readiness endpoint (:8181) so the health probe doesn't compete
//    with lame-duck SERVFAIL on the liveness endpoint (:8080).
//
//  log plugin:
//    Controlled logging (errors only in prod) via the `classes` filter to
//    avoid high-cardinality log flood while still capturing NXDOMAIN / REFUSED.
//
//  Replicas & anti-affinity:
//    2 replicas minimum (3 for >=9-node clusters).  podAntiAffinity with
//    preferredDuringSchedulingIgnoredDuringExecution spreads replicas across
//    failure domains without hard-blocking scheduling on small clusters.
//
//  PodDisruptionBudget (minAvailable: 1):
//    Prevents both replicas from being drained simultaneously during node
//    upgrades or voluntary disruptions.
// ---------------------------------------------------------------------------

// Corefile – tuned for production EKS with Cilium CNI
// EKS injects `cluster.local` forwarding and ndots search path automatically
// when the addon bootstraps; we only override what needs tuning.
const coreDnsCorefile = `.:53 {
    errors
    health {
        # Lame-duck: respond SERVFAIL for 5s after SIGTERM so clients retry
        # against a healthy replica before this pod fully terminates.
        lameduck 5s
    }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    prometheus :9153
    forward . /etc/resolv.conf {
        max_concurrent 1000
    }
    cache 30 {
        # Prefetch popular names 10 queries before TTL expiry (threshold 10%
        # of average query rate) to avoid cold-cache latency spikes.
        prefetch 10 0.1 10%
        # Cap negative (NXDOMAIN) cache so new Services are visible quickly.
        denial 5
    }
    loop
    reload
    loadbalance
    # Log only error/denial classes to avoid high-cardinality flood
    log . {
        class error denial
    }
}
`;

export const coreDnsAddon = new aws.eks.Addon("coredns", {
    clusterName: cluster.eksCluster.name,
    addonName: "coredns",
    // OVERWRITE lets EKS repair config drift on upgrades
    resolveConflictsOnUpdate: "OVERWRITE",
    configurationValues: JSON.stringify({
        // ── Corefile ────────────────────────────────────────────────────────
        corefile: coreDnsCorefile,

        // ── Replicas & scheduling ────────────────────────────────────────────
        replicaCount: 2,

        // Pin to system node group (tainted node.eks.aws/nodegroup=system)
        tolerations: [
            {
                key: "node.eks.aws/nodegroup",
                operator: "Equal",
                value: "system",
                effect: "NoSchedule",
            },
        ],
        nodeSelector: { role: "system" },

        // Spread replicas across nodes so a single node drain can't take out DNS
        affinity: {
            podAntiAffinity: {
                // Preferred (not required) so small clusters still schedule
                preferredDuringSchedulingIgnoredDuringExecution: [
                    {
                        weight: 100,
                        podAffinityTerm: {
                            labelSelector: {
                                matchExpressions: [
                                    {
                                        key: "k8s-app",
                                        operator: "In",
                                        values: ["kube-dns"],
                                    },
                                ],
                            },
                            topologyKey: "kubernetes.io/hostname",
                        },
                    },
                ],
            },
        },

        // ── PodDisruptionBudget ──────────────────────────────────────────────
        // Never allow both replicas to be simultaneously unavailable
        podDisruptionBudget: {
            enabled: true,
            minAvailable: 1,
        },

        // ── Resources ───────────────────────────────────────────────────────
        // Sized for a cluster with up to ~50 nodes / 500 pods.
        // CoreDNS memory scales roughly linearly with Service count;
        // 128 Mi supports ≈10 k Services; increase for larger clusters.
        resources: {
            requests: { cpu: "100m", memory: "70Mi" },
            limits:   { cpu: "200m", memory: "170Mi" },
        },

        // ── Liveness / readiness probes ──────────────────────────────────────
        // initialDelaySeconds must be > lameduck (5 s) so a freshly started
        // pod is not considered alive before it's actually ready.
        livenessProbe: {
            initialDelaySeconds: 60,
            periodSeconds: 10,
            timeoutSeconds: 5,
            failureThreshold: 5,
        },
        readinessProbe: {
            initialDelaySeconds: 30,
            periodSeconds: 10,
            timeoutSeconds: 5,
            failureThreshold: 3,
        },
    }),
    tags: { ManagedBy: "Pulumi", Component: "coredns" },
}, { dependsOn: nodeDeps });

// ---------------------------------------------------------------------------
// metrics-server
//
// Provides the Metrics API used by:
//  - `kubectl top nodes / pods`
//  - Horizontal Pod Autoscaler (HPA)
//  - Vertical Pod Autoscaler (VPA)
//
// Available as an EKS-managed add-on from K8s 1.29+ so AWS handles patching.
// ---------------------------------------------------------------------------
export const metricsServerAddon = new aws.eks.Addon("metrics-server", {
    clusterName: cluster.eksCluster.name,
    addonName: "metrics-server",
    resolveConflictsOnUpdate: "OVERWRITE",
    // Schedule on system nodes; JSON string passed to the add-on's Helm values
    configurationValues: JSON.stringify({
        tolerations: [
            {
                key: "node.eks.aws/nodegroup",
                operator: "Equal",
                value: "system",
                effect: "NoSchedule",
            },
        ],
        nodeSelector: { role: "system" },
        resources: {
            requests: { cpu: "50m", memory: "64Mi" },
            limits: { cpu: "200m", memory: "128Mi" },
        },
    }),
    tags: { ManagedBy: "Pulumi", Component: "metrics-server" },
}, { dependsOn: nodeDeps });

// ---------------------------------------------------------------------------
// EKS Pod Identity Agent
//
// Modern replacement for IRSA (IAM Roles for Service Accounts).
// Runs as a DaemonSet on every node; intercepts credential requests and
// vends short-lived STS credentials scoped to the pod's namespace + SA.
//
// To grant a workload AWS permissions using Pod Identity:
//   1. Create IAM role trusting the EKS service principal:
//        "sts:AssumeRole", "sts:TagSession"
//        Principal: { Service: "pods.eks.amazonaws.com" }
//   2. Declare an aws.eks.PodIdentityAssociation linking role → namespace/SA
//   3. No annotation on the ServiceAccount is required
// ---------------------------------------------------------------------------
export const podIdentityAddon = new aws.eks.Addon("eks-pod-identity-agent", {
    clusterName: cluster.eksCluster.name,
    addonName: "eks-pod-identity-agent",
    resolveConflictsOnUpdate: "OVERWRITE",
    tags: { ManagedBy: "Pulumi", Component: "eks-pod-identity-agent" },
}, { dependsOn: nodeDeps });
