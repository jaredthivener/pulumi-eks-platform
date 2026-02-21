/**
 * EKS Platform – main entrypoint
 *
 * Wires together:
 *  1. EKS cluster + VPC                    (src/cluster/eks.ts)
 *  2. Node groups (system + app/spot)      (src/cluster/nodegroups.ts)
 *  3. EKS managed add-ons                  (src/cluster/addons.ts)
 *     - CoreDNS, metrics-server, eks-pod-identity-agent
 *  4. Networking – Cilium CNI              (src/networking/cilium.ts)
 *     - Disables aws-node; Cilium 1.19.1 in ENI IPAM mode
 *     - WireGuard node-to-node encryption
 *     - Hubble L3-L7 observability
 *  5. Security hardening                   (src/security/)
 *     - Namespaces (no PSS labels – Kyverno handles policy)
 *     - Kyverno HA + kyverno-policies PSS enforcement
 *     - Default-deny NetworkPolicies
 *     - RBAC + ServiceAccounts
 *  6. GitOps – ArgoCD                      (src/gitops/argocd.ts)
 *     - HA ArgoCD Helm release
 *     - App-of-Apps root Application
 *     - ArgoCD Project with RBAC
 *  8. Cost optimisation – Karpenter        (src/autoscaling/karpenter.ts)
 *     - IAM role + SQS interruption queue (Helm managed by ArgoCD)
 *     - NodePool with consolidation
 *     - EC2NodeClass with Graviton
 *  9. Load Balancer Controller             (src/networking/alb-controller.ts)
 *     - IAM role + Pod Identity (Helm managed by ArgoCD)
 * 10. SLO monitoring                       (gitops/apps/observability.yaml, wave 4)
 *     - Recording rules (golden signals)
 *     - Multi-window burn-rate alerts
 *     - Alertmanager PD + Slack routing
 *
 * 11. Observability stack                   (gitops/apps/observability.yaml)
 *     - Loki (log aggregation, S3 backend)   wave 3
 *     - Fluent Bit (log shipper DaemonSet)   wave 4
 *     - OpenTelemetry Operator               wave 2
 *     - Grafana datasource pre-wired to Loki
 *
 * Helm charts managed by ArgoCD (gitops/apps/):
 *   - security.yaml     : kyverno, kyverno-policies, kyverno-cluster-policies, tetragon
 *   - platform.yaml     : cert-manager, external-secrets, aws-load-balancer-controller
 *   - karpenter.yaml    : karpenter, karpenter-config
 *   - observability.yaml: opentelemetry-operator, kube-prometheus-stack, loki, fluent-bit, slo-rules
 */
import * as pulumi from "@pulumi/pulumi";
import * as k8s from "@pulumi/kubernetes";

// ── Cluster & Networking ──────────────────────────────────────────────────────
import { cluster, kubeconfig, vpc, secretsKmsKey } from "./src/cluster/eks";
import { systemNodeGroup, appNodeGroup, nodeRole } from "./src/cluster/nodegroups";

// ── EKS Add-ons ───────────────────────────────────────────────────────────────
// Imported for module-level side-effects: resources declared as top-level
// constants in addons.ts are registered as soon as the module is loaded.
import "./src/cluster/addons";

// ── Cilium CNI ────────────────────────────────────────────────────────────────
import { disableAwsNode, deployCilium } from "./src/networking/cilium";

// ── Security ──────────────────────────────────────────────────────────────────
import { createNamespaces }         from "./src/security/namespaces";
import { createNetworkPolicies }    from "./src/security/network-policies";
import { createRbac }               from "./src/security/rbac";
// Kyverno is managed by ArgoCD – gitops/apps/security.yaml (wave 0)

// ── Load Balancer & GitOps ───────────────────────────────────────────────
import { deployArgoCD, createAppOfApps, createArgoCDProject } from "./src/gitops/argocd";

// ── Cost & AWS side-effects (IAM/SQS/PodIdentity register on load) ───────────
import "./src/networking/alb-controller"; // ALB Controller IAM + PodIdentity
import "./src/autoscaling/karpenter";     // Karpenter IAM + SQS + EventBridge
import "./src/security/external-secrets-iam"; // ESO IAM + PodIdentity (Secrets Manager access)
import "./src/storage/loki-storage";     // Loki S3 bucket + IAM + PodIdentity
// NodePool + EC2NodeClass managed by ArgoCD – gitops/apps/karpenter.yaml (wave 3)

// SLO rules are managed by ArgoCD – gitops/apps/observability.yaml (wave 4)
// Placed after kube-prometheus-stack (wave 3) which installs the PrometheusRule CRD.

// =============================================================================
// Kubernetes provider – uses the generated kubeconfig
// =============================================================================
const k8sProvider = new k8s.Provider("eks-provider", {
    kubeconfig,
    enableServerSideApply: true,
});

// =============================================================================
// 1a. Cilium CNI – bootstrapped BEFORE any pod-level resources
//
//     Order matters:
//       i.  Patch aws-node DaemonSet to nodeSelector that matches nothing → 0 pods
//       ii. Cilium Helm chart installs; operator takes over ENI IP management
//       iii.Cilium agent starts on each node, programs eBPF maps, removes the
//           node.cilium.io/agent-not-ready taint → pods start scheduling
//
//     kube-proxy stays running alongside Cilium (kubeProxyReplacement: true
//     means Cilium shadows kube-proxy's iptables rules with eBPF equivalents).
// =============================================================================
const awsNodePatch = disableAwsNode(k8sProvider);
const cilium = deployCilium(k8sProvider, awsNodePatch);

// =============================================================================
// 2. Namespaces, NetworkPolicies, RBAC
//    Kyverno is managed by ArgoCD – gitops/apps/security.yaml (wave 0)
// namespaces must exist (CreateNamespace=false on kyverno/karpenter/tetragon/argocd apps).
// Node groups must be ready before ArgoCD HA pods can schedule.
const namespaces = createNamespaces(k8sProvider);
createNetworkPolicies(k8sProvider);
createRbac(k8sProvider);

// =============================================================================
// 3. GitOps – ArgoCD (also runs on system node group)
//    ArgoCD then manages all remaining workloads via gitops/apps/
//    dependsOn: namespaces (argocd ns must exist) + node groups (pods need nodes)
// =============================================================================
const argocd = deployArgoCD(k8sProvider, [
    ...namespaces,
    systemNodeGroup,
    appNodeGroup,
]);
createArgoCDProject(k8sProvider);
export const appOfApps = createAppOfApps(k8sProvider, argocd);

// =============================================================================
// Exports
// =============================================================================
export const ciliumVersion     = cilium.version;
export const clusterName = cluster.eksCluster.name;
export const clusterEndpoint = cluster.core.endpoint;
export const clusterVersion = cluster.eksCluster.version;
export const vpcId = vpc.vpcId;
export const privateSubnetIds = vpc.privateSubnetIds;
export const publicSubnetIds = vpc.publicSubnetIds;
export const nodeRoleArn = nodeRole.arn;
export const secretsKmsKeyArn = secretsKmsKey.arn;

// Output kubeconfig as a secret (never expose in plaintext)
export const kubeconfigSecret = pulumi.secret(kubeconfig);
export { lokiBucketName } from "./src/storage/loki-storage";
export { s3VpcEndpoint } from "./src/networking/vpc";
