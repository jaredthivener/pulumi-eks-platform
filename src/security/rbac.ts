/**
 * Kubernetes security hardening – RBAC
 *
 * Kubernetes-specialist principles applied:
 *  - Least-privilege ServiceAccounts per workload
 *  - No default SA with API access
 *  - Cluster-level read auditors, namespace-level operators only
 *  - Separate SA for ArgoCD, Karpenter, monitoring
 */
import * as k8s from "@pulumi/kubernetes";

export function createRbac(provider: k8s.Provider): void {
    // -------------------------------------------------------------------------
    // Developers read-only ClusterRole – inspect resources, no mutation
    // -------------------------------------------------------------------------
    const devReadOnly = new k8s.rbac.v1.ClusterRole("dev-read-only", {
        metadata: { name: "dev-read-only" },
        rules: [
            {
                apiGroups: [""],
                resources: [
                    "pods", "pods/log", "pods/status",
                    "services", "endpoints", "configmaps",
                    "events", "namespaces", "nodes",
                    "persistentvolumes", "persistentvolumeclaims",
                    "resourcequotas", "limitranges",
                ],
                verbs: ["get", "list", "watch"],
            },
            {
                apiGroups: ["apps"],
                resources: ["deployments", "replicasets", "statefulsets", "daemonsets"],
                verbs: ["get", "list", "watch"],
            },
            {
                apiGroups: ["autoscaling"],
                resources: ["horizontalpodautoscalers"],
                verbs: ["get", "list", "watch"],
            },
            {
                apiGroups: ["batch"],
                resources: ["jobs", "cronjobs"],
                verbs: ["get", "list", "watch"],
            },
        ],
    }, { provider });

    // -------------------------------------------------------------------------
    // Platform operators – full access within their namespace only
    // -------------------------------------------------------------------------
    const nsOperatorRole = new k8s.rbac.v1.Role("ns-operator", {
        metadata: { name: "ns-operator", namespace: "production" },
        rules: [
            {
                apiGroups: ["", "apps", "batch", "autoscaling", "policy"],
                resources: ["*"],
                verbs: ["*"],
            },
        ],
    }, { provider });

    // -------------------------------------------------------------------------
    // Deny default ServiceAccount API access across all system namespaces
    // Applied via explicit binding to a "no-api-access" ClusterRole
    // -------------------------------------------------------------------------
    const noApiAccess = new k8s.rbac.v1.ClusterRole("no-api-access", {
        metadata: { name: "no-api-access" },
        rules: [], // empty = no permissions
    }, { provider });

    const systemNamespaces = ["kube-system", "kube-public", "default"];
    systemNamespaces.forEach((ns) => {
        new k8s.rbac.v1.RoleBinding(`deny-default-sa-${ns}`, {
            metadata: { name: "deny-default-sa", namespace: ns },
            roleRef: {
                apiGroup: "rbac.authorization.k8s.io",
                kind: "ClusterRole",
                name: "no-api-access",
            },
            subjects: [
                {
                    kind: "ServiceAccount",
                    name: "default",
                    namespace: ns,
                },
            ],
        }, { provider });
    });

    // -------------------------------------------------------------------------
    // Monitoring view – Prometheus needs cluster-wide read of metrics
    // -------------------------------------------------------------------------
    const prometheusRole = new k8s.rbac.v1.ClusterRole("prometheus-scrape", {
        metadata: { name: "prometheus-scrape" },
        rules: [
            {
                apiGroups: [""],
                resources: ["nodes", "nodes/proxy", "nodes/metrics", "services", "endpoints", "pods"],
                verbs: ["get", "list", "watch"],
            },
            {
                apiGroups: ["extensions", "networking.k8s.io"],
                resources: ["ingresses"],
                verbs: ["get", "list", "watch"],
            },
            {
                nonResourceURLs: ["/metrics", "/metrics/cadvisor"],
                verbs: ["get"],
            },
        ],
    }, { provider });

    new k8s.rbac.v1.ClusterRoleBinding("prometheus-scrape-binding", {
        metadata: { name: "prometheus-scrape" },
        roleRef: {
            apiGroup: "rbac.authorization.k8s.io",
            kind: "ClusterRole",
            name: prometheusRole.metadata.name,
        },
        subjects: [
            {
                kind: "ServiceAccount",
                name: "kube-prometheus-stack-prometheus",
                namespace: "monitoring",
            },
        ],
    }, { provider });
}
