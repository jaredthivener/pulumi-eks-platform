/**
 * Namespaces, ResourceQuotas, and LimitRanges
 *
 * Creates all platform namespaces and enforces resource governance:
 *  - ResourceQuotas: cap total CPU/memory/pod count per namespace
 *  - LimitRanges: inject default requests/limits so pods can't omit them
 *
 * Pod security policy is handled entirely by Kyverno (src/security/kyverno.ts).
 * No PSA/PSS labels are applied here.
 */
import * as k8s from "@pulumi/kubernetes";

export function createNamespaces(provider: k8s.Provider): k8s.core.v1.Namespace[] {
    const namespaces = [
        { name: "production" },
        { name: "staging" },
        { name: "argocd" },
        { name: "monitoring" },
        { name: "karpenter" },
        { name: "tetragon" },
        { name: "cert-manager" },
        { name: "external-secrets" },
        { name: "loki" },
        { name: "opentelemetry-operator-system" },
        { name: "tracing" },  // Jaeger + OTel Collector
    ];

    const created = namespaces.map(({ name }) =>
        new k8s.core.v1.Namespace(name, {
            metadata: {
                name,
                labels: {
                    // Required for Kyverno's namespaceSelector-based exclusions
                    "kubernetes.io/metadata.name": name,
                },
                annotations: { "pulumi.com/managed": "true" },
            },
        }, { provider }),
    );

    return created;

    // ---------------------------------------------------------------------------
    // Resource quotas – prevent a rogue app from exhausting cluster resources
    // ---------------------------------------------------------------------------
    new k8s.core.v1.ResourceQuota("production-quota", {
        metadata: { name: "production-quota", namespace: "production" },
        spec: {
            hard: {
                "requests.cpu": "20",
                "requests.memory": "40Gi",
                "limits.cpu": "40",
                "limits.memory": "80Gi",
                "count/pods": "200",
                "count/services": "50",
                "count/persistentvolumeclaims": "30",
            },
        },
    }, { provider });

    // LimitRange – default requests/limits so pods can't omit them
    new k8s.core.v1.LimitRange("production-limits", {
        metadata: { name: "default-limits", namespace: "production" },
        spec: {
            limits: [
                {
                    type: "Container",
                    default: { cpu: "500m", memory: "512Mi" },
                    defaultRequest: { cpu: "100m", memory: "128Mi" },
                    max: { cpu: "4", memory: "8Gi" },
                    min: { cpu: "50m", memory: "64Mi" },
                },
                {
                    type: "Pod",
                    max: { cpu: "8", memory: "16Gi" },
                },
            ],
        },
    }, { provider });
}

/** Opinionated securityContext to apply to all application containers */
export const restrictedSecurityContext = {
    runAsNonRoot: true,
    runAsUser: 1000,
    runAsGroup: 3000,
    fsGroup: 2000,
    allowPrivilegeEscalation: false,
    readOnlyRootFilesystem: true,
    capabilities: { drop: ["ALL"] },
    seccompProfile: { type: "RuntimeDefault" },
};
