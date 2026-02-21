/**
 * GitOps – ArgoCD deployment via Pulumi Kubernetes Helm
 *
 * GitOps workflow principles applied:
 *  - Declarative App-of-Apps pattern (one root Application manages all others)
 *  - Automated sync with self-heal and prune enabled
 *  - Retry back-off to handle transient failures
 *  - HA ArgoCD (multiple replicas) for production reliability
 *  - External Secrets Operator integration for secret management
 *  - Private repo access via Kubernetes Secret (not stored in Git)
 */
import * as pulumi from "@pulumi/pulumi";
import * as k8s from "@pulumi/kubernetes";

const config = new pulumi.Config();
const gitopsRepoUrl = config.require("gitopsRepoUrl");
const gitopsRepoRevision = config.get("gitopsRepoRevision") ?? "main";

export function deployArgoCD(
    provider: k8s.Provider,
    dependencies: pulumi.Resource[] = [],
): k8s.helm.v3.Release {
    // -------------------------------------------------------------------------
    // ArgoCD Helm chart (HA mode for production reliability)
    // -------------------------------------------------------------------------
    const argocd = new k8s.helm.v3.Release("argocd", {
        name: "argocd",
        chart: "argo-cd",
        version: "9.4.3",
        namespace: "argocd",
        repositoryOpts: { repo: "https://argoproj.github.io/argo-helm" },
        createNamespace: false, // pre-created with PSS labels in pss.ts

        values: {
            // HA controllers
            controller: {
                replicas: 2,
                resources: {
                    requests: { cpu: "250m", memory: "512Mi" },
                    limits:   { cpu: "1000m", memory: "1Gi" },
                },
                tolerations: [
                    { key: "node.eks.aws/nodegroup", operator: "Equal", value: "system", effect: "NoSchedule" },
                ],
                nodeSelector: { role: "system" },
                // PDB: never allow both replicas to be disrupted simultaneously
                pdb: { enabled: true, minAvailable: 1 },
            },
            server: {
                replicas: 2,
                // Disable HTTP; TLS terminated at ALB
                insecure: true,
                resources: {
                    requests: { cpu: "100m", memory: "128Mi" },
                    limits:   { cpu: "500m", memory: "256Mi" },
                },
                tolerations: [
                    { key: "node.eks.aws/nodegroup", operator: "Equal", value: "system", effect: "NoSchedule" },
                ],
                nodeSelector: { role: "system" },
                // Metrics for Prometheus scraping
                metrics: { enabled: true, serviceMonitor: { enabled: true } },
                pdb: { enabled: true, minAvailable: 1 },
            },
            repoServer: {
                replicas: 2,
                resources: {
                    requests: { cpu: "200m", memory: "256Mi" },
                    limits:   { cpu: "1000m", memory: "512Mi" },
                },
                tolerations: [
                    { key: "node.eks.aws/nodegroup", operator: "Equal", value: "system", effect: "NoSchedule" },
                ],
                nodeSelector: { role: "system" },
                pdb: { enabled: true, minAvailable: 1 },
            },
            redis: {
                resources: {
                    requests: { cpu: "100m", memory: "128Mi" },
                    limits:   { cpu: "500m", memory: "256Mi" },
                },
                tolerations: [
                    { key: "node.eks.aws/nodegroup", operator: "Equal", value: "system", effect: "NoSchedule" },
                ],
                nodeSelector: { role: "system" },
            },
            applicationSet: {
                replicas: 2,
                tolerations: [
                    { key: "node.eks.aws/nodegroup", operator: "Equal", value: "system", effect: "NoSchedule" },
                ],
                nodeSelector: { role: "system" },
            },

            // Global config
            global: {
                // All pods run on system nodes
                tolerations: [
                    { key: "node.eks.aws/nodegroup", operator: "Equal", value: "system", effect: "NoSchedule" },
                ],
            },

            configs: {
                cm: {
                    // Enable ApplicationSet and multi-source support
                    "application.instanceLabelKey": "argocd.argoproj.io/app-name",
                    "resource.customizations": "",
                    // Health checks for ArgoCD Rollouts (progressive delivery)
                    "resource.customizations.health.argoproj.io_Rollout": `
hs = {}
hs.status = "Progressing"
hs.message = ""
if obj.status ~= nil then
  if obj.status.phase == "Degraded" then
    hs.status = "Degraded"
    hs.message = obj.status.message
  elseif obj.status.phase == "Healthy" then
    hs.status = "Healthy"
    hs.message = obj.status.message
  end
end
return hs`,
                },
                params: {
                    // Disable anonymous access
                    "server.disable.auth": "false",
                    "server.insecure": "true",
                },
                rbac: {
                    // Only admins can deploy to production projects
                    "policy.default": "role:readonly",
                    "policy.csv": `
p, role:platform-admin, applications, *, */*, allow
p, role:platform-admin, clusters, get, *, allow
p, role:platform-admin, repositories, *, *, allow
p, role:platform-admin, projects, *, *, allow
g, platform-admins, role:platform-admin
`,
                },
            },
        },
    }, { provider, dependsOn: dependencies });

    return argocd;
}

// ---------------------------------------------------------------------------
// App-of-Apps root Application – single source of truth for all deployments
// ---------------------------------------------------------------------------
export function createAppOfApps(
    provider: k8s.Provider,
    argocd: k8s.helm.v3.Release,
): k8s.apiextensions.CustomResource {
    return new k8s.apiextensions.CustomResource("app-of-apps", {
        apiVersion: "argoproj.io/v1alpha1",
        kind: "Application",
        metadata: {
            name: "app-of-apps",
            namespace: "argocd",
            finalizers: ["resources-finalizer.argocd.argoproj.io"],
        },
        spec: {
            project: "default",
            source: {
                repoURL: gitopsRepoUrl,
                targetRevision: gitopsRepoRevision,
                path: "gitops/apps",
            },
            destination: {
                server: "https://kubernetes.default.svc",
                namespace: "argocd",
            },
            syncPolicy: {
                automated: {
                    prune: true,
                    selfHeal: true,
                    allowEmpty: false,
                },
                syncOptions: [
                    "CreateNamespace=true",
                    "PrunePropagationPolicy=foreground",
                    "PruneLast=true",
                    "ServerSideApply=true",
                ],
                retry: {
                    limit: 5,
                    backoff: {
                        duration: "5s",
                        factor: 2,
                        maxDuration: "3m",
                    },
                },
            },
        },
    }, { provider, dependsOn: [argocd] });
}

// ---------------------------------------------------------------------------
// ArgoCD Project – prevents cross-namespace blast radius
// ---------------------------------------------------------------------------
export function createArgoCDProject(provider: k8s.Provider): k8s.apiextensions.CustomResource {
    return new k8s.apiextensions.CustomResource("eks-platform-project", {
        apiVersion: "argoproj.io/v1alpha1",
        kind: "AppProject",
        metadata: {
            name: "eks-platform",
            namespace: "argocd",
        },
        spec: {
            description: "EKS platform infrastructure applications",
            sourceRepos: [
                "*", // Allow all repos: git, OCI (karpenter), Helm (kyverno, cert-manager, etc.)
            ],
            destinations: [
                { namespace: "production",      server: "https://kubernetes.default.svc" },
                { namespace: "staging",          server: "https://kubernetes.default.svc" },
                { namespace: "monitoring",       server: "https://kubernetes.default.svc" },
                { namespace: "argocd",           server: "https://kubernetes.default.svc" },
                { namespace: "karpenter",        server: "https://kubernetes.default.svc" },
                { namespace: "tetragon",         server: "https://kubernetes.default.svc" },
                { namespace: "cert-manager",                    server: "https://kubernetes.default.svc" },
                { namespace: "external-secrets",              server: "https://kubernetes.default.svc" },
                { namespace: "loki",                          server: "https://kubernetes.default.svc" },
                { namespace: "logging",                       server: "https://kubernetes.default.svc" },
                { namespace: "opentelemetry-operator-system", server: "https://kubernetes.default.svc" },
                { namespace: "kube-system",                   server: "https://kubernetes.default.svc" }, // ALB controller
            ],
            clusterResourceWhitelist: [
                { group: "*", kind: "Namespace" },
                { group: "rbac.authorization.k8s.io", kind: "*" },
                { group: "networking.k8s.io", kind: "*" },
                { group: "karpenter.sh", kind: "*" },
                { group: "karpenter.k8s.aws", kind: "*" },
            ],
            orphanedResources: { warn: true },
        },
    }, { provider });
}
