/**
 * NetworkPolicies – default-deny with explicit allow rules
 *
 * Kubernetes-specialist principles applied:
 *  - Default deny all ingress AND egress per namespace
 *  - Explicit allow rules for known communication paths
 *  - DNS egress always allowed (UDP/TCP 53 → kube-dns)
 *  - Inter-namespace traffic only via labelled allow policies
 */
import * as k8s from "@pulumi/kubernetes";

export function createNetworkPolicies(provider: k8s.Provider): void {
    const namespaces = ["production", "staging", "argocd", "monitoring",
        "cert-manager", "external-secrets", "karpenter", "tetragon",
        "loki", "opentelemetry-operator-system", "tracing"];

    // -------------------------------------------------------------------------
    // Default-deny all ingress + egress for every managed namespace
    // -------------------------------------------------------------------------
    namespaces.forEach((ns) => {
        new k8s.networking.v1.NetworkPolicy(`default-deny-${ns}`, {
            metadata: { name: "default-deny-all", namespace: ns },
            spec: {
                podSelector: {}, // applies to ALL pods
                policyTypes: ["Ingress", "Egress"],
                // no ingress/egress rules → deny everything
            },
        }, { provider });

        // Allow DNS egress to kube-system (CoreDNS) – required for all pods
        new k8s.networking.v1.NetworkPolicy(`allow-dns-${ns}`, {
            metadata: { name: "allow-dns-egress", namespace: ns },
            spec: {
                podSelector: {},
                policyTypes: ["Egress"],
                egress: [
                    {
                        ports: [
                            { protocol: "UDP", port: 53 },
                            { protocol: "TCP", port: 53 },
                        ],
                        to: [
                            {
                                namespaceSelector: {
                                    matchLabels: { "kubernetes.io/metadata.name": "kube-system" },
                                },
                            },
                        ],
                    },
                ],
            },
        }, { provider });
    });

    // -------------------------------------------------------------------------
    // Infrastructure namespaces – HTTPS egress + intra-namespace
    //
    // cert-manager:     ACME (Let's Encrypt) + k8s API
    // external-secrets: AWS Secrets Manager + k8s API
    // karpenter:        AWS EC2/SQS/EventBridge + k8s API
    // tetragon:         k8s API (eBPF observability operator)
    // -------------------------------------------------------------------------
    const infraNamespaces = ["cert-manager", "external-secrets", "karpenter", "tetragon",
        "opentelemetry-operator-system", "tracing"];
    infraNamespaces.forEach((ns) => {
        // Allow HTTPS egress: covers AWS APIs, k8s internal endpoint, Helm repos
        new k8s.networking.v1.NetworkPolicy(`allow-https-egress-${ns}`, {
            metadata: { name: "allow-https-egress", namespace: ns },
            spec: {
                podSelector: {},
                policyTypes: ["Egress"],
                egress: [{
                    ports: [{ protocol: "TCP", port: 443 }],
                    to: [{ ipBlock: { cidr: "0.0.0.0/0" } }],
                }],
            },
        }, { provider });

        // Allow intra-namespace traffic (multi-pod operators, webhooks, leader election)
        new k8s.networking.v1.NetworkPolicy(`allow-intra-ns-${ns}`, {
            metadata: { name: "allow-intra-namespace", namespace: ns },
            spec: {
                podSelector: {},
                policyTypes: ["Ingress", "Egress"],
                ingress: [{ from: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": ns } } }] }],
                egress:  [{ to:   [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": ns } } }] }],
            },
        }, { provider });
    });

    // Allow kube-apiserver to reach webhook servers in infra namespaces
    // (cert-manager webhook, kyverno webhook runs in its own namespace)
    infraNamespaces.forEach((ns) => {
        new k8s.networking.v1.NetworkPolicy(`allow-webhook-ingress-${ns}`, {
            metadata: { name: "allow-apiserver-webhook", namespace: ns },
            spec: {
                podSelector: {},
                policyTypes: ["Ingress"],
                ingress: [{
                    // apiserver CIDR — allow from any source on webhook ports
                    ports: [{ protocol: "TCP", port: 9443 }, { protocol: "TCP", port: 10250 }],
                    from: [{ ipBlock: { cidr: "0.0.0.0/0" } }],
                }],
            },
        }, { provider });
    });

    // -------------------------------------------------------------------------
    // Production namespace – allow traffic from ALB controller (kube-system)
    // -------------------------------------------------------------------------
    new k8s.networking.v1.NetworkPolicy("prod-allow-ingress-controller", {
        metadata: { name: "allow-ingress-controller", namespace: "production" },
        spec: {
            podSelector: { matchLabels: { "app.kubernetes.io/part-of": "platform" } },
            policyTypes: ["Ingress"],
            ingress: [
                {
                    from: [
                        {
                            namespaceSelector: {
                                matchLabels: { "kubernetes.io/metadata.name": "kube-system" },
                            },
                        },
                    ],
                    ports: [{ protocol: "TCP", port: 8080 }],
                },
            ],
        },
    }, { provider });

    // Allow Prometheus in monitoring namespace to scrape all pods
    // No port restriction: apps expose metrics on their own ports (varies per workload).
    // Prometheus discovers the correct port via ServiceMonitor/PodMonitor scrape config.
    new k8s.networking.v1.NetworkPolicy("prod-allow-prometheus-scrape", {
        metadata: { name: "allow-prometheus-scrape", namespace: "production" },
        spec: {
            podSelector: {},
            policyTypes: ["Ingress"],
            ingress: [
                {
                    from: [
                        {
                            namespaceSelector: {
                                matchLabels: { "kubernetes.io/metadata.name": "monitoring" },
                            },
                            podSelector: {
                                matchLabels: { "app.kubernetes.io/name": "prometheus" },
                            },
                        },
                    ],
                    // No ports clause: allow scraping on any port.
                    // Prometheus reaches the pod's metrics endpoint via ServiceMonitor config.
                },
            ],
        },
    }, { provider });

    // Allow pods to egress to the AWS API (for IRSA, S3, etc.) via HTTPS
    new k8s.networking.v1.NetworkPolicy("prod-allow-aws-api-egress", {
        metadata: { name: "allow-aws-api-egress", namespace: "production" },
        spec: {
            podSelector: {},
            policyTypes: ["Egress"],
            egress: [
                {
                    ports: [{ protocol: "TCP", port: 443 }],
                    // CIDR 0.0.0.0/0 but only on 443 – allows IRSA STS calls
                    to: [{ ipBlock: { cidr: "0.0.0.0/0", except: ["169.254.169.254/32"] } }],
                },
            ],
        },
    }, { provider });

    // -------------------------------------------------------------------------
    // Loki – S3 egress + Fluent Bit push ingress + Prometheus scrape ingress
    // -------------------------------------------------------------------------
    // Loki needs HTTPS egress for S3 (chunks/index). From a NetworkPolicy
    // perspective the pod connects to S3 IPs on port 443 as normal — the VPC
    // Gateway Endpoint (src/networking/vpc.ts) intercepts the traffic at the
    // routing layer and keeps it on the AWS private backbone (no NAT charges).
    new k8s.networking.v1.NetworkPolicy("loki-https-egress", {
        metadata: { name: "allow-https-egress", namespace: "loki" },
        spec: {
            podSelector: {},
            policyTypes: ["Egress"],
            egress: [{ ports: [{ protocol: "TCP", port: 443 }], to: [{ ipBlock: { cidr: "0.0.0.0/0" } }] }],
        },
    }, { provider });

    new k8s.networking.v1.NetworkPolicy("loki-intra-ns", {
        metadata: { name: "allow-intra-namespace", namespace: "loki" },
        spec: {
            podSelector: {},
            policyTypes: ["Ingress", "Egress"],
            ingress: [{ from: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "loki" } } }] }],
            egress:  [{ to:   [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "loki" } } }] }],
        },
    }, { provider });

    // OTel Collector (tracing ns) -> Loki gateway on port 3100
    new k8s.networking.v1.NetworkPolicy("loki-allow-otelcollector-ingress", {
        metadata: { name: "allow-otelcollector-push", namespace: "loki" },
        spec: {
            podSelector: {},
            policyTypes: ["Ingress"],
            ingress: [{
                from: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "tracing" } } }],
                ports: [{ protocol: "TCP", port: 3100 }],
            }],
        },
    }, { provider });

    // Prometheus → Loki scrape (varied ports)
    new k8s.networking.v1.NetworkPolicy("loki-allow-prometheus-scrape", {
        metadata: { name: "allow-prometheus-scrape", namespace: "loki" },
        spec: {
            podSelector: {},
            policyTypes: ["Ingress"],
            ingress: [{
                from: [{
                    namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "monitoring" } },
                    podSelector: { matchLabels: { "app.kubernetes.io/name": "prometheus" } },
                }],
            }],
        },
    }, { provider });

    // -------------------------------------------------------------------------
    // ArgoCD – allow ingress from itself (controller ↔ repo-server ↔ server)
    // -------------------------------------------------------------------------
    new k8s.networking.v1.NetworkPolicy("argocd-internal", {
        metadata: { name: "allow-argocd-internal", namespace: "argocd" },
        spec: {
            podSelector: { matchLabels: { "app.kubernetes.io/part-of": "argocd" } },
            policyTypes: ["Ingress", "Egress"],
            ingress: [
                {
                    from: [
                        {
                            namespaceSelector: {
                                matchLabels: { "kubernetes.io/metadata.name": "argocd" },
                            },
                        },
                    ],
                },
            ],
            egress: [
                // Internal argocd traffic
                {
                    to: [
                        {
                            namespaceSelector: {
                                matchLabels: { "kubernetes.io/metadata.name": "argocd" },
                            },
                        },
                    ],
                },
                // GitHub / GitLab HTTPS for repo sync
                {
                    ports: [{ protocol: "TCP", port: 443 }],
                    to: [{ ipBlock: { cidr: "0.0.0.0/0" } }],
                },
                // Kubernetes API
                {
                    ports: [{ protocol: "TCP", port: 6443 }],
                    to: [{ ipBlock: { cidr: "0.0.0.0/0" } }],
                },
            ],
        },
    }, { provider });

    // -------------------------------------------------------------------------
    // Monitoring – Prometheus scrapes all namespaces; Alertmanager → external
    // -------------------------------------------------------------------------
    new k8s.networking.v1.NetworkPolicy("monitoring-scrape-egress", {
        metadata: { name: "allow-scrape-egress", namespace: "monitoring" },
        spec: {
            podSelector: { matchLabels: { "app.kubernetes.io/name": "prometheus" } },
            policyTypes: ["Egress"],
            egress: [
                {
                    // Scrape pods on any port in any namespace
                    to: [{ namespaceSelector: {} }],
                },
                // Alertmanager webhook / PagerDuty (Prometheus → Alertmanager)
                {
                    ports: [{ protocol: "TCP", port: 443 }],
                    to: [{ ipBlock: { cidr: "0.0.0.0/0" } }],
                },
            ],
        },
    }, { provider });

    // Alertmanager egress – PagerDuty, Slack, and other notification endpoints.
    // Scoped to alertmanager pods only; does NOT grant Grafana or Prometheus
    // unrestricted egress. Without this, Alertmanager can't fire any alerts.
    new k8s.networking.v1.NetworkPolicy("monitoring-alertmanager-egress", {
        metadata: { name: "allow-alertmanager-egress", namespace: "monitoring" },
        spec: {
            podSelector: { matchLabels: { "app.kubernetes.io/name": "alertmanager" } },
            policyTypes: ["Egress"],
            egress: [
                {
                    // Notification endpoints: PagerDuty (events.pagerduty.com:443),
                    // Slack (hooks.slack.com:443), etc.
                    ports: [{ protocol: "TCP", port: 443 }],
                    to: [{ ipBlock: { cidr: "0.0.0.0/0" } }],
                },
                {
                    // Intra-namespace: Alertmanager HA mesh (gossip on port 9094)
                    to: [{
                        namespaceSelector: {
                            matchLabels: { "kubernetes.io/metadata.name": "monitoring" },
                        },
                    }],
                    ports: [{ protocol: "TCP", port: 9094 }, { protocol: "UDP", port: 9094 }],
                },
            ],
        },
    }, { provider });

    // Grafana egress – Loki datasource query (loki gateway port 80)
    // and HTTPS for external plugin downloads / avatar proxying.
    new k8s.networking.v1.NetworkPolicy("monitoring-grafana-egress", {
        metadata: { name: "allow-grafana-egress", namespace: "monitoring" },
        spec: {
            podSelector: { matchLabels: { "app.kubernetes.io/name": "grafana" } },
            policyTypes: ["Egress"],
            egress: [
                {
                    // Loki gateway for log queries via the Loki datasource
                    ports: [{ protocol: "TCP", port: 80 }, { protocol: "TCP", port: 3100 }],
                    to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "loki" } } }],
                },
                {
                    // HTTPS: Prometheus datasource (intra-ns), plugin downloads, etc.
                    ports: [{ protocol: "TCP", port: 443 }],
                    to: [{ ipBlock: { cidr: "0.0.0.0/0" } }],
                },
                {
                    // Intra-monitoring: reach Prometheus/Alertmanager within same ns
                    to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "monitoring" } } }],
                },
                {
                    // Jaeger Query UI/API (port 16686) for trace datasource
                    ports: [{ protocol: "TCP", port: 16686 }],
                    to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "tracing" } } }],
                },
            ],
        },
    }, { provider });

    // -------------------------------------------------------------------------
    // Staging – mirrors production policies so staging workloads behave the
    // same as production (ALB ingress, Prometheus scrape, AWS API egress).
    // -------------------------------------------------------------------------
    new k8s.networking.v1.NetworkPolicy("staging-allow-ingress-controller", {
        metadata: { name: "allow-ingress-controller", namespace: "staging" },
        spec: {
            podSelector: { matchLabels: { "app.kubernetes.io/part-of": "platform" } },
            policyTypes: ["Ingress"],
            ingress: [{
                from: [{
                    namespaceSelector: {
                        matchLabels: { "kubernetes.io/metadata.name": "kube-system" },
                    },
                }],
                ports: [{ protocol: "TCP", port: 8080 }],
            }],
        },
    }, { provider });

    new k8s.networking.v1.NetworkPolicy("staging-allow-prometheus-scrape", {
        metadata: { name: "allow-prometheus-scrape", namespace: "staging" },
        spec: {
            podSelector: {},
            policyTypes: ["Ingress"],
            ingress: [{
                from: [{
                    namespaceSelector: {
                        matchLabels: { "kubernetes.io/metadata.name": "monitoring" },
                    },
                    podSelector: {
                        matchLabels: { "app.kubernetes.io/name": "prometheus" },
                    },
                }],
            }],
        },
    }, { provider });

    new k8s.networking.v1.NetworkPolicy("staging-allow-aws-api-egress", {
        metadata: { name: "allow-aws-api-egress", namespace: "staging" },
        spec: {
            podSelector: {},
            policyTypes: ["Egress"],
            egress: [{
                ports: [{ protocol: "TCP", port: 443 }],
                to: [{ ipBlock: { cidr: "0.0.0.0/0", except: ["169.254.169.254/32"] } }],
            }],
        },
    }, { provider });

    // -------------------------------------------------------------------------
    // Tracing – app namespaces push OTLP spans to the OTel Collector;
    // Jaeger Query is reachable from Grafana (monitoring); Prometheus scrapes
    // Jaeger and OTel Collector metrics.
    // -------------------------------------------------------------------------
    // Production / staging → OTel Collector OTLP ingress (gRPC 4317, HTTP 4318)
    (["production", "staging"] as const).forEach((ns) => {
        new k8s.networking.v1.NetworkPolicy(`${ns}-allow-otlp-egress`, {
            metadata: { name: "allow-otlp-egress", namespace: ns },
            spec: {
                podSelector: {},
                policyTypes: ["Egress"],
                egress: [{
                    ports: [
                        { protocol: "TCP", port: 4317 }, // OTLP gRPC
                        { protocol: "TCP", port: 4318 }, // OTLP HTTP
                    ],
                    to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "tracing" } } }],
                }],
            },
        }, { provider });
    });

    // OTel Collector and Jaeger accept OTLP spans from app namespaces
    new k8s.networking.v1.NetworkPolicy("tracing-allow-otlp-ingress", {
        metadata: { name: "allow-otlp-ingress", namespace: "tracing" },
        spec: {
            podSelector: {},
            policyTypes: ["Ingress"],
            ingress: [{
                from: [
                    { namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "production" } } },
                    { namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "staging" } } },
                ],
                ports: [
                    { protocol: "TCP", port: 4317 }, // OTLP gRPC
                    { protocol: "TCP", port: 4318 }, // OTLP HTTP
                ],
            }],
        },
    }, { provider });

    // Grafana → Jaeger Query API (port 16686)
    new k8s.networking.v1.NetworkPolicy("tracing-allow-grafana-query", {
        metadata: { name: "allow-grafana-query", namespace: "tracing" },
        spec: {
            podSelector: {},
            policyTypes: ["Ingress"],
            ingress: [{
                from: [{
                    namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "monitoring" } },
                    podSelector: { matchLabels: { "app.kubernetes.io/name": "grafana" } },
                }],
                ports: [{ protocol: "TCP", port: 16686 }],
            }],
        },
    }, { provider });

    // Prometheus → Jaeger + OTel Collector metrics scrape
    new k8s.networking.v1.NetworkPolicy("tracing-allow-prometheus-scrape", {
        metadata: { name: "allow-prometheus-scrape", namespace: "tracing" },
        spec: {
            podSelector: {},
            policyTypes: ["Ingress"],
            ingress: [{
                from: [{
                    namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "monitoring" } },
                    podSelector: { matchLabels: { "app.kubernetes.io/name": "prometheus" } },
                }],
            }],
        },
    }, { provider });

    // OTel Collector (tracing) → Loki gateway (logs pipeline, loki exporter)
    new k8s.networking.v1.NetworkPolicy("tracing-allow-loki-egress", {
        metadata: { name: "allow-loki-egress", namespace: "tracing" },
        spec: {
            podSelector: {},
            policyTypes: ["Egress"],
            egress: [{
                ports: [{ protocol: "TCP", port: 3100 }],
                to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "loki" } } }],
            }],
        },
    }, { provider });

    // OTel Collector (tracing) → Prometheus remote_write (metrics pipeline)
    new k8s.networking.v1.NetworkPolicy("tracing-allow-prometheus-remote-write-egress", {
        metadata: { name: "allow-prometheus-remote-write-egress", namespace: "tracing" },
        spec: {
            podSelector: {},
            policyTypes: ["Egress"],
            egress: [{
                ports: [{ protocol: "TCP", port: 9090 }],
                to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "monitoring" } } }],
            }],
        },
    }, { provider });

    // Prometheus accepts remote_write ingress from OTel Collector in tracing ns
    new k8s.networking.v1.NetworkPolicy("monitoring-allow-otel-remote-write", {
        metadata: { name: "allow-otel-remote-write", namespace: "monitoring" },
        spec: {
            podSelector: { matchLabels: { "app.kubernetes.io/name": "prometheus" } },
            policyTypes: ["Ingress"],
            ingress: [{
                from: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "tracing" } } }],
                ports: [{ protocol: "TCP", port: 9090 }],
            }],
        },
    }, { provider });
}
