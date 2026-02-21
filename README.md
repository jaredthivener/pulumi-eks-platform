# EKS Platform

Production-grade AWS EKS platform built with Pulumi TypeScript, incorporating security hardening, GitOps with ArgoCD, cost optimisation via Karpenter, SRE SLO definitions, and structured incident runbooks.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  AWS Account                                                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  VPC (3 AZs, private/public subnets, 1 NAT GW per AZ)     │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  EKS Cluster (private endpoint, KMS secrets, IRSA)  │  │  │
│  │  │                                                     │  │  │
│  │  │  ┌─────────────┐  ┌──────────────────────────────┐  │  │  │
│  │  │  │ System NG   │  │  App NG (Spot, Graviton)     │  │  │  │
│  │  │  │ On-Demand   │  │  + Karpenter just-in-time    │  │  │  │
│  │  │  │ ArgoCD      │  │  provisioning                │  │  │  │
│  │  │  │ Karpenter   │  │                              │  │  │  │
│  │  │  │ Prometheus  │  │  production / staging NS     │  │  │  │
│  │  │  └─────────────┘  └──────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  KMS (secrets)  SQS (Karpenter interruption)  CloudWatch Logs   │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
.
├── index.ts                        # Main entrypoint – wires all modules
├── Pulumi.yaml                     # Project metadata
├── package.json
├── tsconfig.json
│
├── src/
│   ├── cluster/
│   │   ├── eks.ts                  # EKS cluster, VPC, KMS, control-plane logs
│   │   └── nodegroups.ts           # System (on-demand) + App (spot) node groups
│   │
│   ├── security/
│   │   ├── pss.ts                  # Namespaces, Pod Security Standards, ResourceQuotas
│   │   ├── network-policies.ts     # Default-deny + explicit allow NetworkPolicies
│   │   └── rbac.ts                 # ServiceAccounts, ClusterRoles, RoleBindings
│   │
│   ├── gitops/
│   │   └── argocd.ts               # HA ArgoCD Helm, App-of-Apps, ArgoCD Project
│   │
│   ├── cost/
│   │   └── karpenter.ts            # Karpenter IRSA, Helm chart, NodePool, EC2NodeClass
│   │
│   └── monitoring/
│       └── slos.ts                 # PrometheusRules (recording + alerts), Alertmanager
│
├── gitops/
│   └── applications/
│       └── platform-apps.yaml      # ArgoCD Applications (ingress-nginx, cert-manager,
│                                   #   kube-prometheus-stack, external-secrets)
│
└── runbooks/
    ├── eks-cluster-outage.md       # SEV1/SEV2 cluster-level outage
    ├── node-pressure.md            # CPU/memory/disk pressure
    └── pod-crashloop.md            # CrashLoopBackOff diagnosis & mitigation
```

## Security Hardening (kubernetes-specialist)

| Control | Implementation |
|---|---|
| Private API endpoint | `endpointPublicAccess: false` |
| Secrets encryption | AWS KMS envelope encryption |
| IMDSv2 | `httpTokens: required` on all nodes |
| Encrypted EBS | `encrypted: true` on all node volumes |
| Pod Security Standards | `restricted` (prod), `baseline` (monitoring/argocd) |
| Default-deny NetworkPolicy | Applied to every managed namespace |
| No root containers | `runAsNonRoot: true`, `allowPrivilegeEscalation: false` |
| Least-privilege RBAC | Separate ServiceAccounts per workload |
| Control plane audit logging | All 5 log types → CloudWatch (90-day retention) |

## GitOps Workflow (ArgoCD)

- **App-of-Apps pattern** – single root Application manages all platform apps
- **Automated sync** with `prune: true` and `selfHeal: true`
- **Retry back-off** – 5 retries, exponential back-off up to 3m
- **Progressive delivery** – ArgoCD Rollouts canary/blue-green support
- **Secret management** – External Secrets Operator syncs from AWS Secrets Manager
- **RBAC** – read-only by default; `platform-admin` role for deploy access

## Cost Optimisation (cost-optimization)

| Strategy | Savings | Implementation |
|---|---|---|
| Spot instances (app workloads) | Up to 90% | Karpenter NodePool `"spot"` capacity type |
| Graviton (arm64) priority | ~20% better price/perf | Graviton instance families listed first |
| Instance diversification | Reduces interruption | 15+ instance types in NodePool |
| Node consolidation | 15-30% | `consolidationPolicy: WhenUnderutilized` |
| Node TTL rotation | Picks up cheaper Spot | `expireAfter: 720h` |
| Disruption budget | Avoids downtime | Max 10% removed at once; business hours freeze |

## SLO Definitions (sre-engineer)

| Service | SLI | SLO Target | Error Budget (30d) |
|---|---|---|---|
| API Gateway | Availability (non-5xx ratio) | **99.9%** | 43.2 min |
| API Gateway | Latency p99 < 500ms | **99.9%** | 43.2 min |
| Auth Service | Availability | **99.95%** | 21.6 min |
| EKS Nodes | Healthy node ratio | **99.5%** | 3.6 hours |

**Alerting model:** Multi-window, multi-burn-rate (Google SRE Book)
- 14.4× burn rate over 1h window → **Critical / PagerDuty**
- 6× burn rate over 6h window → **Warning / Slack**
- < 10% error budget remaining → **Warning / Slack**

## Incident Runbooks

| Runbook | Covers | SLA |
|---|---|---|
| [eks-cluster-outage.md](runbooks/eks-cluster-outage.md) | Control plane, mass node failure, ArgoCD drift | SEV1: 15min response |
| [node-pressure.md](runbooks/node-pressure.md) | CPU/memory/disk saturation | SEV2: 30min response |
| [pod-crashloop.md](runbooks/pod-crashloop.md) | CrashLoopBackOff diagnosis | SEV3: 2hr response |

## Prerequisites

- AWS CLI configured with appropriate permissions
- Pulumi CLI ≥ 3.x
- Node.js ≥ 20.x

## Deployment

```bash
# Install dependencies
npm install

# Set required config
pulumi config set clusterName eks-platform
pulumi config set k8sVersion 1.35
pulumi config set gitopsRepoUrl https://github.com/your-org/gitops-repo
pulumi config set adminRoleArn arn:aws:iam::123456789:role/PlatformAdmins

# (Recommended) Use Pulumi ESC instead of stack config for credentials
pulumi env init myorg/eks-platform-prod
pulumi config env add myorg/eks-platform-prod

# Preview changes
pulumi preview

# Deploy
pulumi up
```

## Pulumi ESC Integration

Create a `myorg/eks-platform-prod` ESC environment:

```yaml
values:
  aws:
    login:
      fn::open::aws-login:
        oidc:
          roleArn: arn:aws:iam::123456789:role/pulumi-oidc
          sessionName: pulumi-eks-platform

  pulumiConfig:
    aws:region: us-east-1
    clusterName: eks-platform
    gitopsRepoUrl: https://github.com/your-org/gitops-repo

  environmentVariables:
    AWS_ACCESS_KEY_ID: ${aws.login.accessKeyId}
    AWS_SECRET_ACCESS_KEY: ${aws.login.secretAccessKey}
    AWS_SESSION_TOKEN: ${aws.login.sessionToken}
```

## Stack Outputs

| Output | Description |
|---|---|
| `clusterName` | EKS cluster name |
| `clusterEndpoint` | API server endpoint (private) |
| `vpcId` | VPC ID |
| `privateSubnetIds` | Private subnet IDs |
| `nodeRoleArn` | Node IAM role ARN |
| `secretsKmsKeyArn` | KMS key ARN for Secrets encryption |
| `kubeconfigSecret` | Kubeconfig (marked as secret) |

## Contributing

1. Make changes in a feature branch
2. Run `pulumi preview` to validate
3. Open PR → ArgoCD previews diff before merge
4. Merge triggers ArgoCD auto-sync: staging → production

A Pulumi project configured with a curated set of agent skills for DevOps and infrastructure work. Skills were installed following the guide [The Claude Skills I Actually Use for DevOps](https://www.pulumi.com/blog/top-8-claude-skills-devops-2026/) by Engin Diri.

Skills are markdown files that encode engineering expertise and load into your AI agent on demand, without burning context until they are needed.

---

## Installed Skills

### Pulumi

| Skill | Source | Description |
|-------|--------|-------------|
| `pulumi-typescript` | [dirien/claude-skills](https://github.com/dirien/claude-skills) | Pulumi with TypeScript, ESC secrets management, component patterns, and multi-cloud deployment. Prevents common mistakes like creating resources inside `apply()` callbacks. |
| `pulumi-esc` | [pulumi/agent-skills](https://github.com/pulumi/agent-skills) | Environment, secrets, and configuration management with OIDC, dynamic credentials, and secret store integration (AWS Secrets Manager, Vault, Azure Key Vault). |
| `pulumi-best-practices` | [pulumi/agent-skills](https://github.com/pulumi/agent-skills) | Resource dependencies, ComponentResource patterns, secret encryption, and safe refactoring. Enforces `pulumi preview` before any deployment. |

### Kubernetes & GitOps

| Skill | Source | Description |
|-------|--------|-------------|
| `kubernetes-specialist` | [jeffallan/claude-skills](https://github.com/jeffallan/claude-skills) | Production cluster management, security hardening, and cloud-native architectures. Generates configs with security contexts, resource limits, liveness/readiness probes, and pod disruption budgets by default. |
| `gitops-workflow` | [wshobson/agents](https://github.com/wshobson/agents) | ArgoCD and Flux CD for automated Kubernetes deployments with continuous reconciliation. |
| `k8s-security-policies` | [wshobson/agents](https://github.com/wshobson/agents) | Network policies, pod security standards, RBAC, OPA Gatekeeper constraints, and admission control for defense-in-depth. |

### CI/CD & Automation

| Skill | Source | Description |
|-------|--------|-------------|
| `github-actions-templates` | [wshobson/agents](https://github.com/wshobson/agents) | CI/CD workflows, Docker builds, Kubernetes deployments, security scanning, and matrix builds. |

### Observability & Reliability

| Skill | Source | Description |
|-------|--------|-------------|
| `monitoring-expert` | [jeffallan/claude-skills](https://github.com/jeffallan/claude-skills) | Structured logging, metrics, distributed tracing, alerting, and performance testing for production systems. Covers Prometheus, Grafana, and DataDog. |
| `sre-engineer` | [jeffallan/claude-skills](https://github.com/jeffallan/claude-skills) | SLI/SLO management, error budgets, monitoring, automation, and incident response. Produces Prometheus/Grafana configs and reliability assessments. |

### Cost & Incident Management

| Skill | Source | Description |
|-------|--------|-------------|
| `cost-optimization` | [wshobson/agents](https://github.com/wshobson/agents) | Cloud cost reduction across AWS, Azure, and GCP with right-sizing, reserved instances, and spending analysis. |
| `incident-runbook-templates` | [wshobson/agents](https://github.com/wshobson/agents) | Detection, triage, mitigation, resolution, and communication procedures for production incidents. Includes a four-level severity model (SEV1–SEV4) with escalation decision trees. |

### Security

| Skill | Source | Description |
|-------|--------|-------------|
| `security-review` | [sickn33/antigravity-awesome-skills](https://github.com/sickn33/antigravity-awesome-skills) | Secrets management, input validation, SQL injection, XSS/CSRF prevention, and dependency auditing for application-level security. |

### General DevOps

| Skill | Source | Description |
|-------|--------|-------------|
| `devops-engineer` | [jeffallan/claude-skills](https://github.com/jeffallan/claude-skills) | CI/CD pipelines, container management, deployment strategies (blue-green, canary), and infrastructure as code across AWS, GCP, and Azure. Enforces no production deploys without approval, no secrets in code, no unversioned images. |

### Debugging

| Skill | Source | Description |
|-------|--------|-------------|
| `systematic-debugging` | [obra/superpowers](https://github.com/obra/superpowers) | Root cause investigation, pattern analysis, hypothesis testing, and verified implementation. Implements a four-phase framework that investigates before prescribing fixes. |

---

## Install Commands

```bash
# Pulumi
npx skills add https://github.com/dirien/claude-skills --skill pulumi-typescript
npx skills add https://github.com/pulumi/agent-skills --skill pulumi-esc
npx skills add https://github.com/pulumi/agent-skills --skill pulumi-best-practices

# Debugging
npx skills add https://github.com/obra/superpowers --skill systematic-debugging

# Observability
npx skills add https://github.com/jeffallan/claude-skills --skill monitoring-expert
npx skills add https://github.com/jeffallan/claude-skills --skill sre-engineer

# Kubernetes & GitOps
npx skills add https://github.com/jeffallan/claude-skills --skill kubernetes-specialist
npx skills add https://github.com/wshobson/agents --skill gitops-workflow
npx skills add https://github.com/wshobson/agents --skill k8s-security-policies

# CI/CD & Cost
npx skills add https://github.com/wshobson/agents --skill github-actions-templates
npx skills add https://github.com/wshobson/agents --skill cost-optimization
npx skills add https://github.com/wshobson/agents --skill incident-runbook-templates

# General DevOps
npx skills add https://github.com/jeffallan/claude-skills --skill devops-engineer

# Security
npx skills add https://github.com/sickn33/antigravity-awesome-skills --skill security-review
```

---

## Example Prompts

**Static website** — triggers Pulumi TypeScript, monitoring, and security skills:
```
Create a Pulumi TypeScript program for a static website on AWS with S3, CloudFront,
OIDC credentials via Pulumi ESC, CloudWatch monitoring, and /security-review
the infrastructure before deploying
```

**EKS cluster** — stacks Kubernetes, GitOps, incident response, cost, and SRE skills:
```
Create a Pulumi TypeScript program for an EKS cluster with /kubernetes-specialist
security hardening, /gitops-workflow for ArgoCD deployment, /incident-runbook-templates
for the cluster, /cost-optimization recommendations, and /sre-engineer SLO definitions
for the services
```

---

## References

- Blog post: [The Claude Skills I Actually Use for DevOps](https://www.pulumi.com/blog/top-8-claude-skills-devops-2026/)
- Agent Skills standard: [agentskills.io](https://agentskills.io/)
- Pulumi official skills: [pulumi/agent-skills](https://github.com/pulumi/agent-skills)
- Pulumi Agent Skills announcement: [pulumi.com/blog/pulumi-agent-skills](https://www.pulumi.com/blog/pulumi-agent-skills/)
- Security advisory on malicious skills: [Snyk ToxicSkills research](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)
