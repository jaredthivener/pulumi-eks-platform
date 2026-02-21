# EKS Cluster Outage Runbook

**Service:** EKS Platform  
**Owner:** Platform Team  
**Slack:** #platform-incidents  
**PagerDuty:** platform-oncall  
**Severity Guide:** SEV1 = control plane down / >50% nodes unhealthy | SEV2 = degraded API / >20% nodes unhealthy

---

## Overview & Impact

The EKS cluster hosts all production workloads. A control-plane or mass-node failure cascades to all services, causing full customer-facing outage. Financial impact can exceed $10k/min.

---

## Detection & Alerts

| Alert | SLO | Trigger |
|---|---|---|
| `NodeAvailabilitySLOBreach` | Node availability < 99.5% | Page |
| `ApiGatewayHighErrorBudgetBurn` | Error budget burn 14.4× | Page |
| `AuthServiceErrorBudgetBurn` | Error budget burn 14.4× | Page |

**Dashboards**
- [Cluster Overview – Grafana](https://grafana.internal/d/eks-overview)
- [Node Health](https://grafana.internal/d/node-health)
- [AWS Console – EKS](https://console.aws.amazon.com/eks)

---

## Initial Triage (First 5 Minutes)

### 1. Assess Control Plane

```bash
# Is kubectl responsive?
kubectl cluster-info
kubectl get nodes --watch

# Check control plane condition
kubectl get componentstatuses

# EKS-managed control plane status via AWS CLI
aws eks describe-cluster --name eks-platform --query "cluster.status"

# Check AWS service health
open https://health.aws.amazon.com/health/status
```

### 2. Assess Node Health

```bash
# Count Ready vs NotReady nodes
kubectl get nodes | awk '{print $2}' | sort | uniq -c

# Detailed node conditions
kubectl describe nodes | grep -A5 "Conditions:"

# Karpenter: check if it's attempting to replace unhealthy nodes
kubectl logs -n karpenter -l app.kubernetes.io/name=karpenter --tail=50

# Node resource pressure
kubectl top nodes
```

### 3. Assess Workload Impact

```bash
# Pods not running
kubectl get pods -A | grep -v Running | grep -v Completed

# Recent events (errors first)
kubectl get events -A --sort-by='.lastTimestamp' | grep -i "warning\|error" | tail -50

# ArgoCD sync status – are GitOps apps healthy?
argocd app list
```

---

## Mitigation Steps

### 4.1 Control Plane Unresponsive

The EKS control plane is AWS-managed. If the API server is unresponsive:

```bash
# Confirm it's EKS, not networking
aws eks describe-cluster --name eks-platform

# Check if private endpoint is reachable from a node (use SSM)
aws ssm start-session --target <instance-id>
curl -sk https://<cluster-endpoint>/healthz

# If AWS incident, open support case immediately
aws support create-case \
  --subject "EKS control plane unresponsive – production" \
  --service-code amazon-eks \
  --severity-code urgent
```

**Escalate to Engineering Manager if unresolved in 15 minutes (SEV1).**

### 4.2 Mass Node Failure (NotReady)

```bash
# Identify affected nodes and their cause
kubectl describe node <node-name> | grep -A10 "Conditions\|Events"

# Check if Karpenter is already replacing them
kubectl get nodeclaims
kubectl logs -n karpenter -l app.kubernetes.io/name=karpenter -f

# Force Karpenter to reprovision (delete stuck NodeClaims)
kubectl delete nodeclaim <stuck-nodeclaim>

# If Karpenter is stuck, fall back to manually scaling the managed node group
aws eks update-nodegroup-config \
  --cluster-name eks-platform \
  --nodegroup-name system \
  --scaling-config minSize=3,maxSize=10,desiredSize=6

# Cordon failing nodes to stop new scheduling
kubectl cordon <bad-node>

# Drain safely (timeout 120s per pod)
kubectl drain <bad-node> --ignore-daemonsets --delete-emptydir-data --timeout=120s
```

### 4.3 ArgoCD Sync Failure Causing Drift

```bash
# View out-of-sync apps
argocd app list | grep OutOfSync

# Hard refresh (bypass cache)
argocd app get app-of-apps --refresh

# Force sync with prune
argocd app sync app-of-apps --prune --force

# If CRDs are blocking sync
argocd app sync kube-prometheus-stack --server-side-apply
```

### 4.4 Recent Bad Deployment (Rollback)

```bash
# Find the deployment that's failing
kubectl rollout history deployment/<name> -n production

# Immediate rollback to last good revision
kubectl rollout undo deployment/<name> -n production

# Monitor rollback
kubectl rollout status deployment/<name> -n production --watch

# If Helm chart deployed via ArgoCD, rollback ArgoCD to previous git SHA
argocd app set <app-name> --revision <last-good-sha>
argocd app sync <app-name>
```

---

## Verification Steps

```bash
# All nodes Ready
kubectl get nodes | grep -v Ready

# All production pods running
kubectl get pods -n production | grep -v Running

# Control plane healthy
kubectl get componentstatuses

# Check SLO metrics (1-min moving window)
curl -s "http://prometheus.monitoring:9090/api/v1/query?query=slo:node:healthy_ratio" | jq '.data.result[0].value[1]'

# API Gateway error rate
curl -s "http://prometheus.monitoring:9090/api/v1/query?query=1-slo:api_gateway:availability:5m" | jq
```

---

## Rollback Procedures

| Scenario | Command |
|---|---|
| Bad Deployment | `kubectl rollout undo deployment/<name> -n production` |
| Bad Helm release | `helm rollback <release> <revision> -n <ns>` |
| ArgoCD to old SHA | `argocd app set <app> --revision <sha> && argocd app sync <app>` |
| Karpenter NodePool bad config | `kubectl apply -f gitops/karpenter/nodepool.yaml` |

---

## Escalation Matrix

| Condition | Escalate To | Contact |
|---|---|---|
| Control plane down > 15 min | Engineering Manager | @em-oncall (Slack) |
| Mass data loss suspected | Security + Legal | #security-incidents |
| AWS infrastructure failure | AWS Premium Support | Open P1 case |
| Customer SLA breach likely | Account Managers | @customer-success |

---

## Communication Templates

### Initial (Internal – Post in #platform-incidents)

```
🚨 INCIDENT: EKS Cluster Degradation

Severity: SEV1
Status: Investigating
Impact: [X]% of production pods affected
Start Time: [HH:MM UTC]
IC: @[your-handle]

Dashboards: [link]
Next update in 15 minutes.
```

### Customer-Facing (via StatusPage)

```
We are investigating elevated error rates affecting [service].
Our engineering team is actively working on a resolution.
Updates every 15 minutes.
```

### Resolution

```
✅ RESOLVED: EKS Cluster Incident

Duration: [X] minutes
Root Cause: [brief description]
Resolution: [what fixed it]

Impact: ~[N] users, [%] error rate for [duration]
Postmortem: [link] (to be scheduled within 48h)
```

---

## Post-Incident

- [ ] Schedule blameless postmortem within 48 hours
- [ ] Update this runbook with new failure modes discovered
- [ ] File issue for any toil discovered (manual steps > 3 min)
- [ ] Update SLO targets if error budget was exhausted
