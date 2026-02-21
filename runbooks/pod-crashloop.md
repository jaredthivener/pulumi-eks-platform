# Pod CrashLoopBackOff Runbook

**Service:** Any Kubernetes workload  
**Owner:** Application owner / Platform on-call  
**Severity:** SEV3 (single pod) → SEV2 (all replicas) → SEV1 (cascading failure)

---

## Overview

`CrashLoopBackOff` means the pod is starting, crashing, and Kubernetes is back-off retrying.  
Common causes: bad config, OOM, missing dependencies, failed health checks, bad image.

---

## Initial Triage (2 Minutes)

```bash
# Which pods are crash-looping?
kubectl get pods -A | grep CrashLoop

# How many restarts? (high restart count = persistent issue)
kubectl get pods -n <namespace> | awk '{if ($4>5) print}'

# Get the last exit code and reason
kubectl get pod <pod-name> -n <namespace> -o json | \
  jq '.status.containerStatuses[].lastState.terminated | {reason, exitCode, message}'
```

Exit code reference:
| Code | Meaning |
|---|---|
| 0 | Success (should not crash) |
| 1 | Application error |
| 137 | OOMKilled (SIGKILL) |
| 139 | Segfault |
| 143 | SIGTERM (graceful shutdown) |

---

## Root Cause Investigation

### Bad Configuration / Missing Secret

```bash
# Check recent config changes
kubectl describe pod <pod-name> -n <namespace>

# Look at env and volumes for bad references
kubectl get pod <pod-name> -n <namespace> -o yaml | grep -A20 "env:"

# Verify all referenced Secrets/ConfigMaps exist
kubectl get secret <secret-name> -n <namespace>
kubectl get configmap <cm-name> -n <namespace>
```

### Application Error

```bash
# View crash logs (current and previous container)
kubectl logs <pod-name> -n <namespace> --tail=200
kubectl logs <pod-name> -n <namespace> --previous --tail=200

# Multi-container pod
kubectl logs <pod-name> -n <namespace> -c <container-name> --previous

# If logs are empty, run a debug container
kubectl debug -it <pod-name> -n <namespace> --image=busybox --share-processes
```

### OOMKilled (exit 137)

```bash
# Confirm OOM
kubectl describe pod <pod-name> -n <namespace> | grep -A5 "Last State"

# Check current memory limits
kubectl get pod <pod-name> -n <namespace> -o json | \
  jq '.spec.containers[].resources'

# Temporary fix: increase memory limit
kubectl set resources deployment/<name> -n production \
  --limits=memory=1Gi --requests=memory=512Mi

# Long term: add VPA annotation to auto-right-size
```

### Bad Image / ImagePullBackOff

```bash
kubectl describe pod <pod-name> -n <namespace> | grep -A5 "Events"

# Verify image exists
aws ecr describe-images --repository-name <repo> --image-ids imageTag=<tag>

# Roll back to previous known-good image
kubectl set image deployment/<name> -n production \
  <container>=<registry>/<image>:<last-good-tag>
```

### Failed Liveness Probe

```bash
# Check probe config
kubectl get deployment <name> -n production -o json | \
  jq '.spec.template.spec.containers[].livenessProbe'

# Test probe manually
kubectl exec <pod> -n production -- curl -f http://localhost:8080/healthz

# Temporarily disable probe to stabilise (then fix properly)
kubectl patch deployment <name> -n production \
  --type=json \
  -p='[{"op":"remove","path":"/spec/template/spec/containers/0/livenessProbe"}]'
```

---

## Mitigation

```bash
# Rollback deployment to last good version
kubectl rollout undo deployment/<name> -n production

# Scale to 0 then back (force fresh start)
kubectl scale deployment/<name> -n production --replicas=0
kubectl scale deployment/<name> -n production --replicas=3

# Hard delete stuck pod (Kubernetes will recreate)
kubectl delete pod <pod-name> -n production --grace-period=0 --force
```

---

## Verification

```bash
# Pods stable
kubectl get pods -n production -w

# Restart count not increasing
kubectl get pods -n production | awk '{print $4}' | sort -n

# Check application metrics in Grafana
# Dashboard: [Service Health](https://grafana.internal/d/service-health)
```

---

## Escalation

| Condition | Action |
|---|---|
| All replicas in CrashLoop | Immediately rollback + page application owner |
| Unknown root cause after 20 min | Escalate to senior engineer |
| Data corruption suspected | Page security + engineering manager |

---

## Post-Incident

- [ ] Add missing health check to prevent silent failures
- [ ] Improve OOM – set correct memory request via VPA recommendation
- [ ] Add alert for `kube_pod_container_status_restarts_total > 5` per 5m
- [ ] Review deploy pipeline – add smoke tests before full rollout
