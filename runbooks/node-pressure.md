# Node Pressure Runbook

**Service:** EKS Nodes  
**Owner:** Platform Team  
**Alerts:** `NodeCPUSaturation`, `NodeMemorySaturation`, `NodeAvailabilitySLOBreach`

---

## Overview

Node pressure occurs when CPU or memory are exhausted, causing pod evictions (OOMKilled), scheduling failures (Pending pods), and potentially cascading failures across tenants on the node.

---

## Detection

```bash
# Which nodes are under pressure?
kubectl top nodes --sort-by=cpu
kubectl top nodes --sort-by=memory

# Check node conditions (MemoryPressure, DiskPressure, PIDPressure)
kubectl get nodes -o custom-columns='NAME:.metadata.name,STATUS:.status.conditions[-1].type,REASON:.status.conditions[-1].reason'

# Prometheus query: nodes > 85% CPU
# slo:node:cpu_utilization > 85
```

---

## Mitigation

### CPU Saturation

```bash
# Which pods are consuming most CPU?
kubectl top pods -A --sort-by=cpu | head -20

# Check if HPA is triggered
kubectl get hpa -A

# Manually scale offending deployment
kubectl scale deployment/<name> -n production --replicas=<desired>

# Cordon node to prevent new scheduling
kubectl cordon <node-name>

# Let Karpenter provision replacement node (check it's active)
kubectl logs -n karpenter -l app.kubernetes.io/name=karpenter | grep "launched"

# If Karpenter stuck, bump node group
aws eks update-nodegroup-config \
  --cluster-name eks-platform \
  --nodegroup-name app \
  --scaling-config desiredSize=<current+2>
```

### Memory Pressure / OOMKilled

```bash
# Find OOMKilled pods
kubectl get pods -A -o json | jq '.items[] | select(.status.containerStatuses[]?.lastState.terminated.reason=="OOMKilled") | .metadata.name'

# Check memory limits for a deployment
kubectl describe deployment/<name> -n production | grep -A3 "Limits:"

# Increase memory limit temporarily
kubectl set resources deployment/<name> -n production \
  --limits=memory=512Mi \
  --requests=memory=256Mi

# Find memory-hungry pods
kubectl top pods -A --sort-by=memory | head -20

# Check for memory leaks via metrics
# (Compare current RSS to container limit)
kubectl exec -n production <pod> -- cat /sys/fs/cgroup/memory/memory.usage_in_bytes
```

### Disk Pressure

```bash
# Which node has disk pressure?
kubectl get nodes -o json | jq '.items[] | select(.status.conditions[] | select(.type=="DiskPressure" and .status=="True")) | .metadata.name'

# SSH to node via SSM
aws ssm start-session --target <instance-id>

# Check disk usage
df -h

# Find large files
du -sh /var/lib/docker/containers/* | sort -rh | head -10

# Force container log rotation
find /var/log/containers -name "*.log" -size +100M -delete

# If persistent, add more disk via launch template or replace node
kubectl drain <node> --ignore-daemonsets --delete-emptydir-data
kubectl delete node <node>
# Karpenter will provision a replacement
```

---

## Verification

```bash
# Node pressure resolved
kubectl get nodes | grep -E "MemoryPressure|DiskPressure|PIDPressure"

# Pods stable
kubectl get pods -n production | grep -v Running

# Node resource metrics normal
kubectl top nodes
```

---

## Prevention (Long-Term)

- Ensure all Deployments have VPA (Vertical Pod Autoscaler) recommendations
- Review Karpenter `consolidateAfter` settings to right-size nodes continuously
- Set `LimitRange` defaults in all namespaces (already applied via Pulumi)
- Enable PodDisruptionBudgets for all critical services
