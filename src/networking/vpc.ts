/**
 * VPC – dedicated, isolated network for the EKS platform.
 *
 * Design decisions:
 *  - 3 AZs for HA; one NAT Gateway per AZ (no single-AZ egress bottleneck)
 *  - Private /22 subnets for nodes/pods — large enough for dense pod scheduling
 *  - Public /24 subnets for internet-facing load balancers only
 *  - Subnet tags required by the AWS Load Balancer Controller for ALB/NLB discovery
 *  - S3 Gateway Endpoint: EKS→S3 traffic stays on AWS backbone (no NAT charges)
 *  - VPC and subnets protected from accidental deletion (protect: true)
 */
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";

const config = new pulumi.Config();
const clusterName = config.get("clusterName") ?? "eks-platform";

export const vpc = new awsx.ec2.Vpc(`${clusterName}-vpc`, {
    numberOfAvailabilityZones: 3,
    natGateways: { strategy: awsx.ec2.NatGatewayStrategy.OnePerAz },
    subnetStrategy: awsx.ec2.SubnetAllocationStrategy.Auto,
    subnetSpecs: [
        {
            type: awsx.ec2.SubnetType.Private,
            cidrMask: 22,
            // Required for internal ALB/NLB discovery by the AWS Load Balancer Controller
            tags: { "kubernetes.io/role/internal-elb": "1" },
        },
        {
            type: awsx.ec2.SubnetType.Public,
            cidrMask: 24,
            // Required for internet-facing ALB/NLB discovery
            tags: { "kubernetes.io/role/elb": "1" },
        },
    ],
    tags: {
        Name: `${clusterName}-vpc`,
        [`kubernetes.io/cluster/${clusterName}`]: "shared",
        ManagedBy: "Pulumi",
    },
}, { protect: true });

// ---------------------------------------------------------------------------
// S3 VPC Gateway Endpoint
//
// Routes all EKS → S3 traffic through the AWS private backbone instead of
// the NAT Gateway. Benefits:
//   - No NAT Gateway data-processing charges for S3 traffic (Loki chunks,
//     ECR image layers, EKS audit logs to S3, etc.)
//   - S3 traffic never leaves the AWS network — stronger security posture
//   - No additional latency; gateway endpoints are regional and free
//
// Implementation: one route entry is injected into each private route table,
// pointing S3 CIDRs (pl-63a5400a in us-east-1) at the endpoint, not the NAT.
// ---------------------------------------------------------------------------
const region = aws.getRegionOutput().name;

// Look up the route table associated with each private subnet (one per AZ),
// then deduplicate in case awsx shares a route table across subnets.
const privateRouteTableIds = vpc.privateSubnetIds.apply(async (subnetIds) => {
    const ids = await Promise.all(
        subnetIds.map(subnetId => aws.ec2.getRouteTable({ subnetId }).then(rt => rt.id)),
    );
    return [...new Set(ids)];
});

export const s3VpcEndpoint = new aws.ec2.VpcEndpoint(`${clusterName}-s3-endpoint`, {
    vpcId: vpc.vpcId,
    serviceName: pulumi.interpolate`com.amazonaws.${region}.s3`,
    vpcEndpointType: "Gateway",
    // Associate with every private route table so all nodes/pods use the endpoint.
    routeTableIds: privateRouteTableIds,
    policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            // Restrict to actions/buckets used by the platform.
            // Wildcard principal is required for gateway endpoint policies.
            Effect: "Allow",
            Principal: "*",
            Action: [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:GetObjectAttributes",
                "s3:ListBucket",
                "s3:GetBucketLocation",
                // ECR image layers are also served from S3
                "s3:GetEncryptionConfiguration",
            ],
            Resource: "*",
        }],
    }),
    tags: {
        Name: `${clusterName}-s3-endpoint`,
        ManagedBy: "Pulumi",
    },
});
