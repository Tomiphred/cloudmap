"""AWS discovery. Read-only: only Describe*/List*/Get* calls are made.

Placement model (what ends up inside what):
    Account > Region > VPC > Subnet > {EC2, NAT, Lambda-in-VPC, RDS, ElastiCache ...}
Resources that live at VPC level (load balancers, EKS, ASG, IGW) sit directly in the VPC box,
regional services (SQS, SNS, DynamoDB, API Gateway ...) sit in the Region box, and
account-wide services (CloudFront) sit in the Account box.

Secrets are never collected: no Lambda environment variables, no SNS subscription endpoints
(emails/URLs), no instance user-data, no object listings.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from .. import iam as iamlib
from ..model import Graph, Resource, parse_time
from .base import Provider

# type -> (display name, glyph shown in the icon, category)
_T = {
    "aws.account":            ("AWS Account", "AWS", "container"),
    "aws.region":             ("Region", "RGN", "container"),
    "aws.ec2.vpc":            ("VPC", "VPC", "container"),
    "aws.ec2.subnet":         ("Subnet", "SUB", "container"),
    "aws.ec2.instance":       ("EC2 Instance", "EC2", "compute"),
    "aws.autoscaling.group":  ("Auto Scaling Group", "ASG", "compute"),
    "aws.lambda.function":    ("Lambda Function", "λ", "compute"),
    "aws.ecs.cluster":        ("ECS Cluster", "ECS", "compute"),
    "aws.ecs.service":        ("ECS Service", "SVC", "compute"),
    "aws.eks.cluster":        ("EKS Cluster", "EKS", "compute"),
    "aws.ec2.igw":            ("Internet Gateway", "IGW", "network"),
    "aws.ec2.natgw":          ("NAT Gateway", "NAT", "network"),
    "aws.ec2.vpce":           ("VPC Endpoint", "VPE", "network"),
    "aws.ec2.tgw":            ("Transit Gateway", "TGW", "network"),
    "aws.elbv2.alb":          ("Application LB", "ALB", "network"),
    "aws.elbv2.nlb":          ("Network LB", "NLB", "network"),
    "aws.elbv2.gwlb":         ("Gateway LB", "GLB", "network"),
    "aws.rds.instance":       ("RDS Instance", "RDS", "database"),
    "aws.elasticache.cluster": ("ElastiCache", "ELC", "database"),
    "aws.dynamodb.table":     ("DynamoDB Table", "DDB", "database"),
    "aws.s3.bucket":          ("S3 Bucket", "S3", "storage"),
    "aws.sqs.queue":          ("SQS Queue", "SQS", "integration"),
    "aws.sns.topic":          ("SNS Topic", "SNS", "integration"),
    "aws.apigateway.rest":    ("API Gateway (REST)", "API", "edge"),
    "aws.apigateway.http":    ("API Gateway (HTTP)", "API", "edge"),
    "aws.cloudfront.distribution": ("CloudFront", "CDN", "edge"),
    "aws.iam":                ("Identity & Access (IAM)", "IAM", "container"),
    "aws.iam.user":           ("IAM User", "USR", "security"),
    "aws.iam.group":          ("IAM Group", "GRP", "security"),
    "aws.iam.role":           ("IAM Role", "ROL", "security"),
    "aws.kms.key":            ("KMS Key", "KMS", "security"),
    "aws.secretsmanager.secret": ("Secrets Manager Secret", "SEC", "security"),
    "aws.ssm.parameter":      ("SSM Parameter", "SSM", "security"),
}
TYPES = {k: {"label": v[0], "short": v[1], "category": v[2]} for k, v in _T.items()}

DEFAULT_ROUTES = {"0.0.0.0/0", "::/0"}
ALL_SERVICES = [
    "vpc", "ec2", "autoscaling", "elbv2", "rds", "elasticache", "lambda", "ecs", "eks",
    "dynamodb", "sqs", "sns", "apigateway", "kms", "secretsmanager", "ssm",
    "s3", "cloudfront", "iam",          # global ones last: IAM resolves policies against everything found before it
]
GLOBAL_SERVICES = {"s3", "cloudfront", "iam"}
MAX_ITEMS = 1000           # safety cap per service per region
API_CALL_CAP = 60          # cap for per-item follow-up calls (API Gateway methods)
MAX_ACCESS_EDGES = 6000    # safety cap on permission edges across the whole account

# IAM service prefix -> node types it governs; used to expand 'Resource: "*"' grants into real targets.
SERVICE_TYPES = {
    "s3": ["aws.s3.bucket"], "ec2": ["aws.ec2.instance"], "lambda": ["aws.lambda.function"],
    "dynamodb": ["aws.dynamodb.table"], "sqs": ["aws.sqs.queue"], "sns": ["aws.sns.topic"],
    "rds": ["aws.rds.instance"], "kms": ["aws.kms.key"], "secretsmanager": ["aws.secretsmanager.secret"],
    "ssm": ["aws.ssm.parameter"], "ecs": ["aws.ecs.cluster", "aws.ecs.service"], "eks": ["aws.eks.cluster"],
    "elasticloadbalancing": ["aws.elbv2.alb", "aws.elbv2.nlb", "aws.elbv2.gwlb"],
    "apigateway": ["aws.apigateway.rest", "aws.apigateway.http"], "cloudfront": ["aws.cloudfront.distribution"],
    "elasticache": ["aws.elasticache.cluster"], "autoscaling": ["aws.autoscaling.group"],
    "iam": ["aws.iam.user", "aws.iam.group", "aws.iam.role"],
}


def _tags(items) -> dict[str, str]:
    return {t["Key"]: t.get("Value", "") for t in (items or []) if "Key" in t}


def _pages(client, op: str, key: str, **kw) -> Iterable[dict]:
    n = 0
    if client.can_paginate(op):
        for page in client.get_paginator(op).paginate(**kw):
            for item in page.get(key, []):
                yield item
                n += 1
                if n >= MAX_ITEMS:
                    return
    else:
        for item in getattr(client, op)(**kw).get(key, [])[:MAX_ITEMS]:
            yield item


class Ctx:
    """Everything a collector needs for one region."""

    def __init__(self, provider: "AWSProvider", region: str, graph: Graph):
        self.p, self.region, self.g = provider, region, graph
        self.region_id = f"region:{region}"
        self.shared: dict = {"tg": {}}   # data handed between collectors (target group -> LB)

    def client(self, service: str, region: str | None = None):
        return self.p.client(service, region or self.region)

    def parent_for_subnets(self, subnet_ids: list[str], level: str = "subnet") -> str:
        """Pick a placement from subnet ids: the subnet itself, its VPC, or fall back to region."""
        for sid in subnet_ids or []:
            sub = self.g.resources.get(sid)
            if sub:
                if level == "subnet":
                    return sid
                if sub.parent:
                    return sub.parent
        return self.region_id

    def vpc_or_region(self, vpc_id: str | None) -> str:
        return vpc_id if vpc_id and vpc_id in self.g.resources else self.region_id

    def add(self, **kw) -> Resource:
        kw.setdefault("region", self.region)
        return self.g.add(Resource(**kw))

    def kms_ref(self, ref: str | None) -> str | None:
        """KMS references appear as key id, key ARN or alias; return something Graph.finalize() can resolve."""
        if not ref:
            return None
        if ref.startswith("arn:"):
            return ref
        base = f"arn:{self.p.partition}:kms:{self.region}:{self.g.account}:"
        return base + (ref if ref.startswith("alias/") else f"key/{ref}")


def link_kms(c: Ctx, ref: str | None, rid: str, label: str = "SSE-KMS") -> None:
    key = c.kms_ref(ref)
    if key:
        c.g.link(key, rid, "encrypts", label)


def apply_resource_policy(g: Graph, rid: str, doc: Any, source: str = "resource policy") -> None:
    """Turn a resource-based policy (key policy, secret/queue/topic/bucket policy) into 'who can access this'.

    Named principals in the same account become access edges; foreign accounts, services and
    'anyone' (*) are recorded as properties on the resource instead."""
    res = g.resources.get(rid)
    if res is None:
        return
    services, cross, federated = set(), set(), set()
    public = False
    for st in iamlib.statements(doc):
        if st["effect"] != "Allow":
            continue
        levels = ", ".join(iamlib.level_of(st["actions"])) or "access"
        label = f"{levels}: {iamlib.summarize_actions(st['actions'])} ({source})"
        for ptype, values in st["principals"].items():
            for v in values:
                if ptype == "Service":
                    services.add(v)
                elif ptype == "Federated":
                    federated.add(v)
                elif v == "*":
                    public = public or not st["conditional"]
                else:
                    arn = v if v.startswith("arn:") else f"arn:aws:iam::{v}:root"
                    m = re.match(r"arn:[^:]*:iam::(\d{12}):root$", arn)
                    if m:
                        if m.group(1) != g.account:
                            cross.add(m.group(1))
                        continue          # same-account root just delegates to IAM policies
                    if not re.match(r"arn:[^:]*:iam::(\d{12}):", arn) or arn.split(":")[4] != g.account:
                        cross.add(arn.split(":")[4] if arn.count(":") > 4 else arn)
                        continue
                    g.link(arn, rid, "access", label)
    if public:
        res.props["public_policy"] = True
    if cross:
        res.props["cross_account_principals"] = sorted(cross)
    if services:
        res.props["service_principals"] = sorted(services)
    if federated:
        res.props["federated_principals"] = sorted(federated)


# --------------------------------------------------------------------------- collectors
def collect_vpc(c: Ctx) -> None:
    ec2, g, r = c.client("ec2"), c.g, c.region
    for v in _pages(ec2, "describe_vpcs", "Vpcs"):
        t = _tags(v.get("Tags"))
        c.add(id=v["VpcId"], type="aws.ec2.vpc", name=t.get("Name") or v["VpcId"],
              parent=c.region_id, container=True, tags=t,
              props={"cidr": v.get("CidrBlock"), "default": v.get("IsDefault"),
                     "state": v.get("State"), "tenancy": v.get("InstanceTenancy")})

    subnets: dict[str, dict] = {}
    for s in _pages(ec2, "describe_subnets", "Subnets"):
        t = _tags(s.get("Tags"))
        subnets[s["SubnetId"]] = s
        c.add(id=s["SubnetId"], type="aws.ec2.subnet", name=t.get("Name") or s["SubnetId"],
              parent=c.vpc_or_region(s.get("VpcId")), container=True, tags=t,
              props={"cidr": s.get("CidrBlock"), "az": s.get("AvailabilityZone"),
                     "available_ips": s.get("AvailableIpAddressCount"), "public": False})

    for gw in _pages(ec2, "describe_internet_gateways", "InternetGateways"):
        att = (gw.get("Attachments") or [{}])[0]
        t = _tags(gw.get("Tags"))
        c.add(id=gw["InternetGatewayId"], type="aws.ec2.igw",
              name=t.get("Name") or gw["InternetGatewayId"],
              parent=c.vpc_or_region(att.get("VpcId")), tags=t,
              props={"state": att.get("State")})

    for n in _pages(ec2, "describe_nat_gateways", "NatGateways"):
        if n.get("State") in ("deleted", "deleting", "failed"):
            continue
        t = _tags(n.get("Tags"))
        ips = [a.get("PublicIp") for a in n.get("NatGatewayAddresses", []) if a.get("PublicIp")]
        c.add(id=n["NatGatewayId"], type="aws.ec2.natgw", name=t.get("Name") or n["NatGatewayId"],
              parent=c.parent_for_subnets([n.get("SubnetId")]) if n.get("SubnetId") else c.region_id,
              tags=t, created=n.get("CreateTime"), props={"state": n.get("State"), "public_ip": ", ".join(ips),
                             "connectivity": n.get("ConnectivityType")})

    for e in _pages(ec2, "describe_vpc_endpoints", "VpcEndpoints"):
        if e.get("State") in ("deleted", "deleting", "failed"):
            continue
        t = _tags(e.get("Tags"))
        short = (e.get("ServiceName") or "").split(".", 3)[-1]
        c.add(id=e["VpcEndpointId"], type="aws.ec2.vpce",
              name=t.get("Name") or short or e["VpcEndpointId"],
              parent=c.parent_for_subnets(e.get("SubnetIds") or []) if e.get("SubnetIds")
              else c.vpc_or_region(e.get("VpcId")),
              tags=t, created=e.get("CreationTimestamp"), props={"service": e.get("ServiceName"), "type": e.get("VpcEndpointType")})

    # routing: subnet -> gateway edges, and "public subnet" detection
    main_rt: dict[str, dict] = {}
    subnet_rt: dict[str, dict] = {}
    for rt in _pages(ec2, "describe_route_tables", "RouteTables"):
        for a in rt.get("Associations", []):
            if a.get("Main"):
                main_rt[rt["VpcId"]] = rt
            elif a.get("SubnetId"):
                subnet_rt[a["SubnetId"]] = rt
    for sid, s in subnets.items():
        rt = subnet_rt.get(sid) or main_rt.get(s.get("VpcId"))
        for route in (rt or {}).get("Routes", []):
            tgt = (route.get("GatewayId") or route.get("NatGatewayId")
                   or route.get("TransitGatewayId") or route.get("VpcEndpointId"))
            if not tgt or tgt == "local" or route.get("State") == "blackhole":
                continue
            dest = (route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
                    or route.get("DestinationPrefixListId") or "")
            if tgt.startswith("igw-") and dest in DEFAULT_ROUTES:
                g.resources[sid].props["public"] = True
            g.link(sid, tgt, "route", dest)

    for pcx in _pages(ec2, "describe_vpc_peering_connections", "VpcPeeringConnections"):
        if (pcx.get("Status") or {}).get("Code") == "active":
            g.link(pcx["RequesterVpcInfo"]["VpcId"], pcx["AccepterVpcInfo"]["VpcId"],
                   "peering", "VPC peering")

    for tgw in _pages(ec2, "describe_transit_gateways", "TransitGateways"):
        if tgw.get("State") in ("deleted", "deleting"):
            continue
        t = _tags(tgw.get("Tags"))
        c.add(id=tgw["TransitGatewayId"], type="aws.ec2.tgw",
              name=t.get("Name") or tgw["TransitGatewayId"], parent=c.region_id, tags=t,
              arn=tgw.get("TransitGatewayArn"), created=tgw.get("CreationTime"), props={"state": tgw.get("State")})
    for att in _pages(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments"):
        if att.get("ResourceType") == "vpc" and att.get("State") not in ("deleted", "deleting"):
            g.link(att["TransitGatewayId"], att["ResourceId"], "attachment", "TGW attachment")


def collect_ec2(c: Ctx) -> None:
    ec2 = c.client("ec2")
    for res in _pages(ec2, "describe_instances", "Reservations"):
        for i in res.get("Instances", []):
            state = (i.get("State") or {}).get("Name")
            if state in ("terminated", "shutting-down"):
                continue
            t = _tags(i.get("Tags"))
            profile = ((i.get("IamInstanceProfile") or {}).get("Arn") or "").split("/")[-1]
            c.add(id=i["InstanceId"], type="aws.ec2.instance",
                  name=t.get("Name") or i["InstanceId"],
                  parent=c.parent_for_subnets([i.get("SubnetId")]) if i.get("SubnetId")
                  else c.region_id, tags=t, created=i.get("LaunchTime"),
                  arn=f"arn:{c.p.partition}:ec2:{c.region}:{c.g.account}:instance/{i['InstanceId']}",
                  props={"state": state, "instance_type": i.get("InstanceType"),
                         "az": (i.get("Placement") or {}).get("AvailabilityZone"),
                         "private_ip": i.get("PrivateIpAddress"),
                         "public_ip": i.get("PublicIpAddress"), "ami": i.get("ImageId"),
                         "iam_profile": profile,
                         "security_groups": [sg["GroupId"] for sg in i.get("SecurityGroups", [])]})
            prof_arn = (i.get("IamInstanceProfile") or {}).get("Arn")
            if prof_arn:                      # profile ARN is aliased to its role by the IAM collector
                c.g.link(i["InstanceId"], prof_arn, "identity", "instance profile")


def collect_autoscaling(c: Ctx) -> None:
    asg = c.client("autoscaling")
    for a in _pages(asg, "describe_auto_scaling_groups", "AutoScalingGroups"):
        subnet_ids = [s for s in (a.get("VPCZoneIdentifier") or "").split(",") if s]
        rid = f"asg:{c.region}:{a['AutoScalingGroupName']}"
        c.add(id=rid, type="aws.autoscaling.group", name=a["AutoScalingGroupName"],
              parent=c.parent_for_subnets(subnet_ids, level="vpc"),
              arn=a.get("AutoScalingGroupARN"), tags=_tags(a.get("Tags")),
              created=a.get("CreatedTime"),
              props={"min": a.get("MinSize"), "max": a.get("MaxSize"),
                     "desired": a.get("DesiredCapacity"),
                     "instances": len(a.get("Instances", []))})
        for inst in a.get("Instances", []):
            c.g.link(rid, inst["InstanceId"], "manages", "launches")


def collect_elbv2(c: Ctx) -> None:
    elb = c.client("elbv2")
    kind = {"application": "aws.elbv2.alb", "network": "aws.elbv2.nlb", "gateway": "aws.elbv2.gwlb"}
    by_arn: dict[str, str] = {}
    for lb in _pages(elb, "describe_load_balancers", "LoadBalancers"):
        rid = f"lb:{c.region}:{lb['LoadBalancerName']}"
        by_arn[lb["LoadBalancerArn"]] = rid
        azs = [z.get("ZoneName") for z in lb.get("AvailabilityZones", [])]
        c.add(id=rid, type=kind.get(lb.get("Type"), "aws.elbv2.alb"), name=lb["LoadBalancerName"],
              parent=c.vpc_or_region(lb.get("VpcId")), arn=lb["LoadBalancerArn"],
              created=lb.get("CreatedTime"),
              props={"scheme": lb.get("Scheme"), "dns": lb.get("DNSName"), "azs": azs,
                     "state": (lb.get("State") or {}).get("Code")})
        if lb.get("DNSName"):
            c.g.dns_index[lb["DNSName"].lower()] = rid

    for tg in _pages(elb, "describe_target_groups", "TargetGroups"):
        lbs = [by_arn[a] for a in tg.get("LoadBalancerArns", []) if a in by_arn]
        if not lbs:
            continue
        c.shared["tg"][tg["TargetGroupArn"]] = lbs
        label = f"{tg['TargetGroupName']}:{tg.get('Port', '')}".rstrip(":")
        try:
            health = elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
        except ClientError:
            continue
        for d in health.get("TargetHealthDescriptions", []):
            target = (d.get("Target") or {}).get("Id", "")
            if target.startswith("i-") or target.startswith("arn:aws:lambda"):
                for lb_id in lbs:
                    c.g.link(lb_id, target, "traffic", label)


def collect_rds(c: Ctx) -> None:
    rds = c.client("rds")
    for d in _pages(rds, "describe_db_instances", "DBInstances"):
        subnets = [s["SubnetIdentifier"] for s in (d.get("DBSubnetGroup") or {}).get("Subnets", [])]
        rid = f"rds:{c.region}:{d['DBInstanceIdentifier']}"
        c.add(id=rid, type="aws.rds.instance", name=d["DBInstanceIdentifier"],
              parent=c.parent_for_subnets(subnets), arn=d.get("DBInstanceArn"),
              created=d.get("InstanceCreateTime"),
              props={"engine": f"{d.get('Engine', '')} {d.get('EngineVersion', '')}".strip(),
                     "class": d.get("DBInstanceClass"), "multi_az": d.get("MultiAZ"),
                     "storage_gb": d.get("AllocatedStorage"), "status": d.get("DBInstanceStatus"),
                     "publicly_accessible": d.get("PubliclyAccessible"),
                     "encrypted": d.get("StorageEncrypted"),
                     "endpoint": (d.get("Endpoint") or {}).get("Address")})
        src = d.get("ReadReplicaSourceDBInstanceIdentifier")
        if src:
            c.g.link(f"rds:{c.region}:{src}", rid, "replication", "read replica")
        link_kms(c, d.get("KmsKeyId"), rid, "storage encryption")
        if (d.get("MasterUserSecret") or {}).get("SecretArn"):
            c.g.link(rid, d["MasterUserSecret"]["SecretArn"], "uses", "master credentials")
        if d.get("MonitoringRoleArn"):
            c.g.link(rid, d["MonitoringRoleArn"], "identity", "monitoring role")


def collect_elasticache(c: Ctx) -> None:
    ec = c.client("elasticache")
    groups = {g["CacheSubnetGroupName"]: [s["SubnetIdentifier"] for s in g.get("Subnets", [])]
              for g in _pages(ec, "describe_cache_subnet_groups", "CacheSubnetGroups")}
    for d in _pages(ec, "describe_cache_clusters", "CacheClusters"):
        rid = f"cache:{c.region}:{d['CacheClusterId']}"
        c.add(id=rid, type="aws.elasticache.cluster", name=d["CacheClusterId"],
              parent=c.parent_for_subnets(groups.get(d.get("CacheSubnetGroupName"), [])),
              arn=d.get("ARN"), created=d.get("CacheClusterCreateTime"),
              props={"engine": f"{d.get('Engine', '')} {d.get('EngineVersion', '')}".strip(),
                     "node_type": d.get("CacheNodeType"), "nodes": d.get("NumCacheNodes"),
                     "status": d.get("CacheClusterStatus")})


def collect_lambda(c: Ctx) -> None:
    lam = c.client("lambda")
    for f in _pages(lam, "list_functions", "Functions"):
        subnets = (f.get("VpcConfig") or {}).get("SubnetIds") or []
        c.add(id=f"lambda:{c.region}:{f['FunctionName']}", type="aws.lambda.function",
              name=f["FunctionName"], parent=c.parent_for_subnets(subnets), arn=f["FunctionArn"], created=f.get("LastModified"),
              props={"date_basis": "last modified", "runtime": f.get("Runtime"), "memory_mb": f.get("MemorySize"),
                     "timeout_s": f.get("Timeout"), "handler": f.get("Handler"),
                     "in_vpc": bool(subnets), "role": (f.get("Role") or "").split("/")[-1]})
        fid = f"lambda:{c.region}:{f['FunctionName']}"
        if f.get("Role"):
            c.g.link(fid, f["Role"], "identity", "execution role")
        link_kms(c, f.get("KMSKeyArn"), fid, "env encryption")
        # NOTE: environment variables are deliberately not read.
    for m in _pages(lam, "list_event_source_mappings", "EventSourceMappings"):
        if m.get("EventSourceArn") and m.get("FunctionArn"):
            c.g.link(m["EventSourceArn"], m["FunctionArn"], "trigger", "event source")


def collect_ecs(c: Ctx) -> None:
    ecs = c.client("ecs")
    arns = list(_pages(ecs, "list_clusters", "clusterArns"))
    for i in range(0, len(arns), 100):
        for cl in ecs.describe_clusters(clusters=arns[i:i + 100]).get("clusters", []):
            cid = f"ecs:{c.region}:{cl['clusterName']}"
            c.add(id=cid, type="aws.ecs.cluster", name=cl["clusterName"], parent=c.region_id,
                  arn=cl.get("clusterArn"),
                  props={"status": cl.get("status"), "services": cl.get("activeServicesCount"),
                         "running_tasks": cl.get("runningTasksCount")})
            svc_arns = list(_pages(ecs, "list_services", "serviceArns", cluster=cl["clusterArn"]))
            for j in range(0, len(svc_arns), 10):
                described = ecs.describe_services(cluster=cl["clusterArn"], services=svc_arns[j:j + 10])
                for s in described.get("services", []):
                    net = (s.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
                    sid = f"ecsvc:{c.region}:{cl['clusterName']}:{s['serviceName']}"
                    c.add(id=sid, type="aws.ecs.service", name=s["serviceName"],
                          parent=c.parent_for_subnets(net.get("subnets") or []),
                          arn=s.get("serviceArn"), created=s.get("createdAt"),
                          props={"launch_type": s.get("launchType"), "desired": s.get("desiredCount"),
                                 "running": s.get("runningCount"), "status": s.get("status")})
                    c.g.link(cid, sid, "contains", "")
                    _ecs_task_links(c, ecs, s.get("taskDefinition"), sid)
                    for lb in s.get("loadBalancers", []):
                        for lb_id in c.shared["tg"].get(lb.get("targetGroupArn"), []):
                            c.g.link(lb_id, sid, "traffic", lb.get("containerName", ""))


def _trim_secret_ref(arn: str) -> str:
    """ECS 'valueFrom' may append ':json-key:version-stage:version-id'; keep just the resource ARN."""
    parts = arn.split(":")
    if len(parts) < 6:
        return arn
    return ":".join(parts[:7] if parts[2] == "secretsmanager" else parts[:6])


def _ecs_task_links(c: Ctx, ecs, td_arn: str | None, sid: str) -> None:
    """Which IAM roles and which secrets/parameters does this ECS service's task definition reference?
    (Only the references are read: never environment values or secret contents.)"""
    if not td_arn:
        return
    cache = c.shared.setdefault("td", {})
    if td_arn not in cache:
        try:
            cache[td_arn] = ecs.describe_task_definition(taskDefinition=td_arn)["taskDefinition"]
        except (ClientError, BotoCoreError):
            cache[td_arn] = {}
    td = cache[td_arn]
    if td.get("taskRoleArn"):
        c.g.link(sid, td["taskRoleArn"], "identity", "task role")
    if td.get("executionRoleArn"):
        c.g.link(sid, td["executionRoleArn"], "identity", "execution role")
    for cd in td.get("containerDefinitions", []):
        for sec in cd.get("secrets", []):
            ref = sec.get("valueFrom", "")
            if ref.startswith("arn:"):
                c.g.link(sid, _trim_secret_ref(ref), "uses", "secret" if ":secretsmanager:" in ref else "parameter")


def collect_eks(c: Ctx) -> None:
    eks = c.client("eks")
    for name in _pages(eks, "list_clusters", "clusters"):
        cl = eks.describe_cluster(name=name)["cluster"]
        vpc = (cl.get("resourcesVpcConfig") or {})
        cid = f"eks:{c.region}:{name}"
        c.add(id=cid, type="aws.eks.cluster", name=name, parent=c.vpc_or_region(vpc.get("vpcId")),
              arn=cl.get("arn"), tags=cl.get("tags") or {}, created=cl.get("createdAt"),
              props={"version": cl.get("version"), "status": cl.get("status"),
                     "public_endpoint": vpc.get("endpointPublicAccess"),
                     "private_endpoint": vpc.get("endpointPrivateAccess")})
        if cl.get("roleArn"):
            c.g.link(cid, cl["roleArn"], "identity", "cluster role")
        for enc in cl.get("encryptionConfig") or []:
            link_kms(c, (enc.get("provider") or {}).get("keyArn"), cid, "secrets encryption")
        for r in c.g.snapshot():
            if r.type == "aws.ec2.instance" and r.region == c.region and (
                    r.tags.get("eks:cluster-name") == name or r.tags.get("aws:eks:cluster-name") == name):
                c.g.link(cid, r.id, "manages", "worker node")


def collect_dynamodb(c: Ctx) -> None:
    ddb = c.client("dynamodb")
    for name in _pages(ddb, "list_tables", "TableNames"):
        t = ddb.describe_table(TableName=name)["Table"]
        rid = f"ddb:{c.region}:{name}"
        c.add(id=rid, type="aws.dynamodb.table", name=name, parent=c.region_id, arn=t.get("TableArn"), created=t.get("CreationDateTime"),
              props={"billing": (t.get("BillingModeSummary") or {}).get("BillingMode", "PROVISIONED"),
                     "items": t.get("ItemCount"), "size_bytes": t.get("TableSizeBytes"),
                     "status": t.get("TableStatus"),
                     "stream": bool(t.get("StreamSpecification", {}).get("StreamEnabled"))})
        if t.get("LatestStreamArn"):
            c.g.alias(t["LatestStreamArn"], rid)
        link_kms(c, (t.get("SSEDescription") or {}).get("KMSMasterKeyArn"), rid, "table encryption")


def collect_sqs(c: Ctx) -> None:
    sqs = c.client("sqs")
    for url in _pages(sqs, "list_queues", "QueueUrls"):
        name = url.rsplit("/", 1)[-1]
        try:
            attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
        except ClientError:
            attrs = {}
        rid = f"sqs:{c.region}:{name}"
        c.add(id=rid, type="aws.sqs.queue", name=name, parent=c.region_id, arn=attrs.get("QueueArn"), created=attrs.get("CreatedTimestamp"),
              props={"fifo": name.endswith(".fifo"),
                     "messages": attrs.get("ApproximateNumberOfMessages"),
                     "visibility_timeout_s": attrs.get("VisibilityTimeout")})
        if attrs.get("RedrivePolicy"):
            try:
                dlq = json.loads(attrs["RedrivePolicy"]).get("deadLetterTargetArn")
            except ValueError:
                dlq = None
            if dlq:
                c.g.link(rid, dlq, "dead-letter", "dead-letter queue")
        link_kms(c, attrs.get("KmsMasterKeyId"), rid)
        if attrs.get("Policy"):
            apply_resource_policy(c.g, rid, attrs["Policy"], "queue policy")


def collect_sns(c: Ctx) -> None:
    sns = c.client("sns")
    for t in _pages(sns, "list_topics", "Topics"):
        arn = t["TopicArn"]
        rid = f"sns:{c.region}:{arn.rsplit(':', 1)[-1]}"
        subs = list(_pages(sns, "list_subscriptions_by_topic", "Subscriptions", TopicArn=arn))
        c.add(id=rid, type="aws.sns.topic", name=arn.rsplit(":", 1)[-1], parent=c.region_id, arn=arn,
              props={"subscriptions": len(subs)})
        try:
            attrs = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
        except (ClientError, BotoCoreError):
            attrs = {}
        link_kms(c, attrs.get("KmsMasterKeyId"), rid)
        if attrs.get("Policy"):
            apply_resource_policy(c.g, rid, attrs["Policy"], "topic policy")
        for s in subs:   # only wire up AWS-internal endpoints; emails/URLs are never stored
            if s.get("Protocol") in ("sqs", "lambda") and str(s.get("Endpoint", "")).startswith("arn:"):
                c.g.link(rid, s["Endpoint"], "event", s["Protocol"])


_LAMBDA_URI = re.compile(r"(arn:aws[a-z-]*:lambda:[^/]+:function:[^/:]+)")


def collect_apigateway(c: Ctx) -> None:
    v2 = c.client("apigatewayv2")
    for api in _pages(v2, "get_apis", "Items"):
        rid = f"apigw:{c.region}:{api['ApiId']}"
        c.add(id=rid, type="aws.apigateway.http", name=api.get("Name") or api["ApiId"],
              parent=c.region_id, created=api.get("CreatedDate"),
              props={"protocol": api.get("ProtocolType"), "endpoint": api.get("ApiEndpoint")})
        c.g.dns_index[f"{api['ApiId']}.execute-api.{c.region}.amazonaws.com"] = rid
        try:
            for integ in _pages(v2, "get_integrations", "Items", ApiId=api["ApiId"]):
                m = _LAMBDA_URI.search(str(integ.get("IntegrationUri", "")))
                if m:
                    c.g.link(rid, m.group(1), "invoke", integ.get("IntegrationType", ""))
        except ClientError:
            pass

    rest = c.client("apigateway")
    for api in _pages(rest, "get_rest_apis", "items"):
        rid = f"apigw:{c.region}:{api['id']}"
        c.add(id=rid, type="aws.apigateway.rest", name=api.get("name") or api["id"],
              parent=c.region_id, created=api.get("createdDate"),
              props={"endpoint_type": ",".join((api.get("endpointConfiguration") or {}).get("types", []))})
        c.g.dns_index[f"{api['id']}.execute-api.{c.region}.amazonaws.com"] = rid
        calls = 0
        try:
            for res in _pages(rest, "get_resources", "items", restApiId=api["id"]):
                for method in (res.get("resourceMethods") or {}):
                    if calls >= API_CALL_CAP:
                        break
                    calls += 1
                    m = rest.get_integration(restApiId=api["id"], resourceId=res["id"], httpMethod=method)
                    hit = _LAMBDA_URI.search(str(m.get("uri", "")))
                    if hit:
                        c.g.link(rid, hit.group(1), "invoke", method)
        except ClientError:
            pass


# ---- account-wide (global) collectors; run once, after all regions
def collect_s3(p: "AWSProvider", g: Graph, account_id: str) -> None:
    s3 = p.client("s3", p.home_region)
    buckets = s3.list_buckets().get("Buckets", [])[:MAX_ITEMS]

    def inspect(b: dict) -> None:
        name = b["Name"]
        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
        except ClientError:
            loc = None
        region = {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(loc, loc)
        parent = f"region:{region}" if region in p.regions else account_id
        bucket = g.add(Resource(id=f"s3:{name}", type="aws.s3.bucket", name=name, parent=parent, region=region,
                                arn=f"arn:{p.partition}:s3:::{name}", created=b.get("CreationDate")))
        rc = p.client("s3", region)
        try:                                   # default encryption: SSE-S3 or a KMS key
            rule = (rc.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"] or [{}])[0]
            default = rule.get("ApplyServerSideEncryptionByDefault") or {}
            bucket.props["encryption"] = default.get("SSEAlgorithm")
            if default.get("KMSMasterKeyID"):
                ref = default["KMSMasterKeyID"]
                if not ref.startswith("arn:"):
                    ref = f"arn:{p.partition}:kms:{region}:{g.account}:" + (ref if ref.startswith("alias/") else f"key/{ref}")
                g.link(ref, f"s3:{name}", "encrypts", "bucket default encryption")
        except (ClientError, BotoCoreError):
            pass
        try:
            apply_resource_policy(g, f"s3:{name}", rc.get_bucket_policy(Bucket=name).get("Policy"), "bucket policy")
        except (ClientError, BotoCoreError):
            pass                               # most buckets simply have no policy
        try:
            cfg = rc.get_bucket_notification_configuration(Bucket=name)
        except (ClientError, BotoCoreError):
            return
        for key, arn_key in (("LambdaFunctionConfigurations", "LambdaFunctionArn"),
                             ("QueueConfigurations", "QueueArn"), ("TopicConfigurations", "TopicArn")):
            for n in cfg.get(key, []):
                g.link(f"s3:{name}", n[arn_key], "event", ", ".join(n.get("Events", []))[:60])

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(inspect, buckets))


def collect_cloudfront(p: "AWSProvider", g: Graph, account_id: str) -> None:
    cf = p.client("cloudfront", "us-east-1")
    for page in cf.get_paginator("list_distributions").paginate():
        for d in (page.get("DistributionList") or {}).get("Items", []) or []:
            rid = f"cf:{d['Id']}"
            g.add(Resource(id=rid, type="aws.cloudfront.distribution", name=d.get("DomainName", d["Id"]),
                           parent=account_id, arn=d.get("ARN"), created=d.get("LastModifiedTime"),
                           props={"date_basis": "last modified", "aliases": (d.get("Aliases") or {}).get("Items"),
                                  "status": d.get("Status"), "enabled": d.get("Enabled")}))
            for o in (d.get("Origins") or {}).get("Items", []):
                dom = o.get("DomainName", "").lower()
                if ".s3" in dom and dom.endswith("amazonaws.com"):
                    g.link(rid, f"s3:{dom.split('.s3')[0]}", "origin", "S3 origin")
                else:
                    target = g.dns_index.get(dom.removeprefix("dualstack."))
                    if target:
                        g.link(rid, target, "origin", "origin")


# ---- identity & security (regional): KMS keys, secrets, parameters
def collect_kms(c: Ctx) -> None:
    kms = c.client("kms")
    aliases: dict[str, list[str]] = defaultdict(list)
    for a in _pages(kms, "list_aliases", "Aliases"):
        if a.get("TargetKeyId"):
            aliases[a["TargetKeyId"]].append(a["AliasName"])
    for k in _pages(kms, "list_keys", "Keys"):
        try:
            d = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
        except (ClientError, BotoCoreError):
            continue
        managed = d.get("KeyManager") == "AWS"
        if managed and not c.p.include_aws_managed_keys:
            continue                       # aws/s3, aws/ebs ... : dozens of boxes nobody manages
        names = aliases.get(k["KeyId"], [])
        rotation = None
        if not managed and d.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT" and d.get("Origin") == "AWS_KMS":
            try:
                rotation = kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"]
            except (ClientError, BotoCoreError):
                pass
        rid = f"kms:{c.region}:{k['KeyId']}"
        c.add(id=rid, type="aws.kms.key", name=names[0].removeprefix("alias/") if names else k["KeyId"],
              parent=c.region_id, arn=d.get("Arn") or k.get("KeyArn"), created=d.get("CreationDate"),
              props={"state": d.get("KeyState"), "managed_by": "AWS" if managed else "customer",
                     "usage": d.get("KeyUsage"), "spec": d.get("KeySpec") or d.get("CustomerMasterKeySpec"),
                     "rotation_enabled": rotation, "multi_region": d.get("MultiRegion"),
                     "origin": d.get("Origin"), "aliases": names, "description": d.get("Description"),
                     "scheduled_deletion": d.get("DeletionDate")})
        for n in names:                    # resources reference keys by alias as often as by id
            c.g.alias(f"arn:{c.p.partition}:kms:{c.region}:{c.g.account}:{n}", rid)
        try:
            apply_resource_policy(c.g, rid, kms.get_key_policy(KeyId=k["KeyId"], PolicyName="default")["Policy"], "key policy")
        except (ClientError, BotoCoreError):
            pass


def collect_secrets(c: Ctx) -> None:
    """Secret *metadata* only. get_secret_value is never called, so no secret content is read."""
    sm = c.client("secretsmanager")
    for s in _pages(sm, "list_secrets", "SecretList"):
        rid = f"secret:{c.region}:{s['Name']}"
        c.add(id=rid, type="aws.secretsmanager.secret", name=s["Name"], parent=c.region_id, arn=s["ARN"],
              created=s.get("CreatedDate"), tags=_tags(s.get("Tags")),
              props={"description": s.get("Description"), "rotation_enabled": bool(s.get("RotationEnabled")),
                     "rotation_days": (s.get("RotationRules") or {}).get("AutomaticallyAfterDays"),
                     "last_rotated": s.get("LastRotatedDate"), "last_changed": s.get("LastChangedDate"),
                     "last_accessed": s.get("LastAccessedDate"),
                     "kms_key": s.get("KmsKeyId") or "aws/secretsmanager (default)",
                     "owning_service": s.get("OwningService"), "scheduled_deletion": s.get("DeletedDate")})
        link_kms(c, s.get("KmsKeyId"), rid, "secret encryption")
        try:
            policy = sm.get_resource_policy(SecretId=s["ARN"]).get("ResourcePolicy")
            if policy:
                apply_resource_policy(c.g, rid, policy, "secret policy")
        except (ClientError, BotoCoreError):
            pass


def collect_ssm(c: Ctx) -> None:
    """Parameter Store metadata only: names, types, key ids. Values are never requested."""
    ssm = c.client("ssm")
    n = 0
    for pm in _pages(ssm, "describe_parameters", "Parameters"):
        n += 1
        name = pm["Name"]
        rid = f"ssm:{c.region}:{name}"
        c.add(id=rid, type="aws.ssm.parameter", name=name, parent=c.region_id,
              arn=pm.get("ARN") or f"arn:{c.p.partition}:ssm:{c.region}:{c.g.account}:parameter/{name.lstrip('/')}",
              created=pm.get("LastModifiedDate"),
              props={"date_basis": "last modified", "type": pm.get("Type"), "tier": pm.get("Tier"),
                     "version": pm.get("Version"), "description": pm.get("Description"),
                     "kms_key": pm.get("KeyId") if pm.get("Type") == "SecureString" else None})
        if pm.get("Type") == "SecureString":
            link_kms(c, pm.get("KeyId") or "alias/aws/ssm", rid, "parameter encryption")
    if n >= MAX_ITEMS:
        c.g.warn(f"ssm ({c.region}): stopped after {MAX_ITEMS} parameters")


# ---- identity & security (account-wide): IAM users, groups, roles and what they can reach
def _credential_report(iam, g: Graph) -> dict[str, dict]:
    """The IAM credential report is one CSV about every user (MFA, key age, last use) - no secrets in it."""
    for _ in range(10):
        try:
            rep = iam.get_credential_report()
            return {r["user"]: r for r in csv.DictReader(io.StringIO(rep["Content"].decode("utf-8", "replace")))}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("ReportNotPresent", "ReportExpired"):
                try:
                    iam.generate_credential_report()
                except (ClientError, BotoCoreError):
                    break
            elif code != "ReportInProgress":
                break
            time.sleep(1.0)
    g.warn("iam: credential report unavailable - MFA / access-key details skipped")
    return {}


def _days_since(ts: Any) -> int | None:
    iso = parse_time(ts)
    return (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).days if iso else None


def _fetch_managed_docs(iam, arns: set[str], g: Graph) -> dict[str, Any]:
    def one(arn: str):
        try:
            pol = iam.get_policy(PolicyArn=arn)["Policy"]
            return arn, iam.get_policy_version(PolicyArn=arn, VersionId=pol["DefaultVersionId"])["PolicyVersion"]["Document"]
        except (ClientError, BotoCoreError):
            g.warn(f"iam: could not read AWS-managed policy {arn.rsplit('/', 1)[-1]}")
            return arn, None
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(pool.map(one, sorted(arns)))


def _norm_pattern(pat: str) -> str:
    """Map an IAM resource pattern onto the ARN we index: object -> bucket, qualified function -> function."""
    parts = pat.split(":")
    if len(parts) >= 6:
        svc = parts[2]
        if svc == "s3" and "/" in pat:
            return pat.split("/", 1)[0]
        if svc == "lambda" and len(parts) > 7 and parts[5] == "function":
            return ":".join(parts[:7])
        if svc == "dynamodb":
            return re.split(r"/(?:index|stream|backup)/", pat, maxsplit=1)[0]
    return pat


def _grant_edges(p: "AWSProvider", g: Graph, pid: str, policies: list[tuple[str, Any]],
                 keys: list[str], ids_by_type: dict[str, list[str]], budget: list[int]) -> dict[str, Any]:
    """Turn one principal's policies into access edges (+ summary properties). Allow statements only."""
    acc: dict[str, dict] = {}
    broad: list[str] = []
    denies, admin = 0, False

    def add(tid: str, acts: list[str], cond: bool, pname: str) -> None:
        e = acc.setdefault(tid, {"actions": set(), "cond": True})
        e["actions"].update(acts)
        e["cond"] = e["cond"] and cond

    for pname, doc in policies:
        for st in iamlib.statements(doc):
            if st["effect"] == "Deny":
                denies += 1
                continue
            if st["effect"] != "Allow":
                continue
            if st["not_action"] or st["not_resource"]:
                broad.append(f"{pname}: uses NotAction/NotResource (not expanded)")
                continue
            actions, cond = st["actions"], st["conditional"]
            for pat in st["resources"]:
                if pat == "*":
                    services = {iamlib.service_of(a) for a in actions}
                    if "*" in services:
                        admin = admin or not cond
                        broad.append(f"{pname}: all actions on all resources" + (" (conditional)" if cond else ""))
                        continue
                    targets = [(t, svc) for svc in sorted(services) for typ in SERVICE_TYPES.get(svc, [])
                               for t in ids_by_type.get(typ, [])]
                    if targets and len(targets) <= p.max_wildcard_targets:
                        for tid, svc in targets:
                            add(tid, [a for a in actions if iamlib.service_of(a) in (svc, "*")], cond, pname)
                    else:
                        lv = ", ".join(iamlib.level_of(actions))
                        broad.append(f"{pname}: {', '.join(sorted(services))} ({lv}) on all resources"
                                     + (f" [{len(targets)} resources - too many to draw]" if targets else ""))
                    continue
                for key in iamlib.match_keys(_norm_pattern(pat), keys):
                    parts = key.split(":")
                    svc = parts[2] if len(parts) > 2 else ""
                    add(g.arn_index[key], [a for a in actions if iamlib.service_of(a) in (svc, "*")] or actions, cond, pname)

    for tid, e in acc.items():
        if tid == pid:
            continue
        if budget[0] <= 0:
            g.warn(f"iam: stopped drawing permission edges after {MAX_ACCESS_EDGES}")
            break
        budget[0] -= 1
        levels = ", ".join(iamlib.level_of(e["actions"]))
        g.link(pid, tid, "access", f"{levels}: {iamlib.summarize_actions(e['actions'])}" + (" · conditional" if e["cond"] else ""))
    return {"admin_access": True if admin else None, "broad_access": broad[:25], "deny_statements": denies or None}


def collect_iam(p: "AWSProvider", g: Graph, account_id: str) -> None:
    iam = p.client("iam", p.home_region)
    users, groups, roles, local = [], [], [], {}
    for page in iam.get_paginator("get_account_authorization_details").paginate(
            Filter=["User", "Role", "Group", "LocalManagedPolicy"]):
        users += page.get("UserDetailList", [])
        groups += page.get("GroupDetailList", [])
        roles += page.get("RoleDetailList", [])
        for pol in page.get("Policies", []):
            local[pol["Arn"]] = pol
    if not p.include_service_roles:
        roles = [r for r in roles if not (r.get("Path") or "").startswith("/aws-service-role/")]
    users, groups, roles = users[:MAX_ITEMS], groups[:MAX_ITEMS], roles[:MAX_ITEMS]

    attached = {a["PolicyArn"] for ent in users + groups + roles for a in ent.get("AttachedManagedPolicies", [])}
    managed_docs = _fetch_managed_docs(iam, attached - set(local), g)

    def policy_doc(arn: str) -> Any:
        if arn in local:
            versions = local[arn].get("PolicyVersionList", [])
            v = next((x for x in versions if x.get("IsDefaultVersion")), versions[0] if versions else None)
            return v.get("Document") if v else None
        return managed_docs.get(arn)

    def policies_of(ent: dict, inline_key: str) -> list[tuple[str, Any]]:
        out = []
        for a in ent.get("AttachedManagedPolicies", []):
            tag = " (AWS managed)" if a["PolicyArn"].startswith("arn:aws:iam::aws:") else ""
            out.append((a["PolicyName"] + tag, policy_doc(a["PolicyArn"])))
        for ip in ent.get(inline_key, []):
            out.append((f"{ip['PolicyName']} (inline)", ip.get("PolicyDocument")))
        return out

    cred = _credential_report(iam, g)
    root = cred.get("<root_account>")
    if root and account_id in g.resources:
        g.resources[account_id].props.update(
            root_mfa_enabled=root.get("mfa_active") == "true",
            root_access_keys_active=sum(root.get(f"access_key_{i}_active") == "true" for i in (1, 2)))

    iam_box = f"{account_id}:iam"
    g.add(Resource(id=iam_box, type="aws.iam", name="Identity & Access (IAM)", parent=account_id,
                   container=True, prune_empty=True))
    entities: list[tuple[str, dict, str, list[tuple[str, Any]]]] = []   # (node id, raw, kind, policies)

    for u in users:
        row, uid = cred.get(u["UserName"], {}), f"iam:user:{u['UserName']}"
        keys_active = sum(row.get(f"access_key_{i}_active") == "true" for i in (1, 2))
        ages = [_days_since(row.get(f"access_key_{i}_last_rotated")) for i in (1, 2) if row.get(f"access_key_{i}_active") == "true"]
        pols = policies_of(u, "UserPolicyList")
        g.add(Resource(id=uid, type="aws.iam.user", name=u["UserName"], parent=iam_box, arn=u.get("Arn"),
                       created=u.get("CreateDate"), tags=_tags(u.get("Tags")),
                       props={"path": u.get("Path"), "groups": u.get("GroupList"),
                              "console_access": (row.get("password_enabled") == "true") if row else None,
                              "mfa_enabled": (row.get("mfa_active") == "true") if row else None,
                              "active_access_keys": keys_active if row else None,
                              "oldest_access_key_days": max((a for a in ages if a is not None), default=None),
                              "permissions_boundary": (u.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
                              "policies": [n for n, _ in pols]}))
        entities.append((uid, u, "user", pols))
    for gr in groups:
        gid, pols = f"iam:group:{gr['GroupName']}", policies_of(gr, "GroupPolicyList")
        g.add(Resource(id=gid, type="aws.iam.group", name=gr["GroupName"], parent=iam_box, arn=gr.get("Arn"),
                       created=gr.get("CreateDate"), props={"path": gr.get("Path"), "policies": [n for n, _ in pols]}))
        entities.append((gid, gr, "group", pols))
    for r in roles:
        rid, pols = f"iam:role:{r['RoleName']}", policies_of(r, "RolePolicyList")
        last = (r.get("RoleLastUsed") or {}).get("LastUsedDate")
        g.add(Resource(id=rid, type="aws.iam.role", name=r["RoleName"], parent=iam_box, arn=r.get("Arn"),
                       created=r.get("CreateDate"), tags=_tags(r.get("Tags")),
                       props={"path": r.get("Path"), "last_used": last, "unused_days": _days_since(last) if last else None,
                              "permissions_boundary": (r.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
                              "policies": [n for n, _ in pols]}))
        for ip in r.get("InstanceProfileList", []):
            g.alias(ip["Arn"], rid)           # EC2 instances point at the profile; the profile resolves to the role
        entities.append((rid, r, "role", pols))

    # group membership and role trust
    for uid, u, kind, _ in entities:
        if kind == "user":
            for gn in u.get("GroupList", []):
                g.link(uid, f"iam:group:{gn}", "member", "member of")
    for rid, r, kind, _ in entities:
        if kind != "role":
            continue
        trusted_services, trusted_other, public, conditional = set(), set(), False, False
        for st in iamlib.statements(r.get("AssumeRolePolicyDocument")):
            if st["effect"] != "Allow":
                continue
            conditional = conditional or st["conditional"]
            for ptype, values in st["principals"].items():
                for v in values:
                    if ptype == "Service":
                        trusted_services.add(v)
                    elif ptype == "Federated":
                        trusted_other.add(f"federated: {v.rsplit('/', 1)[-1]}")
                    elif v == "*":
                        public = public or not st["conditional"]
                    else:
                        arn = v if v.startswith("arn:") else f"arn:aws:iam::{v}:root"
                        acct = arn.split(":")[4] if arn.count(":") > 4 else ""
                        if arn.endswith(":root"):
                            trusted_other.add(f"account {acct}" + (" (this account)" if acct == g.account else " (EXTERNAL)"))
                        elif acct != g.account:
                            trusted_other.add(f"external principal {arn.rsplit(':', 1)[-1]} in account {acct} (EXTERNAL)")
                        else:
                            g.link(arn, rid, "assume", "can assume")
        res = g.resources[rid]
        res.props.update(trusted_services=sorted(trusted_services) or None, trusted_principals=sorted(trusted_other) or None,
                         trust_public=True if public else None, trust_has_conditions=True if conditional else None)

    # what each principal can reach
    keys = list(g.arn_index)
    ids_by_type: dict[str, list[str]] = defaultdict(list)
    for r in g.snapshot():
        ids_by_type[r.type].append(r.id)
    budget = [MAX_ACCESS_EDGES]
    for pid, _raw, _kind, pols in entities:
        g.resources[pid].props.update(_grant_edges(p, g, pid, pols, keys, ids_by_type, budget))


REGIONAL = {
    "vpc": collect_vpc, "ec2": collect_ec2, "autoscaling": collect_autoscaling,
    "elbv2": collect_elbv2, "rds": collect_rds, "elasticache": collect_elasticache,
    "lambda": collect_lambda, "ecs": collect_ecs, "eks": collect_eks,
    "dynamodb": collect_dynamodb, "sqs": collect_sqs, "sns": collect_sns,
    "apigateway": collect_apigateway, "kms": collect_kms, "secretsmanager": collect_secrets, "ssm": collect_ssm,
}
GLOBAL = {"s3": collect_s3, "cloudfront": collect_cloudfront, "iam": collect_iam}


# --------------------------------------------------------------------------- provider
class AWSProvider(Provider):
    name = "aws"

    def __init__(self, profile: str | None = None, regions: list[str] | None = None,
                 role_arn: str | None = None, external_id: str | None = None,
                 services: list[str] | None = None, max_workers: int = 6,
                 endpoint_url: str | None = None, session: boto3.Session | None = None,
                 keep_default_vpcs: bool = False, include_aws_managed_keys: bool = False,
                 include_service_roles: bool = False, max_wildcard_targets: int = 30,
                 log: Callable[[str], None] | None = None):
        super().__init__(log)
        self.keep_default_vpcs = keep_default_vpcs
        self.include_aws_managed_keys = include_aws_managed_keys
        self.include_service_roles = include_service_roles
        self.max_wildcard_targets = max_wildcard_targets
        self.partition = "aws"                 # refined from the caller identity in discover()
        self.requested_regions = regions
        self.services = [s for s in (services or ALL_SERVICES)]
        self.max_workers = max_workers
        self.endpoint_url = endpoint_url
        self.session = session or boto3.Session(profile_name=profile)
        if role_arn:
            self.session = self._assume(role_arn, external_id)
        self.home_region = self.session.region_name or "us-east-1"
        self.regions: list[str] = []
        self._config = Config(retries={"max_attempts": 8, "mode": "adaptive"},
                              user_agent_extra="cloudmap/0.1 (read-only)")

    # -- CLI wiring ---------------------------------------------------------
    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--profile", help="AWS named profile (default: standard credential chain)")
        parser.add_argument("--regions", help="comma-separated regions (default: all enabled regions)")
        parser.add_argument("--role-arn", help="assume this role before scanning")
        parser.add_argument("--external-id", help="external id for --role-arn")
        parser.add_argument("--services", help=f"comma-separated subset of: {','.join(ALL_SERVICES)}")
        parser.add_argument("--workers", type=int, default=6, help="regions scanned in parallel")
        parser.add_argument("--endpoint-url", help="custom endpoint (e.g. LocalStack)")
        parser.add_argument("--keep-default-vpcs", action="store_true",
                            help="also draw default VPCs that contain no workloads (hidden by default)")
        parser.add_argument("--include-aws-managed-keys", action="store_true",
                            help="also draw AWS-managed KMS keys (aws/s3, aws/ebs ...); customer keys are always drawn")
        parser.add_argument("--include-service-roles", action="store_true",
                            help="also draw service-linked IAM roles (hidden by default)")
        parser.add_argument("--max-wildcard-targets", type=int, default=30,
                            help="a 'Resource: *' grant is drawn as edges only if it reaches at most this many "
                                 "resources; broader grants are listed in the principal's details (default 30)")

    @classmethod
    def from_args(cls, args, log):
        split = lambda v: [x.strip() for x in v.split(",") if x.strip()] if v else None  # noqa: E731
        services = split(args.services)
        unknown = set(services or []) - set(ALL_SERVICES)
        if unknown:
            raise SystemExit(f"Unknown service(s): {', '.join(sorted(unknown))}")
        return cls(profile=args.profile, regions=split(args.regions), role_arn=args.role_arn,
                   external_id=args.external_id, services=services, max_workers=args.workers,
                   endpoint_url=args.endpoint_url, keep_default_vpcs=args.keep_default_vpcs,
                   include_aws_managed_keys=args.include_aws_managed_keys,
                   include_service_roles=args.include_service_roles,
                   max_wildcard_targets=args.max_wildcard_targets, log=log)

    # -- plumbing -----------------------------------------------------------
    def _assume(self, role_arn: str, external_id: str | None) -> boto3.Session:
        kw = {"RoleArn": role_arn, "RoleSessionName": "cloudmap"}
        if external_id:
            kw["ExternalId"] = external_id
        creds = self.session.client("sts").assume_role(**kw)["Credentials"]
        return boto3.Session(aws_access_key_id=creds["AccessKeyId"],
                             aws_secret_access_key=creds["SecretAccessKey"],
                             aws_session_token=creds["SessionToken"],
                             region_name=self.session.region_name)

    def client(self, service: str, region: str):
        return self.session.client(service, region_name=region, config=self._config,
                                   endpoint_url=self.endpoint_url)

    def _resolve_regions(self) -> list[str]:
        if self.requested_regions:
            return self.requested_regions
        resp = self.client("ec2", self.home_region).describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])

    # -- main ---------------------------------------------------------------
    def discover(self) -> Graph:
        try:
            ident = self.client("sts", self.home_region).get_caller_identity()
        except NoCredentialsError:
            raise SystemExit("No AWS credentials found. Configure a profile, environment "
                             "variables or an SSO session, then retry.") from None
        except (ClientError, BotoCoreError) as e:
            raise SystemExit(f"Could not authenticate to AWS: {e}") from None
        account = ident["Account"]
        self.partition = (ident.get("Arn") or "arn:aws:").split(":")[1] or "aws"
        g = Graph("aws", account, TYPES)

        alias = ""
        try:
            aliases = self.client("iam", self.home_region).list_account_aliases()["AccountAliases"]
            alias = aliases[0] if aliases else ""
        except (ClientError, BotoCoreError):
            pass
        acct_id = f"aws:{account}"
        g.add(Resource(id=acct_id, type="aws.account", name=alias or f"AWS Account {account}",
                       container=True, props={"account_id": account, "principal": ident.get("Arn")}))

        self.regions = self._resolve_regions()
        self.log(f"Scanning {len(self.regions)} region(s): {', '.join(self.regions)}")
        for r in self.regions:
            g.add(Resource(id=f"region:{r}", type="aws.region", name=r, parent=acct_id, region=r,
                           container=True, prune_empty=True))

        wanted = [s for s in self.services if s in REGIONAL]
        with ThreadPoolExecutor(max_workers=max(1, self.max_workers)) as pool:
            list(pool.map(lambda r: self._scan_region(g, r, wanted), self.regions))

        for name in [s for s in self.services if s in GLOBAL]:
            self.log(f"Scanning global service: {name}")
            self._guard(g, name, "global", lambda n=name: GLOBAL[n](self, g, acct_id))

        g.finalize()
        self.log(f"Found {sum(not r.container for r in g.resources.values())} resources, "
                 f"{len(g.edges)} connections.")
        return g

    def _scan_region(self, g: Graph, region: str, services: list[str]) -> None:
        c = Ctx(self, region, g)
        for name in [s for s in ALL_SERVICES if s in services]:   # dependency order
            self._guard(g, name, region, lambda n=name: REGIONAL[n](c))
        if not self.keep_default_vpcs:
            self._drop_unused_default_vpcs(g, region)
        self.log(f"  done: {region}")

    @staticmethod
    def _drop_unused_default_vpcs(g: Graph, region: str) -> None:
        """Every region ships a default VPC; hide those that hold nothing but plumbing."""
        plumbing = {"aws.ec2.subnet", "aws.ec2.igw"}
        for vpc in [r for r in g.snapshot() if r.type == "aws.ec2.vpc" and r.region == region
                    and r.props.get("default")]:
            inside = {vpc.id}
            used = False
            for r in g.snapshot():           # parents are always added before children
                if r.parent in inside:
                    inside.add(r.id)
                    used = used or r.type not in plumbing
            if not used:
                g.remove(inside)

    def _guard(self, g: Graph, service: str, scope: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "ClientError")
            if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                        "AuthorizationError"):
                g.warn(f"{service} ({scope}): access denied - skipped")
            elif code in ("OptInRequired", "AuthFailure", "UnrecognizedClientException",
                          "InvalidClientTokenId", "SubscriptionRequiredException"):
                g.warn(f"{service} ({scope}): not enabled/available - skipped")
            else:
                g.warn(f"{service} ({scope}): {code}")
        except BotoCoreError as e:
            g.warn(f"{service} ({scope}): {type(e).__name__}")
