"""Demo mode: build a realistic fake AWS estate with moto, then scan it with the *real*
AWS provider. Nothing here touches a real account.   (requires: pip install moto)
"""
from __future__ import annotations

import io
import json
import os
import random
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Callable

REGION = "us-east-1"
REGION_2 = "eu-west-1"


def _zip_code() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def build_aws_environment(log: Callable[[str], None]) -> None:
    import boto3

    def optional(label: str, fn) -> None:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - demo data is best-effort across moto versions
            log(f"  (demo: skipped {label}: {type(e).__name__})")

    ec2 = boto3.client("ec2", region_name=REGION)
    tag = lambda n, **extra: [{"Key": "Name", "Value": n}, *[{"Key": k, "Value": v} for k, v in extra.items()]]  # noqa: E731

    def tagged(resource_type: str, name: str, **extra):
        return [{"ResourceType": resource_type, "Tags": tag(name, **extra)}]

    ident = _identity_layer()

    # ---- network ----
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=tagged("vpc", "prod-vpc", env="prod"))["Vpc"]["VpcId"]
    def subnet(name, cidr, az):
        return ec2.create_subnet(VpcId=vpc, CidrBlock=cidr, AvailabilityZone=az,
                                 TagSpecifications=tagged("subnet", name))["Subnet"]["SubnetId"]
    pub_a, pub_b = subnet("public-a", "10.0.1.0/24", f"{REGION}a"), subnet("public-b", "10.0.2.0/24", f"{REGION}b")
    app_a, app_b = subnet("app-a", "10.0.11.0/24", f"{REGION}a"), subnet("app-b", "10.0.12.0/24", f"{REGION}b")
    db_a, db_b = subnet("db-a", "10.0.21.0/24", f"{REGION}a"), subnet("db-b", "10.0.22.0/24", f"{REGION}b")

    igw = ec2.create_internet_gateway(TagSpecifications=tagged("internet-gateway", "prod-igw"))["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    eip = ec2.allocate_address(Domain="vpc")["AllocationId"]
    nat = ec2.create_nat_gateway(SubnetId=pub_a, AllocationId=eip,
                                 TagSpecifications=tagged("natgateway", "prod-nat"))["NatGateway"]["NatGatewayId"]

    rt_pub = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_pub, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    rt_priv = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_priv, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat)
    for s in (pub_a, pub_b):
        ec2.associate_route_table(RouteTableId=rt_pub, SubnetId=s)
    for s in (app_a, app_b):
        ec2.associate_route_table(RouteTableId=rt_priv, SubnetId=s)

    sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ami = ec2.describe_images()["Images"][0]["ImageId"]

    def instance(name, subnet_id, itype="t3.small", profile=None, **extra):
        kw = {"IamInstanceProfile": {"Name": profile}} if profile else {}
        return ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType=itype, SubnetId=subnet_id,
                                 TagSpecifications=tagged("instance", name, **extra), **kw)["Instances"][0]["InstanceId"]
    web1 = instance("web-1", pub_a, "t3.medium", profile="web-profile")
    web2 = instance("web-2", pub_b, "t3.medium", profile="web-profile")
    instance("bastion", pub_a, "t3.nano")
    instance("worker-1", app_b, "c5.xlarge")

    def asg():
        a = boto3.client("autoscaling", region_name=REGION)
        a.create_launch_configuration(LaunchConfigurationName="api-lc", ImageId=ami, InstanceType="m5.large")
        a.create_auto_scaling_group(AutoScalingGroupName="api-asg", LaunchConfigurationName="api-lc", MinSize=2, MaxSize=6,
                                    DesiredCapacity=2, VPCZoneIdentifier=f"{app_a},{app_b}",
                                    Tags=[{"Key": "Name", "Value": "api", "PropagateAtLaunch": True}])
    optional("autoscaling", asg)

    # shared services VPC, peered with prod
    vpc2 = ec2.create_vpc(CidrBlock="10.1.0.0/16", TagSpecifications=tagged("vpc", "shared-services"))["Vpc"]["VpcId"]
    sub2 = ec2.create_subnet(VpcId=vpc2, CidrBlock="10.1.1.0/24", AvailabilityZone=f"{REGION}a",
                             TagSpecifications=tagged("subnet", "tools-a"))["Subnet"]["SubnetId"]
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.small", SubnetId=sub2,
                      TagSpecifications=tagged("instance", "monitoring"))
    pcx = ec2.create_vpc_peering_connection(VpcId=vpc, PeerVpcId=vpc2)["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx)

    # ---- load balancer ----
    elb = boto3.client("elbv2", region_name=REGION)
    def alb():
        lb = elb.create_load_balancer(Name="prod-alb", Subnets=[pub_a, pub_b], SecurityGroups=[sg])["LoadBalancers"][0]
        tg = elb.create_target_group(Name="web-tg", Protocol="HTTP", Port=80, VpcId=vpc)["TargetGroups"][0]["TargetGroupArn"]
        elb.register_targets(TargetGroupArn=tg, Targets=[{"Id": web1}, {"Id": web2}])
        elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}])
    optional("alb", alb)

    # ---- data stores ----
    def rds():
        c = boto3.client("rds", region_name=REGION)
        c.create_db_subnet_group(DBSubnetGroupName="db", DBSubnetGroupDescription="db", SubnetIds=[db_a, db_b])
        c.create_db_instance(DBInstanceIdentifier="orders-db", DBInstanceClass="db.r5.large", Engine="postgres",
                             MasterUsername="admin", MasterUserPassword="demo-not-real-pw1", AllocatedStorage=100,
                             DBSubnetGroupName="db", MultiAZ=True, StorageEncrypted=True, KmsKeyId=ident["key_arn"])
        c.create_db_instance_read_replica(DBInstanceIdentifier="orders-db-replica", SourceDBInstanceIdentifier="orders-db",
                                          DBInstanceClass="db.r5.large")
    optional("rds", rds)

    def cache():
        c = boto3.client("elasticache", region_name=REGION)
        c.create_cache_cluster(CacheClusterId="sessions-cache", Engine="redis", CacheNodeType="cache.t3.small", NumCacheNodes=1)
    optional("elasticache", cache)

    ddb = boto3.client("dynamodb", region_name=REGION)
    for name in ("sessions", "orders"):
        optional(f"dynamodb {name}", lambda n=name: ddb.create_table(
            TableName=n, BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"} if n == "orders" else {"StreamEnabled": False},
            **({"SSESpecification": {"Enabled": True, "SSEType": "KMS", "KMSMasterKeyId": ident["key_arn"]}} if n == "orders" else {})))

    # ---- messaging + serverless ----
    sqs = boto3.client("sqs", region_name=REGION)
    dlq_url = sqs.create_queue(QueueName="orders-dlq")["QueueUrl"]
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    q_url = sqs.create_queue(QueueName="orders-queue", Attributes={
        "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 5}),
        "KmsMasterKeyId": "alias/app-data"})["QueueUrl"]
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    optional("queue policy", lambda: sqs.set_queue_attributes(QueueUrl=q_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": q_arn},
            {"Effect": "Allow", "Principal": {"AWS": ident["roles"]["order-processor-role"]},
             "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"], "Resource": q_arn}]})}))

    sns = boto3.client("sns", region_name=REGION)
    topic = sns.create_topic(Name="order-events", Attributes={"KmsMasterKeyId": "alias/app-data"})["TopicArn"]
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=q_arn)
    sns.subscribe(TopicArn=topic, Protocol="email", Endpoint="ops@example.com")   # never stored by the scanner

    role = ident["roles"]["lambda-role"]
    lam = boto3.client("lambda", region_name=REGION)
    def fn(name, vpc_subnets=None, role_arn=None):
        kw = {"VpcConfig": {"SubnetIds": vpc_subnets, "SecurityGroupIds": [sg]}} if vpc_subnets else {}
        return lam.create_function(FunctionName=name, Runtime="python3.12", Role=role_arn or role, Handler="index.handler",
                                   Code={"ZipFile": _zip_code()}, MemorySize=256, Timeout=30,
                                   Environment={"Variables": {"SECRET": "never-read-by-scanner"}}, **kw)["FunctionArn"]
    proc_arn = fn("order-processor", [app_a, app_b], ident["roles"]["order-processor-role"])
    thumb_arn = fn("thumbnailer")
    api_arn = fn("api-handler")
    optional("sqs->lambda mapping", lambda: lam.create_event_source_mapping(EventSourceArn=q_arn, FunctionName="order-processor"))
    optional("ddb stream->lambda mapping", lambda: lam.create_event_source_mapping(
        EventSourceArn=ddb.describe_table(TableName="orders")["Table"]["LatestStreamArn"],
        FunctionName="order-processor", StartingPosition="LATEST"))

    http = boto3.client("apigatewayv2", region_name=REGION)
    def api():
        a = http.create_api(Name="public-api", ProtocolType="HTTP")
        http.create_integration(ApiId=a["ApiId"], IntegrationType="AWS_PROXY", IntegrationUri=api_arn,
                                PayloadFormatVersion="2.0")
    optional("http api", api)

    # ---- containers ----
    def ecs_stack():
        ecs = boto3.client("ecs", region_name=REGION)
        ecs.create_cluster(clusterName="apps")
        ecs.register_task_definition(
            family="web", taskRoleArn=ident["roles"]["ecs-task-role"], executionRoleArn=ident["roles"]["ecs-exec-role"],
            containerDefinitions=[{"name": "web", "image": "nginx", "memory": 256, "secrets": [
                {"name": "STRIPE_KEY", "valueFrom": ident["api_secret_arn"] + ":key::"},
                {"name": "DB_URL", "valueFrom": ident["ssm_db_url_arn"]}]}])
        ecs.create_service(cluster="apps", serviceName="checkout", taskDefinition="web", desiredCount=2, launchType="FARGATE",
                           networkConfiguration={"awsvpcConfiguration": {"subnets": [app_a, app_b], "securityGroups": [sg]}})
    optional("ecs", ecs_stack)

    def eks_stack():
        eks = boto3.client("eks", region_name=REGION)
        eks.create_cluster(name="platform", roleArn=role, version="1.30",
                           resourcesVpcConfig={"subnetIds": [app_a, app_b], "securityGroupIds": [sg]})
    optional("eks", eks_stack)

    # ---- storage + CDN ----
    s3 = boto3.client("s3", region_name=REGION)
    for b in ("acme-prod-assets", "acme-prod-logs", "acme-data-lake", "acme-uploads"):
        s3.create_bucket(Bucket=b)
    optional("bucket encryption", lambda: s3.put_bucket_encryption(Bucket="acme-uploads", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": ident["key_arn"]}}]}))
    optional("log bucket encryption", lambda: s3.put_bucket_encryption(Bucket="acme-prod-logs", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "alias/log-archive"}}]}))
    optional("bucket policy", lambda: s3.put_bucket_policy(Bucket="acme-prod-assets", Policy=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-prod-assets/*"},
            {"Effect": "Allow", "Principal": {"AWS": ident["users"]["ci-bot"]}, "Action": "s3:PutObject",
             "Resource": "arn:aws:s3:::acme-prod-assets/*"}]})))
    optional("s3 notification", lambda: s3.put_bucket_notification_configuration(
        Bucket="acme-uploads", NotificationConfiguration={"LambdaFunctionConfigurations": [
            {"LambdaFunctionArn": thumb_arn, "Events": ["s3:ObjectCreated:*"]}]}))

    def cdn():
        boto3.client("cloudfront", region_name=REGION).create_distribution(DistributionConfig={
            "CallerReference": "demo", "Comment": "assets", "Enabled": True,
            "Origins": {"Quantity": 1, "Items": [{"Id": "s3", "DomainName": "acme-prod-assets.s3.amazonaws.com",
                                                  "S3OriginConfig": {"OriginAccessIdentity": ""}}]},
            "DefaultCacheBehavior": {"TargetOriginId": "s3", "ViewerProtocolPolicy": "allow-all",
                                     "ForwardedValues": {"QueryString": False, "Cookies": {"Forward": "none"}},
                                     "MinTTL": 0, "TrustedSigners": {"Enabled": False, "Quantity": 0}}})
    optional("cloudfront", cdn)

    # ---- a second, small region ----
    e2 = boto3.client("ec2", region_name=REGION_2)
    v = e2.create_vpc(CidrBlock="10.20.0.0/16", TagSpecifications=tagged("vpc", "eu-dr-vpc"))["Vpc"]["VpcId"]
    sn = e2.create_subnet(VpcId=v, CidrBlock="10.20.1.0/24", TagSpecifications=tagged("subnet", "dr-a"))["Subnet"]["SubnetId"]
    ami2 = e2.describe_images()["Images"][0]["ImageId"]
    e2.run_instances(ImageId=ami2, MinCount=1, MaxCount=1, InstanceType="t3.small", SubnetId=sn,
                     TagSpecifications=tagged("instance", "dr-standby"))
    boto3.client("sqs", region_name=REGION_2).create_queue(QueueName="dr-replay")


def _identity_layer() -> dict:
    """KMS keys, secrets, parameters, IAM roles/users/groups - created first so everything else can use them.
    Every 'secret' here is an obvious placeholder; tests assert none of them ever reaches the output."""
    import boto3

    acct = "123456789012"                                     # moto's default account id
    kms, sm, ssm, iam = (boto3.client(s, region_name=REGION) for s in ("kms", "secretsmanager", "ssm", "iam"))

    key = kms.create_key(Description="Application data encryption")["KeyMetadata"]
    kms.create_alias(AliasName="alias/app-data", TargetKeyId=key["KeyId"])
    kms.enable_key_rotation(KeyId=key["KeyId"])
    logk = kms.create_key(Description="Log archive encryption")["KeyMetadata"]
    kms.create_alias(AliasName="alias/log-archive", TargetKeyId=logk["KeyId"])
    old = kms.create_key(Description="Retired signing key")["KeyMetadata"]
    kms.create_alias(AliasName="alias/retired-signing", TargetKeyId=old["KeyId"])
    kms.disable_key(KeyId=old["KeyId"])

    db_secret = sm.create_secret(Name="prod/db/password", SecretString="not-a-real-secret-1", KmsKeyId=key["KeyId"],
                                 Description="Orders database credentials")["ARN"]
    api_secret = sm.create_secret(Name="prod/api/stripe-key", SecretString="not-a-real-secret-2")["ARN"]
    ssm.put_parameter(Name="/prod/app/db_url", Value="postgres://placeholder", Type="String")
    ssm.put_parameter(Name="/prod/app/api_token", Value="not-a-real-token", Type="SecureString", KeyId="alias/app-data")
    ssm_db_url = f"arn:aws:ssm:{REGION}:{acct}:parameter/prod/app/db_url"

    def trust(principal) -> str:
        return json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}]})

    def policy(*stmts) -> str:
        return json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", **s} for s in stmts]})

    def managed(name, *stmts) -> str:
        return iam.create_policy(PolicyName=name, PolicyDocument=policy(*stmts))["Policy"]["Arn"]

    admin_pol = managed("FullAdmin", {"Action": "*", "Resource": "*"})
    power_pol = managed("DeployAccess", {"Action": ["lambda:*", "s3:*", "ecs:*", "logs:*"], "Resource": "*"})
    basic_pol = managed("LambdaBasicLogging", {"Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"})

    q = f"arn:aws:sqs:{REGION}:{acct}:orders-queue"
    roles: dict[str, str] = {}
    def role(name, principal, inline=None, managed=(), **kw) -> str:
        roles[name] = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust(principal), **kw)["Role"]["Arn"]
        if inline:
            iam.put_role_policy(RoleName=name, PolicyName=inline[0], PolicyDocument=inline[1])
        for m in managed:
            try:
                iam.attach_role_policy(RoleName=name, PolicyArn=m)
            except Exception:  # noqa: BLE001 - moto only ships some AWS-managed policies
                pass
        return roles[name]

    role("lambda-role", {"Service": "lambda.amazonaws.com"},
         managed=[basic_pol])
    role("web-instance-role", {"Service": "ec2.amazonaws.com"}, ("web-access", policy(
        {"Action": ["s3:GetObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::acme-prod-assets", "arn:aws:s3:::acme-prod-assets/*"]},
        {"Action": "secretsmanager:GetSecretValue", "Resource": db_secret},
        {"Action": "kms:Decrypt", "Resource": key["Arn"]},
        {"Action": "ssm:GetParameter*", "Resource": "arn:aws:ssm:*:*:parameter/prod/app/*"})))
    iam.create_instance_profile(InstanceProfileName="web-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="web-profile", RoleName="web-instance-role")
    role("order-processor-role", {"Service": "lambda.amazonaws.com"}, ("order-access", policy(
        {"Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": q},
        {"Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query"], "Resource": f"arn:aws:dynamodb:{REGION}:{acct}:table/orders"},
        {"Action": ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream"],
         "Resource": f"arn:aws:dynamodb:{REGION}:{acct}:table/orders/stream/*"},
        {"Action": "kms:Decrypt", "Resource": key["Arn"]},
        {"Action": "secretsmanager:GetSecretValue", "Resource": db_secret})),
         managed=[basic_pol])
    role("ecs-task-role", {"Service": "ecs-tasks.amazonaws.com"}, ("task-access", policy(
        {"Action": ["dynamodb:GetItem", "dynamodb:PutItem"], "Resource": f"arn:aws:dynamodb:{REGION}:{acct}:table/sessions"})))
    role("ecs-exec-role", {"Service": "ecs-tasks.amazonaws.com"}, ("read-secrets", policy(
        {"Action": "secretsmanager:GetSecretValue", "Resource": [db_secret, api_secret]},
        {"Action": "ssm:GetParameters", "Resource": ssm_db_url})))
    role("deploy-role", {"AWS": [f"arn:aws:iam::{acct}:user/ci-bot", "arn:aws:iam::999988887777:root"]},
         managed=[power_pol])
    role("legacy-open-role", {"AWS": "*"}, ("legacy", policy({"Action": "s3:ListAllMyBuckets", "Resource": "*"})))

    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn=admin_pol)
    iam.create_group(GroupName="developers")
    iam.put_group_policy(GroupName="developers", PolicyName="dev-access", PolicyDocument=policy(
        {"Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::acme-uploads", "arn:aws:s3:::acme-uploads/*"]},
        {"Action": "lambda:*", "Resource": "*"},
        {"Action": ["logs:*", "cloudwatch:*"], "Resource": "*"}))
    users: dict[str, str] = {}
    for name, group in (("alice", "admins"), ("bob", "developers"), ("ci-bot", None)):
        users[name] = iam.create_user(UserName=name)["User"]["Arn"]
        if group:
            iam.add_user_to_group(GroupName=group, UserName=name)
    iam.create_login_profile(UserName="alice", Password="Not-A-Real-Passw0rd!")
    iam.create_access_key(UserName="ci-bot")
    iam.put_user_policy(UserName="ci-bot", PolicyName="ci-access", PolicyDocument=policy(
        {"Action": "s3:PutObject", "Resource": "arn:aws:s3:::acme-prod-assets/*"},
        {"Action": "sts:AssumeRole", "Resource": roles["deploy-role"]}))
    return {"key_arn": key["Arn"], "roles": roles, "users": users, "api_secret_arn": api_secret, "ssm_db_url_arn": ssm_db_url}


def _spread_dates(graph: dict) -> None:
    """moto stamps everything 'now'; give the mock estate a believable history (~10% undated)."""
    rng = random.Random(42)
    now = datetime.now(timezone.utc)
    for r in graph["resources"]:
        if r["container"]:
            continue
        r["props"].pop("date_basis", None)
        if rng.random() < 0.1:
            r["created"] = None
        else:
            r["created"] = (now - timedelta(days=int(rng.random() ** 2 * 700) + 1, hours=rng.randint(0, 23))).isoformat(timespec="seconds")


def run_demo(provider: str, log: Callable[[str], None]) -> dict:
    """Build a fake environment for `provider`, run the real mapping code over it, return the graph dict."""
    if provider == "aws":
        graph = _demo_aws(log)
        _spread_dates(graph)
    elif provider == "azure":
        from .fixtures import azure_identity, azure_rows
        from .providers.azure import build_graph
        rows, names, tenant = azure_rows()
        graph = build_graph(rows, names, tenant, azure_identity()).to_dict()
    elif provider == "gcp":
        from .fixtures import gcp_assets, gcp_policies
        from .providers.gcp import build_graph
        graph = build_graph(gcp_assets(), "acme-prod", gcp_policies()).to_dict()
    else:
        raise SystemExit(f"No demo environment for '{provider}'.")
    graph.setdefault("warnings", []).append("Demo data: a fictional estate with synthetic creation dates.")
    return graph


def _demo_aws(log: Callable[[str], None]) -> dict:
    try:
        from moto import mock_aws
    except ImportError:
        raise SystemExit("Demo mode needs moto:  pip install moto") from None
    from .providers.aws import AWSProvider

    fake = {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}
    saved = {k: os.environ.get(k) for k in fake}
    os.environ.update(fake)
    try:
        with mock_aws():
            log("Building a mock AWS environment (no real account is touched)...")
            build_aws_environment(log)
            return AWSProvider(regions=[REGION, REGION_2], log=log).discover().to_dict()
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
