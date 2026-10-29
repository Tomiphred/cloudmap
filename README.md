# cloudmap

## What it does

cloudmap answers three questions about a cloud account without you clicking through a console:

1. **What is in it?** It connects to **AWS, Azure or GCP** using your normal credentials, lists every resource it can see
   (networks, servers, containers, serverless functions, databases, storage, queues, load balancers and more), and draws them as
   one interactive diagram, nested the way the cloud is organised (account ▸ region ▸ network ▸ subnet ▸ resource).
2. **What is connected to what?** Arrows show traffic paths, triggers, queues and topics, peering, private links and CDN origins.
3. **Who and what has access to it?** IAM users, groups and roles (Azure role assignments and managed identities, GCP service
   accounts and IAM bindings), KMS keys, secrets and parameters are drawn as resources too, with arrows for what each one
   **controls** (with the permission level), who can **assume** it, which workload **runs as** it, which key **encrypts** a resource,
   and which workload **uses** a secret. Risky patterns, such as admin-equivalent access, public access, roles trusted by other
   accounts, missing key rotation or old access keys, are flagged as searchable properties.

You get the result as a single offline HTML file you can open in a browser and share internally. In it you can:

- **Explore the diagram:** zoom, pan, search, click any resource to see its properties, what it connects to or controls, and what uses it.
- **Switch to the Table view:** every resource itemized, one row each, with its connections in both directions, sortable, searchable and exportable to CSV.
- **Filter by creation date:** past day, week, month or year, or any date range, with a histogram grouped by day, week, month or year,
  to see what changed recently.
- **Focus on security:** one click shows only identity and access arrows, or only infrastructure arrows.
- **Export:** SVG or PNG for documents and slides, JSON for the raw data, CSV for the inventory.

**Safe by design:** it is read-only (list, describe and get calls only), runs on your machine, and sends nothing anywhere.
It reads metadata only and never collects secret values, passwords, access keys or object contents.
It shows what policies *grant*, not what was actually used, so treat access arrows as an upper bound.

**Typical uses:** documenting an environment you inherited, onboarding new engineers, preparing for an audit or security review
("who can read this secret?", "what runs as this admin role?", "which buckets are public?"), and spotting what was created in the last week.

Point it at a cloud account, get back an **interactive architecture diagram** of everything in it —
on **AWS, Azure or GCP** — including **who and what has access to it**: IAM users, groups and roles, KMS keys,
secrets and parameters, each drawn with what it controls and what it is connected to. There is a **creation-date
filter** (past day / week / month / year, or any range) and a **Table view** that itemizes every resource with its connections.

- **Read-only.** Only list/describe/get calls. Nothing is created, changed or deleted.
- **Runs locally.** Credentials come from each cloud's normal chain; the output is one offline HTML file. Nothing is sent anywhere.
- **Pictorial.** Resources are drawn nested the way each cloud is organised, with arrows for the connections between them:

| Cloud | Nesting | Connections drawn |
|---|---|---|
| AWS | Account ▸ Region ▸ VPC ▸ Subnet ▸ resources, plus an **Identity & Access** box | routes, load-balancer targets, event triggers, queues/topics, DLQs, peering, CDN origins · **IAM access, trust, group membership, instance/task/function roles, KMS encryption, secret use** |
| Azure | Tenant ▸ Subscription ▸ Resource group ▸ VNet ▸ Subnet ▸ resources, plus an **Identity & Access** box | load-balancer / App Gateway backends, private endpoints, peering, NAT gateways, SQL server → database · **RBAC role assignments, managed identities, Key Vault keys/secrets/access policies, customer-managed keys** |
| GCP | Scope ▸ Project ▸ VPC ▸ Subnet ▸ resources (regional services sit in a Region box), plus **Identity & Access** boxes | forwarding rule → backend service → instance group, Pub/Sub → functions/subscriptions, private-IP links · **IAM bindings, service accounts and "runs as", KMS keys (CMEK), Secret Manager, public access** |

## Quick start

```bash
pip install -e ".[all]"            # Python 3.10+; or ".[azure]" / ".[gcp]" / nothing for AWS only

python -m cloudmap aws                                   # every enabled region
python -m cloudmap aws   --profile prod --regions us-east-1,eu-west-1
python -m cloudmap azure                                 # every subscription you can see
python -m cloudmap azure --subscriptions <id>,<id>
python -m cloudmap gcp   --projects my-proj,other-proj   # or --folder 123 / --organization 456
```
Each writes `<cloud>-architecture.html` (change with `--out`; add `--json FILE` for the raw graph).

**Try it with no account:** `python -m cloudmap aws|azure|gcp --demo` (AWS demo needs `pip install -e ".[dev]"`; it uses a mocked estate).

### Sign-in and permissions
| Cloud | Sign in | Role needed |
|---|---|---|
| AWS | `aws configure` / `aws sso login` / env vars, `--profile`, `--role-arn` | The least-privilege [`iam-policy.json`](iam-policy.json) (metadata only — it deliberately has **no** `GetSecretValue`, `ssm:GetParameter`, `kms:Decrypt` or `s3:GetObject`). `ViewOnlyAccess` covers most but not all identity calls |
| Azure | `az login` or `AZURE_*` service-principal variables | **Reader** on the subscriptions (covers role assignments and Key Vault key/secret *metadata*). Optional: Microsoft Graph `Directory.Read.All` to show user/group/app names instead of object ids (`--no-principal-names` skips it) |
| GCP | `gcloud auth application-default login` or `GOOGLE_APPLICATION_CREDENTIALS` | **Cloud Asset Viewer** + **Viewer**; the *Cloud Asset API* must be enabled. Cloud Asset Viewer also lets the scan read IAM policies |

Missing permissions never abort an AWS scan: that service is skipped and listed under "Scan notes".
Auth problems print one readable line with the fix (`CLOUDMAP_DEBUG=1` for the full traceback).

## Filtering by creation date
The **Created** panel at the top of the sidebar filters the whole diagram:

- **Past day / week / month / year** — measured from the moment of the scan, since the diagram is a snapshot.
- **Histogram** of resources created over time. **Group bars by** Day, Week (Mon–Sun), Month or Year, then **click a bar** to show only that period; **Shift-click** another to extend the range; click the active bar to clear it.
- **From / To** date boxes for an exact range. All dates are UTC.
- **Include unknown date** — some resources have no creation date. They're shown when no range is set and hidden once you pick one, unless you tick this.
- Boxes (VPCs, subnets, resource groups…) stay visible if anything inside them matches, or if they were themselves created in the range.

**Where dates come from** (and where they can't):
| Cloud | Source | Gaps |
|---|---|---|
| AWS | each service's own create time (EC2 *launch* time, RDS, ELB, DynamoDB, SQS, S3, EKS…) | VPCs, subnets, SNS have none. Lambda and CloudFront only expose *last modified* |
| Azure | ARM `createdTime` (falls back to `timeCreated` / `creationTime` properties) | not every resource type reports it |
| GCP | `creationTimestamp` / `createTime` / `timeCreated` | Pub/Sub topics have none; v1 Cloud Functions only expose *last modified* |

Where only a last-modified time exists it is used, but the details panel labels it **Last modified**, never "Created".
EC2's launch time resets when an instance is stopped and started again.

## Identity, security and "what controls what"
Identity and security services are first-class resources (category **Security & identity**), each connected to the things they touch:

| Arrow | Meaning | Example |
|---|---|---|
| **Access** | a permission grant, labelled with the level (`full` / `permissions` / `write` / `read`) and the actions or role | `web-instance-role → prod/db/password: read: secretsmanager:GetSecretValue` |
| **Can assume (trust)** | who may assume a role | `ci-bot → deploy-role` |
| **Runs as (identity)** | the identity a workload executes with | `web-1 → web-instance-role` (via instance profile), Lambda/ECS/Cloud Run/GKE/VM identities |
| **Group membership** | user → group | `alice → admins` |
| **Encrypted with (KMS)** | the key protecting a resource | `app-data → orders-db`, customer-managed keys on Azure, CMEK on GCP |
| **Uses secret / parameter** | a workload that reads a secret | `checkout → prod/api/stripe-key` (ECS `secrets`, Cloud Run `secretKeyRef`, Functions secret env vars, App Gateway certificates) |

Click any identity to see **Connects to / controls** (what it can reach) and **Connected from / used by** (what runs as it, who is a member, what it encrypts).
In the sidebar, **Identity & access only** / **Infrastructure only** / **All** switch the arrows in one click; identity arrows are drawn faint until you hover or select, so a large account stays readable.

Per-item risk signals are shown as properties and searchable (true-valued flags are searchable by name — try `admin_access`, `public_policy`, `trust_public`, `public_access`, or a word like `EXTERNAL`):
**AWS** admin-equivalent policies, wildcard (`*`) grants, roles trusted by other accounts / services / anyone, public bucket/queue/key/secret policies, MFA and access-key age (credential report), key rotation, disabled keys. **Azure** `Owner` at subscription scope, unresolved/deleted principals, Key Vault purge protection / RBAC mode, disabled or expiring secrets. **GCP** `roles/owner`, `allUsers` / `allAuthenticatedUsers` (shown as a "Public" principal and flagged on the resource), user-managed service-account keys with their age, disabled service accounts, deleted members, KMS keys with no rotation.

**How to read "access":** it is what a policy *grants*, not a proof that something happened. Only `Allow` is read - `Deny`, permission boundaries, SCPs, session policies, Azure deny assignments / PIM / conditions and GCP deny policies are **not** evaluated, so treat it as an upper bound. A `Resource: "*"` grant is drawn to the real resources only if it matches at most 30 (`--max-wildcard-targets`); otherwise it is listed on the principal as `broad_access` rather than drawing hundreds of arrows. Group membership in Entra ID / Google Groups is not expanded (who is *in* a group isn't visible from the resource APIs). AWS service-linked roles and AWS-managed KMS keys are hidden unless you pass `--include-service-roles` / `--include-aws-managed-keys`. Grants made at an ancestor (a subscription or project) are listed on the principal and in the table; the arrow to a box that contains the principal itself isn't drawn.

## Table view (everything itemized)
The **Table** button next to **Diagram** lists *every* resource — one row each — with type, category, region, parent, creation date, **Connects to / controls** and **Connected from / used by** (each connection is a clickable pill showing its kind). Click a header to sort; the search box, category checkboxes, connection-type checkboxes and the **Created** date filter all apply to it. **CSV** downloads exactly what is shown (all connections spelled out, one cell each, formula-injection safe). Tick **Include containers** to add accounts, regions, VPCs and subnets.

## Using the diagram
Scroll to zoom, drag to pan, click a resource for its properties and connections, hover to trace its links.
Search (`/`) by name, id, type, tag or property. Sidebar filters hide categories or connection types.
Buttons export **SVG**, **PNG** (for docs/slides), the raw **JSON**, and (Table view) **CSV**.

## What's collected
- **AWS:** VPC, subnets, route tables, Internet/NAT gateways, VPC endpoints, peering, Transit Gateway · EC2, Auto Scaling, ECS, EKS, Lambda · ALB/NLB/GWLB and targets · RDS, ElastiCache, DynamoDB · S3, SQS, SNS, API Gateway, CloudFront · **IAM users, groups, roles and their policies (inline, attached and managed), KMS keys (aliases, rotation, key policy), Secrets Manager secrets (metadata + resource policy), SSM parameters (metadata only), S3 bucket / SQS / SNS resource policies.**
- **Azure** (via Resource Graph): VNets/subnets, VMs (placed via their NICs), scale sets, AKS, App Service/Functions, Container Apps, load balancers, App Gateway, Firewall, Bastion, VPN/ER gateways, NAT, private endpoints, API Management, Front Door/CDN, SQL, Cosmos DB, PostgreSQL/MySQL, Redis, Storage, Key Vault, Service Bus, Event Hubs/Grid, and any other resource type as a generic box. Plumbing (NICs, disks, NSGs, route tables, extensions…) is hidden. **Plus:** managed identities (system- and user-assigned), RBAC role assignments (Entra users, groups and service principals → management group / subscription / resource group / resource), Key Vault keys and secrets (metadata only) and access policies, customer-managed-key and Key Vault secret references.
- **GCP** (via Cloud Asset Inventory): VPCs/subnets, Compute instances & managed instance groups, GKE, Cloud Run, Cloud Functions, load balancer chain, VPC connectors, Cloud SQL, Memorystore, Spanner, BigQuery, Cloud Storage, Pub/Sub · **service accounts and their user-managed keys, IAM bindings (project, folder, organization and resource level), Cloud KMS key rings and keys, Secret Manager secrets (metadata only).** The scan asks for these asset types only; other types aren't drawn yet.

**Never collected:** secret *values* of any kind (Secrets Manager / SSM / Key Vault / Secret Manager contents, access keys, service-account key material), Lambda env vars, instance user-data, SNS email/URL endpoints, app settings or connection strings, object listings. Only metadata is read — the AWS policy file contains no permission that could read a value, and a test enforces that.
Resource names, IDs, IPs and tags *are* in the output, so treat the HTML/JSON as internal.

