# Access Risk Analyzer

A Python tool that models a cloud IAM environment as a graph, walks it for
**privilege-escalation attack paths** (the same class of misconfigurations
flagged by tools like PMapper / Cloudsplaining for AWS, or BloodHound for
Active Directory), and generates **least-privilege recommendations** --
then proves their value by re-running the graph with trimmed permissions
and measuring how much the attack surface actually shrinks.

```
Fake IAM data  -->  Weighted attack graph  -->  Graph-based attack paths
     |                                                    |
     v                                                    v
Simulated usage logs --> Least-privilege recs --> Before/after remediation impact
```

## Why this exists

Most IAM "risk" tooling either (a) flags individual over-permissioned
policies in isolation, or (b) visualizes access without scoring it. The
interesting failures in real cloud environments are usually **chains**:
a developer with `iam:PassRole` + `ec2:RunInstances` can launch an
instance with an admin role attached and harvest its credentials, even
though no single permission they hold looks dangerous on its own. Modeling
identities, roles, and permissions as a directed graph turns "is there a
multi-step path from this low-privilege user to full admin" into a
shortest-path problem instead of something a human has to manually trace
through a spreadsheet of policies.

## Pipeline

1. **`data_generator.py`** -- builds a synthetic but realistic IAM
   environment (users, groups, roles, managed/inline policies, resources)
   using `Faker` for identity data. A configurable fraction of users are
   seeded with an extra "convenience" policy layered on top of their
   normal access -- modeling real permission creep rather than hand-placed
   scenario flags. Deterministic given a seed.

2. **`privesc_rules.py`** -- a catalog of known IAM privilege-escalation
   techniques (mirroring the public research on AWS IAM privesc paths),
   each mapped to a **MITRE ATT&CK (Cloud)** technique ID:

   | Technique | ATT&CK ID |
   |---|---|
   | Create access key / reset password for another user | T1098.001 |
   | Attach/put a policy onto self, create a new policy version | T1098.003 |
   | `PassRole` + `RunInstances` / Lambda | T1548.005 |
   | Rewrite a role's trust policy | T1098.003 |
   | Assume a role via an overly permissive trust policy | T1078.004 |

3. **`graph_builder.py`** -- builds a directed, weighted `networkx` graph.
   Edge weight encodes how cheap/reliable a technique is for an attacker
   (lower = more dangerous). Accepts an `overrides` map so the same builder
   can construct a "what-if this identity only had its actually-used
   permissions" graph -- this is what powers the remediation comparison.

4. **`attack_paths.py`** -- two focused analyses, kept separate on
   purpose:
   - `find_privesc_paths_to_admin` -- the headline result: the cheapest
     chain of escalation techniques from each user to full admin.
   - `find_resource_exposure_paths` -- a complementary "blast radius"
     metric: how directly each user can reach a resource tagged
     sensitivity=high, independent of admin takeover.

5. **`least_privilege.py`** -- simulates a 90-day usage log per identity
   (standing in for CloudTrail/Access Advisor data), diffs granted vs.
   used actions, and flags unused permissions that are specifically the
   ingredients of a known escalation technique. Identities holding a
   literal `AdministratorAccess` wildcard are called out rather than
   silently scored, since a wildcard can't be diffed against a usage log.
   `remediation_impact()` rebuilds the graph with trimmed permissions and
   reports how many users still have a path to admin afterward.

6. **`risk_report.py` / `visualize.py`** -- a composite 0-100 risk score
   per user (escalation risk + resource exposure + least-privilege gap),
   written to CSV/JSON, plus a `networkx`+`matplotlib` rendering of the
   full graph and the single riskiest path, highlighted.

## Running it

```bash
pip install -r requirements.txt
python -m access_risk_analyzer.main --num-users 25 --seed 42 --output-dir output
```

Outputs land in `output/`:
- `iam_data.json` -- the generated environment
- `attack_paths.json` -- every escalation-to-admin and resource-exposure
  path found, with the exact technique chain and ATT&CK IDs
- `least_privilege_recommendations.json` -- per-identity trimmed policy
  recommendations
- `risk_report.csv` / `risk_summary.json` -- the composite scoring
- `attack_graph.png` / `top_risk_path.png` -- visualizations

Run the sanity test suite with:
```bash
pytest -q
```
These don't try to prove the security findings are realistic -- that's a
judgment call -- they check that the pipeline's internal logic is
consistent (every reported path is actually walkable in the graph,
remediation never *increases* risk, the report's row count matches the
user count, the dataset is deterministic given a seed, etc.).

## Example finding (from a seeded run)

> `donaldgarcia` (developer, MFA disabled) holds `iam:PassRole` +
> `ec2:RunInstances` through the `DeveloperDeployPolicy`. Because that
> policy isn't scoped to a specific role ARN, `donaldgarcia` can launch an
> EC2 instance with `BreakGlassAdminRole` attached and harvest its
> instance-profile credentials -- a 2-hop path to full admin
> (risk score 95/100). The least-privilege engine independently flags
> `iam:PassRole` as unused in `donaldgarcia`'s simulated 90-day activity;
> removing it closes this path without affecting their actual work.

This is the single most common real-world AWS IAM finding this kind of
tool is meant to catch: an unscoped `PassRole` grant turning an
unprivileged role into a stepping stone to admin.

## Design notes / honesty about scope

- This operates on a **synthetic** dataset, not a live AWS/Azure/GCP
  account. Wiring `data_generator.py`'s output format to a real
  `aws iam get-account-authorization-details` export (or Azure/GCP
  equivalents) is the natural next step and wouldn't require changing the
  graph/analysis layers at all -- only the data-loading layer.
- Resource-level permission scoping (`Resource: "arn:aws:s3:::specific-bucket"`)
  is simplified to service-level (`s3:*` grants access to "an S3 bucket"
  rather than one specific ARN). Real environments are usually *more*
  constrained than this model, not less -- so treat the absolute path
  counts as illustrative of the technique, not a literal vulnerability
  count.
- The 90-day usage log is simulated (a random subset of granted actions),
  not pulled from a real access-advisor export. The diffing/recommendation
  *logic* is the deliverable; plugging in a real usage source is a
  data-layer swap, not a redesign.

## Stack

Python 3.10+, `networkx` (graph construction + Dijkstra shortest paths),
`matplotlib` (visualization), `Faker` (synthetic identity data), `pytest`
(sanity tests). No external services or API keys required.
