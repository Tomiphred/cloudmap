# cloudmap
Create an iam-role with account level permission take note of the resource arn

## Quick start

```bash
pip install -e ".[all]"            # Python 3.10+; or ".[azure]" / ".[gcp]" / nothing for AWS only

python3 -m cloudmap aws --role-arn <attach role arn>         # every enabled region
python -m cloudmap aws --role-arn <attach role arn> --profile prod --regions us-east-1,eu-west-1
python -m cloudmap azure --service-account          # every subscription you can see
python -m cloudmap azure --subscriptions <id>,<id>
python -m cloudmap gcp   --projects my-proj,other-proj   # or --folder 123 / --organization 456
```
Each writes `<cloud>-architecture.html` (change with `--out`; add `--json FILE` for the raw graph).