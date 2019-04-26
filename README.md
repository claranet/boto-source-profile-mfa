# boto-source-profile-mfa

AWS boto helper library for reusing MFA tokens in profiles with the same source profile.

## Why

We access customer accounts using "assume role" profiles, with roles that require MFA tokens. Our AWS configuration looks like this:

```
[profile claranet]
aws_access_key_id = ...
aws_secret_access_key = ...

[profile customer1]
external_id = ...
mfa_serial = ...
role_arn = ...
source_profile = claranet

[profile customer2]
external_id = ...
mfa_serial = ...
role_arn = ...
source_profile = claranet

[profile customer3]
external_id = ...
mfa_serial = ...
role_arn = ...
source_profile = claranet
```

With standard awscli and boto tooling, using each customer profile triggers an MFA prompt. There is caching for each profile, so you are not prompted for an MFA token for the same profile multiple times, but using 3 customer profiles will trigger 3 MFA prompts.

This library provides a way to have only 1 MFA prompt.

## How

Standard awscli and boto tooling effectively does:

1. Create session for source profile
2. Assume role in customer profile with MFA
3. Cache result

This library effectively does:

1. Create session in source profile
2. Get session token with MFA
3. Cache result
4. Assume role into customer profile

## Setup

```
pip install boto_source_profile_mfa
```

## Usage

Getting a boto3 session in Python:

```python
from boto_source_profile_mfa import get_session

session = get_session('customer1')
s3 = session.client('s3')

print(s3.list_buckets())
```

Set environment variables in Bash:

```bash
profile=customer1
vars=$(python -c "from boto_source_profile_mfa import print_environment_variables as p; p('${profile}')") && export $vars
```
