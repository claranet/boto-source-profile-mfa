import argparse
import datetime
import json
import os
import sys

from boto3 import Session
from botocore.credentials import CachedCredentialFetcher, CredentialProvider, DeferredRefreshableCredentials, JSONFileCache
from botocore.exceptions import InvalidConfigError, ProfileNotFound
from botocore.session import Session as BotocoreSession

from getpass import getpass

from hashlib import sha1


cache_dir = os.path.expanduser(os.path.join('~', '.aws', 'boto-source-profile-mfa', 'cache'))
cache = JSONFileCache(cache_dir)


class SourceProfileMfaCredentialsFetcher(CachedCredentialFetcher):
    """
    Fetches credentials for a temporary session, prompting for MFA,
    and caches the results to reduce the number of MFA prompts.

    """

    def __init__(self, profile, mfa_serial, mfa_prompter, cache, expiry_window_seconds=60):
        self._profile = profile
        self._mfa_serial = mfa_serial
        self._mfa_prompter = mfa_prompter
        super(SourceProfileMfaCredentialsFetcher, self).__init__(
            cache=cache,
            expiry_window_seconds=expiry_window_seconds,
        )

    def _create_cache_key(self):
        return sha1(json.dumps([self._profile, self._mfa_serial]).encode('utf-8')).hexdigest()

    def _get_credentials(self):
        sts = Session(profile_name=self._profile).client('sts')
        if self._mfa_serial:
            params = {
                'SerialNumber': self._mfa_serial,
                'TokenCode': self._get_mfa_token(),
            }
        else:
            params = {}
        return sts.get_session_token(**params)

    def _get_mfa_token(self):
        prompt = 'Enter MFA code for {}: '.format(self._mfa_serial)
        token = self._mfa_prompter(prompt)
        return token


class SourceProfileMfaCredentialProvider(CredentialProvider):
    """
    Provides credentials for profiles with a source_profile and mfa_serial.
    It reuses MFA-enabled sessions in source profiles to avoid prompting
    for MFA tokens in every profile with the same source profile.

    """

    METHOD = 'custom-source-profile-mfa'
    CANONICAL_NAME = 'custom-source-profile-mfa'

    def __init__(self, profile, mfa_prompter):
        self._profile = profile
        self._mfa_prompter = mfa_prompter

    def load(self):

        botocore_session = BotocoreSession(profile=self._profile)
        config = botocore_session.get_scoped_config()

        source_profile = config.get('source_profile')

        if source_profile:

            mfa_serial = config.get('mfa_serial', '')

            fetcher = SourceProfileMfaCredentialsFetcher(
                profile=source_profile,
                mfa_serial=mfa_serial,
                mfa_prompter=self._mfa_prompter,
                cache=cache,
            )
            refresher = fetcher.fetch_credentials

            role_arn = config.get('role_arn')
            if role_arn:
                external_id = config.get('external_id')
                refresher = create_assume_role_refresher(
                    refresher=refresher,
                    role_arn=role_arn,
                    external_id=external_id,
                    session_name=self._profile,
                )

            return DeferredRefreshableCredentials(
                method=self.METHOD,
                refresh_using=refresher,
            )


def _serialize_if_needed(value, iso=False):
    """
    Copied from botocore.

    """

    if isinstance(value, datetime.datetime):
        if iso:
            return value.isoformat()
        return value.strftime('%Y-%m-%dT%H:%M:%S%Z')
    return value


def create_assume_role_refresher(refresher, role_arn, external_id, session_name):
    """
    Wraps a credentials refresher to assume a role
    and return those temporary credentials.

    """

    def assume_role_refresher():

        creds = refresher()
        session = Session(
            aws_access_key_id=creds['access_key'],
            aws_secret_access_key=creds['secret_key'],
            aws_session_token=creds['token'],
        )
        client = session.client('sts')

        params = {
            'RoleArn': role_arn,
            'RoleSessionName': session_name,
        }
        if external_id:
            params['ExternalId'] = external_id

        response = client.assume_role(**params)
        credentials = response['Credentials']
        return {
            'access_key': credentials['AccessKeyId'],
            'secret_key': credentials['SecretAccessKey'],
            'token': credentials['SessionToken'],
            'expiry_time': _serialize_if_needed(credentials['Expiration']),
        }

    return assume_role_refresher


def get_session(profile_name, mfa_prompter=getpass, **kwargs):
    """
    Returns a boto3 session for the specified profile. If the profile is
    configured to assume a role and use MFA, then the MFA token will be used
    on the source profile rather than on the assume role profile. This is
    cached and reused to allow for using different assume role profiles with
    the same source profile without prompting for MFA tokens every time.

    """

    # Create a regular botocore session.
    botocore_session = BotocoreSession(profile=profile_name)

    # Create a custom credential provider.
    custom_provider = SourceProfileMfaCredentialProvider(profile_name, mfa_prompter)

    # Put the custom provider at the front of the resolver list,
    # so it will be checked/used before the default boto providers.
    credential_resolver = botocore_session.get_component('credential_provider')
    credential_resolver.providers.insert(0, custom_provider)

    # Return a boto3 session using the patched botocore session.
    return Session(botocore_session=botocore_session, **kwargs)


def print_environment_variables(profile=None, include_region=False, **kwargs):
    """
    Prints AWS credentials as environment variables.
    This uses the get_session() function to reuse MFA sessions.

    """

    # Work with profile or profile_name.
    if profile:
        kwargs['profile_name'] = profile

    session = get_session(**kwargs)

    creds = session.get_credentials()

    if not creds:
        raise InvalidConfigError(
            error_msg='No credentials found for {}'.format(kwargs),
        )

    frozen_creds = creds.get_frozen_credentials()
    expiry_time = getattr(creds, '_expiry_time', None)

    print('AWS_ACCESS_KEY_ID={}'.format(frozen_creds.access_key))
    print('AWS_SECRET_ACCESS_KEY={}'.format(frozen_creds.secret_key))

    if expiry_time:
        print('AWS_SESSION_EXPIRATION={}'.format(_serialize_if_needed(expiry_time)))

    if frozen_creds.token:
        print('AWS_SESSION_TOKEN={}'.format(frozen_creds.token))

    if include_region and session.region_name:
        print('AWS_DEFAULT_REGION={}'.format(session.region_name))
        print('AWS_REGION={}'.format(session.region_name))


def cli():
    parser = argparse.ArgumentParser(prog='awsp', description='Prints credentials for an AWS profile.')
    parser.add_argument('profile', help='Profile name')
    parser.add_argument('-r', '--region', action='store_true', help='Include region')
    args = parser.parse_args()
    try:
        print_environment_variables(profile=args.profile, include_region=args.region)
    except ProfileNotFound as error:
        print(error, file=sys.stderr)
        sys.exit(1)
