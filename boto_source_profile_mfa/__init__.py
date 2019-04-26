import datetime
import json
import os

from boto3 import Session
from botocore.credentials import CachedCredentialFetcher, CredentialProvider, DeferredRefreshableCredentials, JSONFileCache
from botocore.exceptions import InvalidConfigError
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

    def __init__(self, profile, mfa_serial, cache, expiry_window_seconds=60):
        self._profile = profile
        self._mfa_serial = mfa_serial
        super(SourceProfileMfaCredentialsFetcher, self).__init__(
            cache=cache,
            expiry_window_seconds=expiry_window_seconds,
        )

    def _create_cache_key(self):
        return sha1(json.dumps([self._profile, self._mfa_serial]).encode('utf-8')).hexdigest()

    def _get_credentials(self):
        session = Session(profile_name=self._profile)
        return session.client('sts').get_session_token(
            SerialNumber=self._mfa_serial,
            TokenCode=self._get_mfa_token(),
        )

    def _get_mfa_token(self):
        prompt = 'Enter MFA code for {}: '.format(self._mfa_serial)
        token = getpass(prompt)
        return token


class SourceProfileMfaCredentialProvider(CredentialProvider):
    """
    Provides credentials for profiles with a source_profile and mfa_serial.
    It reuses MFA-enabled sessions in source profiles to avoid prompting
    for MFA tokens in every profile with the same source profile.

    """

    METHOD = 'custom-source-profile-mfa'
    CANONICAL_NAME = 'custom-source-profile-mfa'

    def __init__(self, profile):
        self._profile = profile

    def load(self):

        botocore_session = BotocoreSession(profile=self._profile)
        config = botocore_session.get_scoped_config()

        mfa_serial = config.get('mfa_serial')
        source_profile = config.get('source_profile')

        if mfa_serial and source_profile:

            fetcher = SourceProfileMfaCredentialsFetcher(
                profile=source_profile,
                mfa_serial=mfa_serial,
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


def get_session(profile):
    """
    Returns a boto3 session for the specified profile. If the profile is
    configured to assume a role and use MFA, then the MFA token will be used
    on the source profile rather than on the assume role profile. This is
    cached and reused to allow for using different assume role profiles with
    the same source profile without prompting for MFA tokens every time.

    """

    # Create a regular botocore session.
    botocore_session = BotocoreSession(profile=profile)

    # Create a custom credential provider.
    custom_provider = SourceProfileMfaCredentialProvider(profile)

    # Put the custom provider at the front of the resolver list,
    # so it will be checked/used before the default boto providers.
    credential_resolver = botocore_session.get_component('credential_provider')
    credential_resolver.providers.insert(0, custom_provider)

    # Return a boto3 session using the patched botocore session.
    return Session(botocore_session=botocore_session)


def print_environment_variables(profile):
    """
    Prints AWS credentials as environment variables.
    This uses the get_session() function to reuse MFA sessions.

    """

    session = get_session(profile)

    creds = session.get_credentials()

    if not creds:
        raise InvalidConfigError(
            error_msg='No credentials found in profile {}'.format(profile),
        )

    frozen_creds = creds.get_frozen_credentials()
    expiry_time = getattr(creds, '_expiry_time', None)

    print('AWS_ACCESS_KEY_ID={}'.format(frozen_creds.access_key))
    print('AWS_SECRET_ACCESS_KEY={}'.format(frozen_creds.secret_key))

    if expiry_time:
        print('AWS_SESSION_EXPIRATION={}'.format(_serialize_if_needed(expiry_time)))

    if frozen_creds.token:
        print('AWS_SESSION_TOKEN={}'.format(frozen_creds.token))
