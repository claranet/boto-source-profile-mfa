#!/usr/bin/env python

from setuptools import setup

setup(
    name='boto-source-profile-mfa',
    version='0.0.10',
    description='AWS boto helper library for reusing MFA tokens in profiles with the same source profile',
    author='Raymond Butcher',
    author_email='ray.butcher@claranet.uk',
    url='https://github.com/claranet/boto-source-profile-mfa',
    license='MIT License',
    packages=(
        'boto_source_profile_mfa',
    ),
    entry_points = {
        'console_scripts': (
            'awsp=boto_source_profile_mfa:cli',
        ),
    },
    install_requires=(
        'boto3',
        'botocore',
    ),
)
