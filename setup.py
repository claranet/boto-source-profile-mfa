#!/usr/bin/env python

from setuptools import setup

setup(
    name='boto-source-profile-mfa',
    version='0.0.1',
    description='AWS boto helper library for reusing MFA tokens in profiles with the same source profile',
    author='Raymond Butcher',
    author_email='ray.butcher@claranet.uk',
    url='https://github.com/claranet/boto-source-profile-mfa',
    license='MIT License',
    packages=(
        'boto_source_profile_mfa',
    ),
    install_requires=(
        'boto3',
        'botocore',
    ),
)
