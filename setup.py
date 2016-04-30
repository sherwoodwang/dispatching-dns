#!/usr/bin/env python3

from setuptools import setup

setup(
    name='dispatching-dns',
    version='0.0.14',
    packages=['dispatching_dns'],
    url='https://github.com/sherwoodwang/dispatching-dns',
    license='2-clause BSD',
    author='Sherwood Wang',
    author_email='sherwood@wang.onl',
    description='A simple suboptimal dns server which forward requests to multiple servers according to domains',
    install_requires=[
        'cachetools',
        'dnslib',
        'pyyaml',
        'recordclass',
    ],
    entry_points={
        'console_scripts': [
            'dispatching-dns=dispatching_dns.script:main'
        ],
    }
)
