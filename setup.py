#!/usr/bin/env python

from setuptools import setup, find_packages


requires = open('requirements.txt').read().strip().split('\n')

setup(
    name='intake-pcap',
    version='0.0.5',
    description='Intake PCAP plugin',
    url='https://github.com/ContinuumIO/intake-pcap',
    maintainer='Joseph Crail',
    maintainer_email='jbcrail@gmail.com',
    license='BSD',
    packages=find_packages(),
    package_data={'': ['*.pcap', '*.yml', '*.html']},
    include_package_data=True,
    install_requires=requires,
    long_description=open('README.md').read(),
    zip_safe=False,
)
