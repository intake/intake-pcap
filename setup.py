#!/usr/bin/env python

from setuptools import setup, find_packages
import versioneer


requires = open('requirements.txt').read().strip().split('\n')

setup(
    name='intake-pcap',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description='Intake PCAP plugin',
    url='https://github.com/ContinuumIO/intake-pcap',
    maintainer='Joseph Crail',
    maintainer_email='jbcrail@gmail.com',
    license='BSD',
    packages=find_packages(),
    entry_points={
        'intake.drivers': [
            'pcap = intake_pcap.source:PCAPSource',
        ]},
    package_data={'': ['*.pcap', '*.yml', '*.html']},
    include_package_data=True,
    install_requires=requires,
    long_description=open('README.md').read(),
    zip_safe=False,
)
