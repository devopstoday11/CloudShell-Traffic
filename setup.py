#!/usr/bin/env python
# encoding: utf-8

from setuptools import setup, find_packages

from cloudshell.traffic import __version__

with open('requirements.txt') as f_required:
    required = f_required.read().splitlines()

setup(
    name='cloudshell-traffic',
    url='https://github.com/QualiSystems/cloudshell-traffic',
    author='QualiSystems',
    author_email='info@qualisystems.com',
    packages=find_packages(),
    install_requires=required,
    test_suite='cloudshell.traffic.test',
    version=__version__,
    description='QualiSystems Python base class and utilities for traffic generators shells (chassis and controller)',
    include_package_data=True,
    license='Apache Software License',
    platforms='any',
    classifiers=[
        'Programming Language :: Python',
        'Development Status :: 4 - Beta',
        'Natural Language :: English',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Testing :: Traffic Generation'],
)
