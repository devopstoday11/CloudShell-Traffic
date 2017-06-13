
from setuptools import setup, find_packages
import os

with open(os.path.join('version.txt')) as version_file:
    version_from_file = version_file.read().strip()

with open('requirements.txt') as f_required:
    required = f_required.read().splitlines()

with open('test_requirements.txt') as f_tests:
    required_for_tests = f_tests.read().splitlines()

setup(
    name='cloudshell-traffic',
    url='https://github.com/QualiSystems/cloudshell-traffic',
    author='QualiSystems',
    author_email='info@qualisystems.com',
    packages=find_packages(),
    install_requires=required,
    test_suite='cloudshell.traffic.test',
    tests_require=required_for_tests,
    version=version_from_file,
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
    extras_require={
        'testing': ['pytest'],
    }
)
