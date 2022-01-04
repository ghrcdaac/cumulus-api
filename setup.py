#!/usr/bin/env python
import os
from codecs import open
from setuptools import setup, find_packages
from importlib import import_module

here = os.path.abspath(os.path.dirname(__file__))
try:
    __version__ = import_module('cumulus_api.version').__version__
except:
    __version__ = "v1.1.1"

with open(os.path.join(here, 'requirements.txt'), encoding='utf-8') as f:
    reqs = f.read().split('\n')
install_requires = [x.strip() for x in reqs]

setup(
    name='cumulus-api',
    version=__version__,
    author='Abdelhak Marouane',
    description='Python package using Cumulus API which allows developers to interact with the Cumulus Framework,'
                ' such as monitoring status or creating, editing, and deleting records ',
    url='https://gitlab.com/ghrc-cloud/cumulus-api',
    license='Apache 2.0',
    classifiers=[
        'Framework :: Pytest',
        'Topic :: Scientific/Engineering/Developers',
        'Intended Audience :: Developers',
        'License :: Freeware',
        'Programming Language :: Python :: 3+',
    ],
    packages=find_packages(exclude=['docs', 'tests*']),
    include_package_data=True,
    install_requires=install_requires
)
