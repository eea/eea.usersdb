import os
from setuptools import setup, find_packages

NAME = "eea.usersdb"
PATH = NAME.split('.') + ['version.txt']
VERSION = open(os.path.join(*PATH)).read().strip()

setup(
    name=NAME,
    version=VERSION,
    author='Eau de Web',
    author_email='office@eaudeweb.ro',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=['python-ldap', 'colander', 'phonenumbers', 'six'],
)
