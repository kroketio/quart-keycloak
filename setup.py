"""
Quart-Keycloak
-------------
Add Keycloak OpenID Connect to your Quart application.
"""
from setuptools import setup

with open('README.md') as f:
    long_description = f.read()


INSTALL_REQUIRES = open("requirements.txt").read().splitlines()

setup(
    name='Quart-Keycloak',
    version='1.0.8',
    url='https://github.com/kroketio/quart-keycloak',
    author='Kroket Ltd.',
    author_email='code@kroket.io',
    description='Add Keycloak OpenID Connect to your Quart application',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=['quart_keycloak'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=INSTALL_REQUIRES,
    tests_require=INSTALL_REQUIRES + ["asynctest", "hypothesis", "pytest", "pytest-asyncio"],
    extras_require={"dotenv": ["python-dotenv"]},
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: BSD License",
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
