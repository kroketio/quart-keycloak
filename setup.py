"""
Quart-OpenID
-------------
Adds OpenID Connect support to your Quart application.
"""
from setuptools import setup

with open('README.md') as f:
    long_description = f.read()


INSTALL_REQUIRES = open("requirements.txt").read().splitlines()

setup(
    name='Quart-OpenID-Session',
    version='1.0.0',
    url='https://github.com/sferdi0/quart-openid-session',
    author='Sander',
    author_email='sander@sanderf.nl',
    description='Add identity providers to your Quart application',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=['quart_openid'],
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
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
