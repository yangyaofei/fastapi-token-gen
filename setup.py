#!/usr/bin/env python3
# coding : utf-8
from setuptools import setup, find_packages
import fastapi_token

# with open("README.md", encoding="utf-8") as f:
#     readme = f.read()
dependencies = [
    "cryptography==3.4.7",
    "PyJWT==2.1.0",
    "fastapi>=0.65.2",
    "pydantic>=1.8.2",
    "typing>=3.7.4.3",
    "cidrize>=2.0.0"
]
setup(
    name='fastapi-token-gen',
    version=fastapi_token.__version__,
    packages=find_packages(),
    url='',
    license='MIT',
    author='yangyaofei',
    author_email='yangyaofei@gmail.com',
    description='Gen token from client',
    long_description="",
    long_description_content_type="text/markdown",
    python_requires='>=3.6',
    install_requires=dependencies,
    include_package_data=True,
    test_suite='tests',
    platforms=[
        'win32',
        'win64',
        'linux32',
        'linux64'
        'darwin',
    ]
)
