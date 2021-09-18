#!/usr/bin/env python3
# coding : utf-8
import os

from setuptools import setup, find_packages

import fastapi_token

dependencies = os.path.join(os.path.abspath(os.path.dirname(__file__)), "requirements.txt")
with open(dependencies, "r") as f:
    dependencies = f.read().split("\n")
setup(
    name='fastapi-token-gen',
    version=fastapi_token.__version__,
    packages=find_packages(),
    url='',
    license='MIT',
    author='yangyaofei',
    author_email='yangyaofei@gmail.com',
    description='Gen token for FastAPI',
    long_description="",
    long_description_content_type="text/markdown",
    python_requires='>=3.7',
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
