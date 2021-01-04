#!/usr/bin/env python3
# coding : utf-8
from setuptools import setup, find_packages
import fastapi_token

# with open("README.md", encoding="utf-8") as f:
#     readme = f.read()
dependencies = [
    "cryptography==3.3.1",
    "PyJWT==1.7.1",
    "fastapi==0.63.0",
    "starlette==0.13.6",
    "pydantic==1.7.3",
    "typing==3.7.4.3"
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