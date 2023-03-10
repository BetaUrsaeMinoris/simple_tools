# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/10 17:20
# @Version     : Python 3.6.4
from setuptools import setup

import simple_tools

setup(
    name='simple_tools',
    version=simple_tools.__version__,
    url='https://github.com/lijinquan123/simple_tools/',
    license='MIT License',
    author='lijinquan123',
    install_requires=[
        'pycryptodome==3.11.0',
        'PyExecJS==1.5.1',
        'pymongo==3.6.1',
        'redis==2.10.6',
        'requests>=2.26.0',
    ],
    description='some simple but useful tools',
    long_description='some simple but useful tools',
    packages=['simple_tools'],
    include_package_data=True,
    platforms='any',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'License :: MIT License',
        'Natural Language :: English',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python',
        'Topic :: Utilities',
    ],
    extras_require={}
)
