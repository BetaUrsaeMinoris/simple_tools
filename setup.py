# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/10 17:20
# @Version     : Python 3.6.4
from setuptools import setup

import simple_tools

install_requires = [
    # 'pycryptodome',
    # 'pyexecjs',
    # 'pymongo',
    # 'redis',
    'requests',
    # 'rsa',
]
setup(
    name='simple_tools',
    version=simple_tools.__version__,
    url='https://github.com/lijinquan123/simple_tools/',
    license='MIT License',
    author='lijinquan123',
    install_requires=install_requires,
    description='some simple but useful tools',
    long_description='some simple but useful tools',
    packages=['simple_tools'],
    include_package_data=True,
    package_data={"simple_tools": ["binaries/*"]},
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
        'Programming Language :: Python :: 3.11.7',
        'Programming Language :: Python',
        'Topic :: Utilities',
    ],
    extras_require={}
)
