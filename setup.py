from setuptools import setup
from setuptools import find_packages


version = '0.1.0.dev1'

# Remember to update local-oldest-requirements.txt when changing the minimum
# acme/certbot version.
install_requires = [
    'acme>=0.21.1',
    'certbot>=0.21.1',
    'aliyun-python-sdk-core>=2.6.0',
    'aliyun-python-sdk-alidns>=2.0.7',
    'setuptools',
    'zope.interface',
]

setup(
    name='certbot-dns-alidomain',
    version=version,
    description="Aliyun DNS Authenticator plugin for Certbot",
    url='https://github.com/ant-sir/certbot-dns-alidomain',
    author="zhu.yanlei",
    author_email='zhuyanleigm@gmail.com',
    license='Apache License 2.0',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,

    entry_points={
        'certbot.plugins': [
            'dns-aliyun = certbot_dns_aliyun.dns_aliyun:Authenticator',
        ],
    },
)
