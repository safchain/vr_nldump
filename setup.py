from setuptools import setup, find_packages

setup(name='vr_nldump',
    version='0.1',
    description='Capture a analyze sandesh netlink message.',
    author='Sylvain Afchain',
    author_email='safchain@gmail.com',
    url='https://github.com/safchain/vr_nldump',
    packages=find_packages(),
    install_requires=[
        'pyroute2',
        'pcapy'
    ],
    entry_points={
        'console_scripts': [
            'vr_nldump = vr_nldump.vr_nldump:main'
        ],
    }
)
