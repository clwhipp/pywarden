from setuptools import setup, find_packages

setup(
    name='pywarden',
    version='0.1',
    description='Contains a python wrapper for Bitwarden CLI interface.',
    long_description='',
    url='https://github.com/clwhipp/pywarden',
    packages=find_packages(
    ),
    entry_points = {
        'console_scripts': [
            'pybw=pywarden.command_line:main'
        ]
    },
    install_requires=[
        'click',
        'pyinstaller',
        'ruamel.yaml'
    ]
)