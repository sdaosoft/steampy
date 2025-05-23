import sys

from setuptools import setup

if sys.version_info < (3, 12):
    sys.exit("Python < 3.12 is not supported")

version = '1.2.0'

setup(
    name='steampy',
    packages=['steampy', 'test', 'examples'],
    version=version,
    description='A Steam lib for trade automation',
    author='Michał Bukowski',
    author_email='gigibukson@gmail.com',
    license='MIT',
    url='https://github.com/bukson/steampy',
    download_url='https://github.com/bukson/steampy/tarball/' + version,
    keywords=['steam', 'trade'],
    classifiers=[],
    install_requires=[
        "requests",
        "beautifulsoup4",
        "rsa",
    ],
)
