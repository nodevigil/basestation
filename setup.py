"""
Setup script for DePIN Infrastructure Scanner
"""

from setuptools import setup, find_packages

# Read requirements from requirements.txt
def read_requirements():
    with open('requirements.txt', 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="pgdn",
    version="1.0.1",
    description="PGDN - DePIN Infrastructure Scanner Library",
    long_description="A clean library for DePIN infrastructure scanning with support for custom scanners like Sui and Filecoin.",
    author="DePIN Team",
    author_email="",
    url="",
    packages=find_packages(),
    package_data={
        'pgdn': ['protocols/*.yaml', 'protocols/*.yml'],
    },
    include_package_data=True,
    py_modules=['cli', 'pgdn_entry'],
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'pgdn=pgdn_entry:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
)