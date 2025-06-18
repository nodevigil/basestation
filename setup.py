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
    version="1.0.0",
    description="DePIN Infrastructure Scanner with Agentic Architecture",
    long_description="A comprehensive infrastructure scanner for DePIN networks with agentic architecture for reconnaissance, scanning, processing, and publishing security analysis results.",
    author="DePIN Team",
    author_email="",
    url="",
    packages=find_packages(),
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
