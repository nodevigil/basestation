"""
Setup script for DePIN Infrastructure Scanner
"""

from setuptools import setup, find_packages

# Read requirements from requirements.txt
def read_requirements():
    with open('requirements.txt', 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="basestation",
    version="1.0.0",
    description="PGDN - Agentic DePIN Infrastructure Scanner",
    long_description="A comprehensive infrastructure scanner for DePIN networks with agentic architecture for reconnaissance, scanning, processing, and publishing security analysis results.",
    author="DePIN Team",
    author_email="",
    url="",
    packages=[
        'pgdn',
        'pgdn.agents',
        'pgdn.agents.discovery',
        'pgdn.agents.process', 
        'pgdn.agents.publish',
        'pgdn.agents.recon',
        'pgdn.agents.report',
        'pgdn.agents.scan',
        'pgdn.agents.score',
        'pgdn.agents.signature',
        'pgdn.core',
        'pgdn.memory',
        'pgdn.models',
        'pgdn.repositories',
        'pgdn.services',
        'pgdn.utils',
        'pgdn.scanning',
        'pgdn.storage',
        'pgdn.web_probes',
        'pgdn.tasks',
        'pgdn.tools'
    ],
    package_dir={
        'pgdn.core': 'core',
        'pgdn.memory': 'memory', 
        'pgdn.models': 'models',
        'pgdn.repositories': 'repositories',
        'pgdn.services': 'services',
        'pgdn.utils': 'utils',
        'pgdn.scanning': 'scanning',
        'pgdn.storage': 'storage',
        'pgdn.web_probes': 'web_probes',
        'pgdn.tasks': 'tasks',
        'pgdn.tools': 'tools'
    },
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
