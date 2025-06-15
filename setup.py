#!/usr/bin/env python3
"""
Setup script for Meshtastic UDP Monitor
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Real-time Meshtastic mesh network traffic monitor"

# Read requirements
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name="meshtastic-udp-monitor",
    version="1.0.0",
    author="Carl Edwards",
    description="Real-time Meshtastic mesh network traffic monitor",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/carledwards/meshtastic-udp-monitor",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Communications :: Ham Radio",
        "Topic :: Internet :: Log Analysis",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.7",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "meshtastic-udp-monitor=meshtastic_udp_monitor:main",
            "mesh-monitor=meshtastic_udp_monitor:main",
        ],
    },
    keywords="meshtastic, mesh, network, monitoring, udp, lora, radio",
    project_urls={
        "Bug Reports": "https://github.com/carledwards/meshtastic-udp-monitor/issues",
        "Source": "https://github.com/carledwards/meshtastic-udp-monitor",
        "Documentation": "https://github.com/carledwards/meshtastic-udp-monitor/blob/main/README.md",
    },
)
