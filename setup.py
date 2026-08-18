#!/usr/bin/env python3
"""
Setup configuration for Vanguard EDR - Endpoint Detection & Response System
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vanguard-edr",
    version="1.0.0",
    author="Gautam Karat",
    author_email="gautamkarat@gmail.com",
    description="Full-stack Endpoint Detection & Response (EDR) system with real-time threat detection and active remediation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/novicecoder10/vanguard",
    project_urls={
        "Bug Tracker": "https://github.com/novicecoder10/vanguard/issues",
        "Documentation": "https://github.com/novicecoder10/vanguard/blob/main/docs/DOCUMENTATION.md",
        "Source Code": "https://github.com/novicecoder10/vanguard",
    },
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.9",
    install_requires=[
        "flask>=2.0.0",
        "customtkinter>=5.0.0",
        "pywin32>=305",
        "tensorflow>=2.4.0",
        "tf-keras>=2.11.0",
        "numpy>=1.20.0",
        "watchdog>=2.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "black>=21.0",
            "flake8>=3.9.0",
            "mypy>=0.910",
        ],
        "frida": [
            "frida>=15.0.0",
            "frida-tools>=11.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vanguard-agent=vanguard_agent.main_gui:main",
            "vanguard-server=vanguard_server.server:main",
            "vanguard-service=vanguard_agent.vanguard_service:main",
        ],
    },
    include_package_data=True,
    keywords=[
        "edr",
        "endpoint-detection-response",
        "threat-detection",
        "malware-detection",
        "security-monitoring",
        "incident-response",
        "behavioral-analysis",
        "machine-learning",
        "windows-security",
        "sysmon",
    ],
    zip_safe=False,
)
