#!/usr/bin/env python3
"""
ARECON 2.0 Setup Script
Author: Rakshit Walia
Copyright: (c) 2026 Rakshit Walia. All rights reserved.
License: MIT License
"""

from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="arecon",
    version="2.0.0",
    author="Rakshit Walia",
    author_email="rakshitwalia@users.noreply.github.com",
    description="Advanced Attack Surface Management & Bug Bounty Reconnaissance Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Rakshitwalia01/Arecon",
    license="MIT",
    packages=find_packages(),
    py_modules=["recon", "arecon_web", "arecon_gui", "launch"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "arecon=recon:main",
            "arecon-web=arecon_web:launch_web_gui",
            "arecon-gui=arecon_gui:main",
            "arecon-launch=launch:main",
        ],
    },
)
