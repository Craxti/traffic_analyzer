from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="traffic_analyzer",
    version="0.1.1",
    author="Craxti",
    author_email="fetis.dev@gmail.com",
    description="A network traffic analysis library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/craxti/traffic_analyzer",
    project_urls={
        "Bug Tracker": "https://github.com/craxti/traffic_analyzer/issues",
        "Documentation": "https://github.com/craxti/traffic_analyzer/wiki",
    },
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "scapy>=2.5.0",
        "matplotlib>=3.7.2",
        "tabulate>=0.9.0",
        "psutil>=5.9.5",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "flake8>=6.1.0",
            "black>=23.7.0",
            "isort>=5.12.0",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "traffic-analyzer=traffic_analyzer.cli:main",
        ],
    },
)
