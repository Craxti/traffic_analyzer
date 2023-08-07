from setuptools import setup, find_packages

setup(
    name="traffic_analyzer",
    version="0.1",
    author="Craxti",
    author_email="fetis.dev@gmail.com",
    description="A network traffic analysis library",
    long_description="A library for capturing, analyzing, and visualizing network traffic.",
    url="https://github.com/yourusername/traffic_analyzer",
    packages=find_packages(),
    install_requires=[
        "scapy",
        "matplotlib",
        "tabulate"
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)
