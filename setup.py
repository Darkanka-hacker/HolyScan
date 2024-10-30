from setuptools import setup, find_packages

setup(
    name="HolyScan",
    version="1.0",
    description="A network scanning tool with multiple plugins.",
    url="https://github.com/Darkanka-hacker/HolyScan",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "PyQt5",
        "cryptography",
        "aioquic",
        # add more here
    ],
    entry_points={
        "console_scripts": [
            "holyscan=holyscan:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
