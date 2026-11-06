from setuptools import setup, find_packages
import os

readme_path = os.path.join(os.path.dirname(__file__), "README.md")
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, "r", encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="fmagenticl",
    version="1.4.0",
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn[standard]>=0.20.0",
        "redis>=5.0.0",
        "pydantic>=1.10.0,<3.0.0",
        "requests>=2.30.0",
        "httpx>=0.24.0",
        "cryptography>=41.0.0",
        "jsonpatch>=1.33",
    ],
    entry_points={
        "console_scripts": [
            "fmagenticl-server=fmagenticl.server.main:main",
        ]
    },
    author="FMagenticL Collective",
    author_email="maintainers@fmagenticl.org",
    description="FMagenticL Self-Healing Registry Daemon, Client, and Remote Streamable MCP",
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
