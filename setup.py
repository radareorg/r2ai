"""The classic setuptools python file."""

from setuptools import setup
import r2ai

with open("README.md", encoding = "utf-8") as fd:
    readme = fd.read()

setup(
    name ='r2ai',
    version = r2ai.VERSION,
    description = "Applying language models on radare2 for reverse engineering and fun purposes",
    long_description = readme,
    long_description_content_type = "text/markdown",
    author = "pancake",
    author_email = "pancake@nopcode.org",
    url = "https://www.radare.org/",
    packages = [
        'r2ai',
    ],
    install_requires = [
        'rich',
        'r2pipe',
        'inquirer',
        'llama-cpp-python',
        'huggingface_hub',
        'appdirs',
        'unidecode',
        'jsonref',
        'transformers',
        'pydantic',
        'torch',
    ],
    entry_points = {
        'console_scripts': [
            'r2ai = r2ai.main:main'
        ]
    }
)
