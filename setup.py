from setuptools import setup

setup(
    name='r2ai',
    version='0.5.0',
    packages=[
        'r2ai',
    ],
    install_requires=[
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
    },
)
