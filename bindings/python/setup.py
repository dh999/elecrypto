"""
Setup script for Elecrypto Python bindings
"""

from setuptools import setup, find_packages
import os

# Read README
readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()

setup(
    name='elecrypto',
    version='0.1.0',
    description='Cross-platform cryptographic library with post-quantum support',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Elecrypto Contributors',
    url='https://github.com/yourusername/elecrypto',
    license='MIT',
    packages=find_packages(),
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security :: Cryptography',
    ],
    keywords='cryptography encryption aes chacha20 ed25519 post-quantum',
    project_urls={
        'Bug Reports': 'https://github.com/yourusername/elecrypto/issues',
        'Source': 'https://github.com/yourusername/elecrypto',
    },
)
