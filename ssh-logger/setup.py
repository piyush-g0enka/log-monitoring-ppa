from setuptools import setup, find_packages

setup(
    name='ssh-logger',
    version='1.1.0',
    description='logging of ssh authentication events',
    author='Piyush Goenka',
    author_email='goenkapiyush5@gmail.com',
    license='MIT',
    install_requires=['firebase-admin>=6.0.0'],
    packages=find_packages(),
    entry_points=dict(
        console_scripts=['ssh_logger=src.main:run_logger']
    )
)
