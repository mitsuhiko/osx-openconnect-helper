from setuptools import setup

setup(
    name='osx-openconnect-helper',
    version='0.4',
    description='Wrapper around openconnect and the system keychain',
    license='BSD',
    author='Armin Ronacher',
    author_email='armin.ronacher@active-4.com',
    url='https://github.com/mitsuhiko/osx-openconnect-helper',
    py_modules=['openconnect_helper'],
    install_requires=[
        'Click',
        'toml',
        'requests',
    ],
    entry_points='''
    [console_scripts]
    openconnect-helper=openconnect_helper:cli
    '''
)
