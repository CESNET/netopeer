from distutils.core import setup

setup(name='netopeer-configurator',
      version='0.9.0',
      author='Radek Krejci',
      author_email='rkrejci@cesnet.cz',
      description='Tool for the first configuration of the netopeer-server NETCONF server.',
      url='https://netopeer.googlecode.com',
      scripts=['netopeer-configurator'],
      packages=['netopeer'],
      platforms=['Linux'],
      license='BSD License',
      )