from distutils.core import setup
setup(name='multiapt',
  version='0.01',
  description='Remote apt-get upgrade automator',
  author='Christian Hofstaedtler',
  author_email='ch@zeha.at',
  packages=['multiapt'],
  package_dir={'': 'lib'},
  scripts=['multiapt']
  )
