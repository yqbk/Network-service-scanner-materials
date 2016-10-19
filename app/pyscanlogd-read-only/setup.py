#Gets setuptools
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

#Normal setup.py starts here
import sys, os

version = '0.1'

setup(name='pyscanlogd',
      version=version,
      description="Pyscanlogd is a port scan detection tool written in Python",
      long_description="""\
Pyscanlogd is a port scan detection tool written in pure Python. It can
detect most fast port scans and even can detect port-scans of longer
duration upto an hour. It can run as a daemon as well as in the foreground.
""",
      # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
          'Development Status :: 5 - Stable',
          'Environment :: Console',
          'Environment :: Desktop Environment',
          'Intended Audience :: End Users/Desktop',
          'License :: GNU GPLv3 License',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          ],
      keywords='networking security python reconnaissance scanning tools',
      author='pythonhacker',
      author_email='python.thehacker@gmail.com',
      maintainer='pythonhacker',
      maintainer_email='python.thehacker@gmail.com',
      url='http://code.google.com/p/pyscanlogd',
      license='GPL',
      include_package_data = True,    # include everything in source control
      py_modules = ['scanlogger','timerlist','entry'],
      zip_safe=False,
      #install_requires=[
      #"python-twitter >= 0.6",
      #],
      entry_points="""
      [console_scripts]
        pyscanlogd = scanlogger:main
      """,
      )

