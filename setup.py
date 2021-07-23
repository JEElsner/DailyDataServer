import versioneer

from setuptools import setup, find_packages

setup(name='DailyDataServer',
      version=versioneer.get_version(),
      cmdclass=versioneer.get_cmdclass(),
      description='Web server to store and update time log information',
      url='https://github.com/JEElsner/DailyDataServer',
      author='Jonathan Elsner',
      author_email='jeelsner@outlook.com',
      packages=find_packages(),
      python_requires='>=3',
      # TODO
      # licence='',
      # classifiers=[],
      # keywords='',
      # project_urls=[]
      )
