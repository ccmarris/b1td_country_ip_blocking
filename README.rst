*****************
Quick Start Guide
*****************

.. note::
  For full documentation, please see the docs directory.

Requirements
============

This script requires Python 3.x and utilises the :mod:'bloxone' python module. 

The :mod:'bloxone' module can be install using pip::

  pip3 install bloxone


Usage
=====

The simplest place to start is to run the :mod:`b1td_tide_data_feed.py` Script
with the -h or --help option to display the simple usage help text.::

  $ ./b1td_tide_data_feed.py --help
  usage: b1td_tide_data_feed.py [-h] [-o OUTPUT] [-c CONFIG] 
                          [-f FEEDTYPE] [-t THREATCLASS] [-T THREATPROPERTY]
                          [-p PROFILE] [-r RLIMIT] [-i] [-d]

  Simple TIDE data feed example

  optional arguments:
    -h, --help            show this help message and exit
    -o OUTPUT, --output OUTPUT
                          Output to <filename>
    -c CONFIG, --config CONFIG
                          Overide Config file
    -f FEEDTYPE, --feedtype FEEDTYPE
                          Specify feed type <host(default), ip, url>
    -t THREATCLASS, --threatclass THREATCLASS
                          Specify Threat Class for feed
    -T THREATPROPERTY, --threatproperty THREATPROPERTY
                          Specify Threat Property for feed
    -p PROFILE, --profile PROFILE
                          Set profile for feed (default=IID)
    -r RLIMIT, --rlimit RLIMIT
                          Set limit for number of records (default=100)
    -i, --iocsonly        Output IOCs only
    -d, --debug           Enable debug messages


Configuring the API Key
========================

Although the script will accept your API Key as part of the command line using
the --apikey / -k option, :mod:`b1td_tide_data_feed` supports the use of a bloxone.ini file to store the API Key.

.. note::
  Using the --apikey/-k option overrides any API Key stored in
  the ``bloxone.ini``

By default :mod:`b1td_tide_data_feed` will look for a ``bloxone.ini`` file in the
current working directory. An alternate ini file can be specified with the
the --config/-c option. This allows you to call the script with alternative ini
files as needed without the need to use the --apikey option to use alternate 
authentication credentials.

ini File Format
---------------

A sample bloxone.ini file is included with this package, however, the simple
format is shown below::

  [BloxOne]
  url = 'https://csp.infoblox.com'
  api_version = 'v1'
  api_key = '<you API Key here>'

Add you API Key from the portal to the :data:`api_key` property and save the
file. An example, using a fictious key is shown::

  [BloxOne]
  url = 'https://csp.infoblox.com'
  api_version = 'v1'
  api_key = c3042afe88ea9a1a24b8fb220e203343a1e4ee08d1c8a00331594c802ad50a4c

Once this step is complete you will not have to use the --apikey / -k option
unless you specifically want to override the configured key.

Simple Examples
===============

Once the :data:`api_key` is defined in the bloxone.ini the script can be run without
any options using the defaults, to generate 100 CSV lines of type HOST and using IID 
as the profile displayed on screen.

::
  $ ./b1td_tide_data_feed.py

This can easily be sent to a file using the --output <filename> option::

  $ ./b1td_tide_data_feed.py --output mydatafeed.csv

It is also possible to output only the IOCs without the metadata using the 
--iocsonly option::

  $ ./b1td_tide_data_feed.py -c bloxone.ini --iocsonly --output mydatafeed.txt
