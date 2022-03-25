=========================
BloxOne Block Country IPs
=========================

| Version: 0.1.3
| Author: Chris Marrison
| Email: chris@infoblox.com

Description
-----------

This script is designed to provide a quick way to access the Country IP data
that is available in BloxOne Threat Defense and use this to perform one of 
the following:

  - Create custom lists and apply these to a BloxOne Threat Defense security
    policy
  - Output to a NIOS RPZ CSV import format
  - Output to a simple CSV for use with your security ecosystem


Prerequisites
-------------

Python 3.7 or above
bloxone module >= 0.8.10


Installing Python
~~~~~~~~~~~~~~~~~

You can install the latest version of Python 3.x by downloading the appropriate
installer for your system from `python.org <https://python.org>`_.

.. note::

  If you are running MacOS Catalina (or later) Python 3 comes pre-installed.
  Previous versions only come with Python 2.x by default and you will therefore
  need to install Python 3 as above or via Homebrew, Ports, etc.

  By default the python command points to Python 2.x, you can check this using 
  the command::

    $ python -V

  To specifically run Python 3, use the command::

    $ python3


.. important::

  Mac users will need the xcode command line utilities installed to use pip3,
  etc. If you need to install these use the command::

    $ xcode-select --install

.. note::

  If you are installing Python on Windows, be sure to check the box to have 
  Python added to your PATH if the installer offers such an option 
  (it's normally off by default).


Modules
~~~~~~~

Non-standard modules:

    - bloxone 0.8.10+

These are specified in the *requirements.txt* file.

The latest version of the bloxone module is available on PyPI and can simply be
installed using::

    pip3 install bloxone --user

To upgrade to the latest version::

    pip3 install bloxone --user --upgrade

Complete list of modules::

    import bloxone
    import os
    import shutil
    import logging
    import argparse
    import ipaddress
    import json
    import pkg_resources


Installation
------------

The simplest way to install and maintain the tools is to clone this 
repository::

    % git clone https://github.com/ccmarris/b1td_country_ip_blocking


Alternative you can download as a Zip file.


Basic Configuration
-------------------

The script utilises a bloxone.ini file as used by the bloxone module.

bloxone.ini
~~~~~~~~~~~

The *bloxone.ini* file is used by the bloxone module to access the bloxone
API. A sample inifile for the bloxone module is shared as *bloxone.ini* and 
follows the following format provided below::

    [BloxOne]
    url = 'https://csp.infoblox.com'
    api_version = 'v1'
    api_key = '<you API Key here>'

Simply create and add your API Key, and this is ready for the bloxone
module used by the automation demo script. This inifile should be kept 
in a safe area of your filesystem. 

Use the --config/-c option to specify the ini file.


Usage
-----

The b1td_country_ip_blocking.py uses TIDE as the source of the IP data. 

The prime use of the data is to create appropriate Custom Lists within
BloxOne Threat Defense Cloud and optionally automatically apply this to a 
security policy.

The data also be output to screen or file in either a simple CSV
file format or NIOS CSV import format to create an RPZ for use elsewhere 
in your security ecosystem.

This allows the script to be used for both demonstration purposes of the
automation capabilities provide by the BloxOne APIs.

The script supports -h or --help on the command line to access the options 
available::

    % ./b1td_country_ip_blocking.py --help
    usage: b1td_country_ip_blocking.py [-h] [-o OUTPUT] [-c CONFIG] 
    [-C COUNTRIES] [-p POLICY] [-d] (-l CUSTOM_LIST | -n | -s)

    B1TD Country IPs

    optional arguments:
      -h, --help            show this help message and exit
      -o OUTPUT, --output OUTPUT
                            Output to <filename>
      -c CONFIG, --config CONFIG
                            Overide Config file
      -C COUNTRIES, --countries COUNTRIES
                            Country or list of comma delimited countries
      -p POLICY, --policy POLICY
                            Name of security policy to add custom lists
      -d, --debug           Enable debug messages
      -l CUSTOM_LIST, --custom_list CUSTOM_LIST
                            Base name for custom lists in BloxOne TD
      -n, --nios            NIOS RPZ CSV Output
      -s, --subnets         Output CIDR subnets in simple CSV
      
.. note::

    Country used are for illustration purposes only.


Generate a simple CSV
~~~~~~~~~~~~~~~~~~~~~

Use this to generate a CSV of format *subnet,country* this is a good test mode
to ensure script is working as expected.

::

    % ./b1td_country_ip_blocking.py -c <path to inifile> --countries Somalia --subnets
    % ./b1td_country_ip_blocking.py -c <path to inifile> -C SO -s -o <filename>
    

Generate NIOS RPZ CSV Import
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use this to generate a CSV Import file for NIOS RPZ::

    % ./b1td_country_ip_blocking.py -c bloxone.ini -C Italy --nios


Create a Custom List in BloxOne Threat Defense
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This mode will automatically create a custom list in BloxOne Threat Defense
and optionally append this to the specified security policy. Custom lists
only support /24 or smaller subnet definitions at this time and so the script
automatically splits larger networks in to /24s. The script will automatically
create the appropriate number of custom lists needed due to the 50,000 items
per custom list and uses the base_name (-l/--custom_list) with a postfix of 
the format -N where N is a counter starting from 0. If there are less than
50k items then the base_name is used as is.

Examples::

  % ./b1td_country_ip_blocking.py -c bloxone.ini -C So -l mylist
  % ./b1td_country_ip_blocking.py -c bloxone.ini -C So,Russia -l mylist -p mypolicy


License
-------

This project, and the bloxone module are licensed under the 2-Clause BSD License
- please see LICENSE file for details.


Aknowledgements
---------------

Thanks to Tom Grimes for initial user testing.
