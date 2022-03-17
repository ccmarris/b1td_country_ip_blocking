============
Introduction
============

This script forms part of the Threat Intelligence toolkit whose aim is to 
provide demonstration scripts for BloxOne ThreatDefense. These can be used
for API demonstrations, or help to simplify PoCs for Threat Intelligence, 
demonstrating the value of TIDE and Infoblox threat intel offerings.

The b1td_tide_data_feed.py script is designed to provide a simple demonstration of
generating a CSV export from TIDE 'active state' data for use in other elements
of the security ecosystem.

By default the script will generate a simplified CSV file format, however, 
options can be used to select either the complete (raw) CSV file format with all
fields, or even just the IOCs themselves.

This documentation assumes that you have python3 installed and are familiar with 
both the Unix command line, files and the use of pip/pip3 to install any 
appropriate modules.


