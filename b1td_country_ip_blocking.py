#!/usr/bin/env python3
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
"""
------------------------------------------------------------------------

 Description:
  Sample script using BloxOne Threat Defense for Country IP enforcement
  within your security ecosystem. This script can produce:
    1. A list of CIDR notation IP subnets associated with a country or 
       countries
    2. Create a custom list in BloxOne to apply to a security policy
    3. Create a NIOS RPZ CSV file for import in to NIOS

 Requirements:
  Requires bloxone >= 0.8.8

 Usage:
    Use b1td_country_ip_blocking.py --help for details on options

 Author: Chris Marrison

 Date Last Updated: 20220322

Copyright 2022 Chris Marrison / Infoblox

Redistribution and use in source and binary forms,
with or without modification, are permitted provided
that the following conditions are met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

------------------------------------------------------------------------
"""
__version__ = '0.0.5'
__author__ = 'Chris Marrison'
__author_email__ = 'chris@infoblox.com'

from distutils.sysconfig import customize_compiler
import bloxone
import os
import shutil
import logging
import argparse

# ** Global Variables **
log = logging.getLogger(__name__)

# ** Functions **

def parseargs():
    '''
    Parse Arguments Using argparse

    Parameters:
        None

    Returns:
        Returns parsed arguments
    '''
    parse = argparse.ArgumentParser(description='B1TD Country IPs')
    group = parse.add_mutually_exclusive_group(required=True)
    parse.add_argument('-o', '--output', type=str,
                       help="Output to <filename>", default="")
    parse.add_argument('-c', '--config', type=str, default='bloxone.ini',
                       help="Overide Config file")
    parse.add_argument('-C', '--countries', type=str,
                       help="Country or list of comma delimited countries")
    parse.add_argument('-d', '--debug', action='store_true',
                       help="Enable debug messages")
    group.add_argument('-l', '--custom_list', type=str,
                       help="Name of custom list to create in BloxOne TD")
    group.add_argument('-n', '--nios', action='store_true',
                       help="NIOS RPZ CSV Output")
    group.add_argument('-s', '--subnets', action='store_true',
                       help="Output CIDR subnets")

    return parse.parse_args()


def setup_logging(debug):
    '''
     Set up logging

     Parameters:
        debug (bool): True or False.

     Returns:
        None.

    '''
    # Set debug level
    if debug:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s %(levelname)s: %(message)s')

    return


def open_file(filename):
    '''
     Attempt to open file for output

     Parameters:
        filename (str): Name of file to open.

     Returns:
        file handler object.

    '''
    if os.path.isfile(filename):
        backup = filename+".bak"
        try:
            shutil.move(filename, backup)
            log.info("Outfile exists moved to {}".format(backup))
            try:
                handler = open(filename, mode='w')
                log.info("Successfully opened output file {}.".format(filename))
            except IOError as err:
                log.error("{}".format(err))
                handler = False
        except shutil.Error:
            log.warning("Could not back up existing file {}, "
                        "exiting.".format(filename))
            handler = False
    else:
        try:
            handler = open(filename, mode='w')
            log.info("Successfully opened output file {}.".format(filename))
        except IOError as err:
            log.error("{}".format(err))
            handler = False

    return handler


def parse_countries(countries):
    '''
    Parse string in to list

    Parameters:
        countries (str): String from command line

    Returns:
        list of countries
    '''
    list_of_countries = []
    if isinstance(countries, str):
        list_of_countries = countries.split(',')
    
    return list_of_countries


def get_subnets(b1td, countries):
    '''
    Build list of subnets for list of countries

    Parameters:
        b1td (obj): bloxone.b1td instance
        countries (list): list of countries
    
    Returns:
        subnets (list): List of dict {cidr, country}
    '''
    subnets = []
    for country in countries:
        try:
            response = b1td.get_country_ips(country)
            if response.status_code in b1td.return_codes_ok:
                subnets += response.json().get('country_ip')
            else:
                logging.error(f'API error: {response.status_code} - ' +
                              f'{response.text}')
        except bloxone.CountryISOCodeNotFound:
            logging.error(f'Country {country} not found.')

    return subnets


def output_csv(subnets, outfile=None):
    '''
    Output IP list as CSV

    Parameters:
        subnets (list of dict): IP subnet list
        outfile (obj): filehandler
    '''
    csvrow = ""
    csvheader = ""
    csvrow = ""

    headers = [ 'cidr', 'country' ]
    
    log.debug('Building CSV from IP List dataset')
    # Build Header String
    for item in headers:
        csvheader += item + ','

    # Trim final comma
    csvheader = csvheader[:-1]

    # Output CSV Header
    if outfile:
        log.debug(f'Outputting header data to file: {outfile}')
        print(csvheader, file=outfile)
    else:
        log.debug(f'Outputting header data to stdout')
        print(csvheader)
    
    # Ootput CSV Data
    log.debug('Generating simple CSV rows')
    for subnet in subnets:
        csvrow = ""
        # Build CSV Row
        for column in headers:
            if column in subnet.keys():
                csvrow += str(subnet[column]) + ','
            else:
                csvrow += ','
        csvrow = csvrow[:-1]

        if outfile:
            print(csvrow, file=outfile)
        else:
            print(csvrow)
            
    return


def output_nios_csv(subnets, 
                    zone='countryips.rpz.local', 
                    view='default',
                    outfile=None):
    '''
    Create CSV in NIOS RPZ Import format

    Parameters:
        subnets (list): List of dict of subnets
        zone (str): rpz zone name
        rpz_parent (str): RPZ parent zone

    '''
    reverse_labels= bloxone.utils.reverse_labels(zone)

    # Print CSV Header
    if outfile:
        print('header-responsepolicycnamerecord,fqdn*,_new_fqdn,canonical_name,' +
              'comment,disabled,parent_zone,ttl,view', file=outfile)
    else:
        print('header-responsepolicycnamerecord,fqdn*,_new_fqdn,canonical_name,' +
              'comment,disabled,parent_zone,ttl,view')

    # Process subnets and generate CSV lines
    for subnet in subnets:
        cidr = subnet.get('cidr')
        country = subnet.get('country')
        cidr = bloxone.utils.reverse_labels(cidr.replace('/', '.'))

        line = ( f'responsepolicycnamerecord,{cidr}.{zone},,,Country: {country},False,' +
                 f'{reverse_labels},,{view}' )
        
        if outfile:
            print(line, file=outfile)
        else:
            print(line)

    return


def generate_custom_list(b1cfg, custom_list='', subnets=[], append=False):
    '''
    Create BloxOne custom liss

    Parameters:
        b1cfg (obj): bloxone.b1cfg() class object
        subnets (list): list of subnets
        custom_list (str): name of custom list
        append (bool): If list exists append data or not
    
    Returns:
        Bool: True if custom list successfully created/appended
    '''
    status = False
    nets = []
    b1tdc = bloxone.b1tdc(b1cfg)
    for subnet in subnets:
        cidr = subnet.get('cidr')
        country = subnet.get('country')
        nets.append({ "description": country, "item": cidr })

    id = b1tdc.get_custom_list(name=custom_list)
    if not id:
        response = b1tdc.create_custom_list(name=custom_list, 
                                            items_described=nets)
        if response.status_code in b1tdc.return_codes_ok:
            logging.info(f'Successfully created custom list: {custom_list}')
            status = True
        else:
            logging.error(f'Failed to create custom list: {custom_list}')
            logging.error(f'HTTP Response Code: {response.status_code}')
            logging.error(f'Content: {response.text}')
    else:
        if append:
            response = b1tdc.add_items_to_custom_list(name=custom_list, 
                                                      items_described=nets)
            if response.status_code in b1tdc.return_codes_ok:
                logging.info(f'Custom list {custom_list} appended.')
                status = True
            else:
                logging.error(f'Failed to append Custom list: {custom_list}')
                status = False
        else:
            logging.info(f'Custom list {custom_list} exists, please use ' +
                         f'--append if you wish to add to this list')
            status = False

    return status


def main():
    '''
    * Main *

    Core logic when running as script

    '''
    # Local variables
    exitcode = 0
    # Parse Arguments and configure
    args = parseargs()

    # Set up logging
    debug = args.debug
    configfile = args.config
    setup_logging(debug)
    outputfile = args.output
    countries = parse_countries(args.countries)
    csv = args.subnets
    nios = args.nios
    custom_list = args.custom_list

    # Initialise bloxone
    b1td = bloxone.b1td(configfile)

    # Set up output file
    if outputfile:
        outfile = open_file(outputfile)
        if not outfile:
            log.error('Failed to open output file for CSV.')
    else:
        outfile = False

    subnets = get_subnets(b1td, countries)

    # Parse args ensures one of these is set
    if csv:
        output_csv(subnets, outfile=outfile)
    if nios:
        output_nios_csv(subnets, outfile=outfile)
    if custom_list:
        generate_custom_list(configfile, subnets, custom_list)

    return exitcode


# ** Main **
if __name__ == '__main__':
    exitcode = main()
    raise SystemExit(exitcode)

# ** End Main **
