#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import sys
import time


APNIC_DELEGATED_LATEST = "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"


def get_apnic_delegated():
    from urllib import request

    u = request.urlopen(APNIC_DELEGATED_LATEST)
    return u.read().decode('utf-8')


def generate_ipset(content, name, location_set, type_set, output_file):

    if 'ipv4' in type_set:
        cidr_trans = {}
        for i in range(0, 32):
            cidr_trans[2 ** (32 - i - 1)] = i + 1

    for line in content.splitlines():
        if line.startswith('#'):
            continue

        splits = line.split('|')
        if len(splits) == 7:
            '''
            This is a Record with 7 fields
            '''

            registry, cc, type_, start, value, _, _ = splits
            if registry != 'apnic':
                continue

            if cc in location_set and type_ in type_set:

                if type_ == 'ipv4':
                    '''
                    In the case of IPv4 address the count of hosts for this range. This count does not have to represent a CIDR range.

                    But. It seems that it is always a CIDR range in this particular file.
                    '''
                    mask = cidr_trans[int(value)]
                    output_file.write(
                        'add {} {}/{} -exist\n'.format(name, start, mask))

                elif type_ == 'ipv6':
                    '''
                    In the case of an IPv6 address the value will be the CIDR prefix length from the ‘first address’ value of <start>.
                    '''
                    output_file.write(
                        'add {} {}/{} -exist\n'.format(name, start, value))


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--name', '-n', help='Name of ipset',
                        type=str, required=True)
    parser.add_argument('--location', '-l', help='Location to be filtered, like CN',
                        nargs='+', type=str, required=True)
    parser.add_argument('--address-type', '-t', help='Address type, like ipv4, ipv6',
                        nargs='+', type=str, required=True, choices=['ipv4', 'ipv6'])
    parser.add_argument(
        '--output', '-o', help='Output file, default to stdout', type=str, required=False)

    args = parser.parse_args()

    name = args.name
    location_set = set(args.location)
    type_set = set(args.address_type)

    start_time = time.time()
    data = get_apnic_delegated()

    if hasattr(args, 'output'):
        with open(args.output, 'w') as fp:
            generate_ipset(data, name, location_set, type_set, fp)
    else:
        generate_ipset(data, name, location_set, type_set, sys.stdout)
