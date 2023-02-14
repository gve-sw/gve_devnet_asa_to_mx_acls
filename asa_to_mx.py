# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright (c) 2022 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Trevor Maco <tmaco@cisco.com>"
__copyright__ = "Copyright (c) 2022 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

import json
import re
import os
import sys
import itertools
import getopt

import meraki

from config import *

from socket import getservbyname

from ciscoconfparse import CiscoConfParse

from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich.prompt import Confirm

# Subnet / wildcard mask to CIDR prefix length lookup table
SUBNET_MASKS = {
    "128.0.0.0": "1",
    "127.255.255.255": "1",
    "192.0.0.0": "2",
    "63.255.255.255": "2",
    "224.0.0.0": "3",
    "31.255.255.255": "3",
    "240.0.0.0": "4",
    "15.255.255.255": "4",
    "248.0.0.0": "5",
    "7.255.255.255": "5",
    "252.0.0.0": "6",
    "3.255.255.255": "6",
    "254.0.0.0": "7",
    "1.255.255.255": "7",
    "255.0.0.0": "8",
    "0.255.255.255": "8",
    "255.128.0.0": "9",
    "0.127.255.255": "9",
    "255.192.0.0": "10",
    "0.63.255.255": "10",
    "255.224.0.0": "11",
    "0.31.255.255": "11",
    "255.240.0.0": "12",
    "0.15.255.255": "12",
    "255.248.0.0": "13",
    "0.7.255.255": "13",
    "255.252.0.0": "14",
    "0.3.255.255": "14",
    "255.254.0.0": "15",
    "0.1.255.255": "15",
    "255.255.0.0": "16",
    "0.0.255.255": "16",
    "255.255.128.0": "17",
    "0.0.0.127.255": "17",
    "255.255.192.0": "18",
    "0.0.63.255": "18",
    "255.255.224.0": "19",
    "0.0.31.255": "19",
    "255.255.240.0": "20",
    "0.0.15.255": "20",
    "255.255.248.0": "21",
    "0.0.7.255": "21",
    "255.255.252.0": "22",
    "0.0.3.255": "22",
    "255.255.254.0": "23",
    "0.0.1.255": "23",
    "255.255.255.0": "24",
    "0.0.0.255": "24",
    "255.255.255.128": "25",
    "0.0.0.127": "25",
    "255.255.255.192": "26",
    "0.0.0.63": "26",
    "255.255.255.224": "27",
    "0.0.0.31": "27",
    "255.255.255.240": "28",
    "0.0.0.15": "28",
    "255.255.255.248": "29",
    "0.0.0.7": "29",
    "255.255.255.252": "30",
    "0.0.0.3": "30",
    "255.255.255.254": "31",
    "0.0.0.1": "31",
    "255.255.255.255": "32",
    "0.0.0.0": "32",
}

# Regex patterns for all possible Cisco ASA line combinations (methodology: fix start pattern, all possible end
# patterns)
regex_patterns = [
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_subnet>\d+.\d+.\d+.\d+) (?P<src_mask>\d+.\d+.\d+.\d+) (?P<dst_subnet>\d+.\d+.\d+.\d+) (?P<dst_mask>\d+.\d+.\d+.\d+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_subnet>\d+.\d+.\d+.\d+) (?P<src_mask>\d+.\d+.\d+.\d+) host (?P<dst_ip>\d+.\d+.\d+.\d+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_subnet>\d+.\d+.\d+.\d+) (?P<src_mask>\d+.\d+.\d+.\d+) (?P<dst_ip>any4)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_subnet>\d+.\d+.\d+.\d+) (?P<src_mask>\d+.\d+.\d+.\d+) fqdn (?P<dst_fqdn>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_subnet>\d+.\d+.\d+.\d+) (?P<src_mask>\d+.\d+.\d+.\d+) object (?P<dst_obj>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_subnet>\d+.\d+.\d+.\d+) (?P<src_mask>\d+.\d+.\d+.\d+) object-group (?P<dst_obj_group>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',

    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) host (?P<src_ip>\d+.\d+.\d+.\d+) host (?P<dst_ip>\d+.\d+.\d+.\d+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) host (?P<src_ip>\d+.\d+.\d+.\d+) (?P<dst_subnet>\d+.\d+.\d+.\d+) (?P<dst_mask>\d+.\d+.\d+.\d+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) host (?P<src_ip>\d+.\d+.\d+.\d+) (?P<dst_ip>any4)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) host (?P<src_ip>\d+.\d+.\d+.\d+) fqdn (?P<dst_fqdn>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) host (?P<src_ip>\d+.\d+.\d+.\d+) object (?P<dst_obj>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) host (?P<src_ip>\d+.\d+.\d+.\d+) object-group (?P<dst_obj_group>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',

    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_ip>any4) host (?P<dst_ip>\d+.\d+.\d+.\d+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_ip>any4) (?P<dst_subnet>\d+.\d+.\d+.\d+) (?P<dst_mask>\d+.\d+.\d+.\d+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_ip>any4) (?P<dst_ip>any4 (echo|echo-reply|time-exceeded|unreachable))((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_ip>any4) (?P<dst_ip>any4)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_ip>any4) fqdn (?P<dst_fqdn>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_ip>any4) object (?P<dst_obj>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) (?P<src_ip>any4) object-group (?P<dst_obj_group>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',

    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object (?P<src_obj>\S+) (?P<dst_subnet>\d+.\d+.\d+.\d+) (?P<dst_mask>\d+.\d+.\d+.\d+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object (?P<src_obj>\S+) host (?P<dst_ip>\d+.\d+.\d+.\d+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object (?P<src_obj>\S+) (?P<dst_ip>any4)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object (?P<src_obj>\S+) fqdn (?P<dst_fqdn>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object (?P<src_obj>\S+) object (?P<dst_obj>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object (?P<src_obj>\S+) object-group (?P<dst_obj_group>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',

    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object-group (?P<src_obj_group>\S+) (?P<dst_subnet>\d+.\d+.\d+.\d+) (?P<dst_mask>\d+.\d+.\d+.\d+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object-group (?P<src_obj_group>\S+) host (?P<dst_ip>\d+.\d+.\d+.\d+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object-group (?P<src_obj_group>\S+) (?P<dst_ip>any4)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object-group (?P<src_obj_group>\S+) fqdn (?P<dst_fqdn>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object-group (?P<src_obj_group>\S+) object (?P<dst_obj>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',
    r'access-list (?P<acl_name>.*) line (?P<line_number>\d+) extended (?P<action>\w+) ((?:object-group\s(?P<protocol_group>\S+))|(?P<protocol>\w+)) object-group (?P<src_obj_group>\S+) object-group (?P<dst_obj_group>\S+)((?:\sobject-group\s(?P<dst_port_group>\S+))|(?:\seq\s(?P<dst_port>[\w-]+-[\w-]+|[\w-]+))|(?:\srange\s(?P<dst_port_range>[\w-]+ [\w-]+)))?',

]

# Global remark object, shared across line's where appropriate
CURRENT_REMARK = ""

# Rich Console Instance
console = Console()

# Meraki Dashboard instance
dashboard = meraki.DashboardAPI(MERAKI_API_KEY, suppress_logging=True)

# Maintain list of Policy Objects and Policy Object Groups (initialized with existing groups)
object_groups = {}
objects = {}

# Custom objects
port_groups = {}
group_of_groups = {}
protocol_objects = {}
any_translation = {}
interfaces = {}
routes = {}
nat_table = {}

# Triggers reading sub entries if top level ACL line fails
CHILD_FLAG = False

# Triggers reading sub entries for NAT lines (since objects, objects groups, etc. not supported)
NAT_FLAG = False

# Triggers Any translation if needed by rules
ANY_FLAG = False


def build_mx_object(org_id, object_type, element):
    """
    Process individual object from show run config file, individual processing determined based on object type.
    :param org_id: meraki org id
    :param object_type: type of object we are processing
    :param element: object we are processing
    :return:
    """
    global objects, object_groups, port_groups, group_of_groups, protocol_objects, interfaces, any_translation, routes, nat_table

    mx_object = {}

    # Build Policy Object
    if object_type == 'object':
        name = element.text.replace('object network ', '')
        name = name.replace('.', '_')

        mx_object['name'] = name
        mx_object['category'] = 'network'

        # Process sub-lines of element
        lines = element.children

        # Case of no children elements, ignore
        if len(lines) == 0:
            return None

        for line in lines:
            content = line.text.split()

            if content[0] == 'nat':
                # Add static NAT mappings between network objects (network object id's can be retrieved from
                # objects table)
                # Dynamic entries ignored, this is default behavior in Meraki
                if content[2] == 'static' and name not in nat_table:
                    # Translate objects to IPs
                    cidr = dashboard.organizations.getOrganizationPolicyObject(organizationId=org_id,
                                                                               policyObjectId=objects[name])['cidr']
                    internal_ip = cidr.split('/')[0]

                    cidr = dashboard.organizations.getOrganizationPolicyObject(organizationId=org_id,
                                                                               policyObjectId=objects[
                                                                                   content[3].replace('.', '_')])[
                        'cidr']
                    external_ip = cidr.split('/')[0]

                    nat_table[internal_ip] = external_ip

                # Return None because we are adding to nat table, but don't want to create Policy Object
                return None
            elif content[0] == 'host':
                mx_object['type'] = 'cidr'
                mx_object['cidr'] = content[1] + '/32'
            elif content[0] == 'subnet':
                mx_object['type'] = 'cidr'
                mx_object['cidr'] = content[1] + '/' + SUBNET_MASKS[content[2]]
            elif content[0] == 'range':
                # Ranges not support in Meraki, ignoring
                return None
            elif content[0] == 'fqdn':
                mx_object['type'] = 'fqdn'
                mx_object['fqdn'] = content[2]

        if name in objects:
            return None

    # Build Policy Object Group
    elif object_type == 'group':
        name = element.text.replace('object-group network ', '')
        name = name.replace('.', '_')

        # Ignore objects that already exist
        if name not in object_groups:
            mx_object['name'] = name
            mx_object['category'] = 'NetworkObjectGroup'
            mx_object['objectIds'] = []
            mx_object['group_of_groups'] = []

            # Process sub-lines of element
            lines = element.children

            # Case of no children elements, ignore
            if len(lines) == 0:
                return None

            for line in lines:
                content = line.text.split()

                # Add object id to object group
                if content[0] == 'network-object':
                    # Sanitize
                    content[2] = content[2].replace('.', '_')

                    # Invalid object that was unsupported before, won't be in group
                    if content[2] not in objects:
                        return None

                    object_id = objects[content[2]]
                    mx_object['objectIds'].append(object_id)

                # nested group object case
                elif content[0] == 'group-object':

                    if content[1] not in object_groups:
                        return None

                    group_id = object_groups[content[1]]
                    mx_object['group_of_groups'].append(group_id)
        else:
            return None

    # Build service group (custom datastructure, not natively supported in Meraki) - port group, service-object
    elif object_type == 'service':
        content = element.text.replace('object-group service ', '').split()
        name = content[0]

        # Port object group (something at the end like tcp, udp, etc.)
        if len(content) > 1:
            # Ignore objects that already exist
            if name not in port_groups:
                mx_object['name'] = name
                mx_object['ports'] = []

                # Process sub-lines of element
                lines = element.children

                # Case of no children elements, ignore
                if len(lines) == 0:
                    return None

                for line in lines:
                    content = line.text.split()

                    if content[0] == 'port-object':
                        # eq case (only eq supported)
                        if content[1] == 'eq':
                            if not content[2].isdigit():
                                mx_object['ports'].append(str(getservbyname(content[2])))
                            else:
                                mx_object['ports'].append(content[2])
                        elif content[1] == 'range':
                            if not content[2].isdigit():
                                content[2] = str(getservbyname(content[2]))
                            if not content[3].isdigit():
                                content[3] = str(getservbyname(content[3]))

                            mx_object['ports'].append(content[2] + '-' + content[3])
            else:
                return None
        else:
            return None
    # Build protocol objects (not a native Meraki object, custom object)
    elif object_type == 'protocol':
        name = element.text.replace('object-group protocol ', '')

        # Ignore objects that already exist
        if name not in protocol_objects:
            mx_object['name'] = name
            mx_object['protocols'] = []

            # Process sub-lines of element
            lines = element.children

            # Case of no children elements, ignore
            if len(lines) == 0:
                return None

            for line in lines:
                content = line.text.split()
                mx_object['protocols'].append(content[1])
        else:
            return None

    # Build access group objects (not a native Meraki object, custom object)
    elif object_type == 'access-group':
        line = element.text.replace('access-group ', '')
        line = line.split()

        name = line[0]
        nameif = line[3]
        # Ignore objects that already exist
        if name not in any_translation and nameif in interfaces:
            mx_object['name'] = name
            mx_object['cidr'] = [interfaces[nameif]]

            # add other routes for any translation
            if nameif in routes:
                mx_object['cidr'] += routes[nameif]
        else:
            return None
    # Build interfaces object (not a native Meraki object, custom object)
    elif object_type == 'interface':
        # Process sub-lines of element
        lines = element.children

        # Case of no children elements, ignore
        if len(lines) == 0:
            return None

        for line in lines:
            content = line.text.split()

            if content[0] == 'nameif':
                mx_object['name'] = content[1]
            elif content[0] == 'ip':
                mx_object['cidr'] = content[2] + '/' + SUBNET_MASKS[content[3]]
    # Build route objects (not a native Meraki object, custom object)
    elif object_type == 'route':
        line = element.text.replace('route ', '')
        line = line.split()

        name = line[0]

        mx_object['name'] = name
        mx_object['cidr'] = line[1] + '/' + SUBNET_MASKS[line[2]]

    return mx_object


def create_objects(org_id, parse):
    """
    Build out objects and constructs from ASA Show Run and ACL for the MX. Objects include network objects, network object groups, port groups, protocol groups, and nat table.
    :param org_id: meraki org id
    :param parse: CiscoConfParse object representing parsed form of show run file
    :return:
    """
    global objects, object_groups, port_groups, group_of_groups, protocol_objects, interfaces, any_translation, routes, nat_table

    # Parse network objects
    # Grab existing list of policy objects, create new dictionary mapping name to id
    policy_objects = dashboard.organizations.getOrganizationPolicyObjects(organizationId=org_id)

    for obj in policy_objects:
        objects[obj['name']] = obj['id']

    solo_objects = parse.find_objects(r'object network')
    solo_objects = [elem for elem in solo_objects if elem.text.startswith('object network')]

    solo_object_count = len(solo_objects)

    console.print("[blue]Creating Network Objects (and NAT Table) [/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=solo_object_count, transient=True)
        counter = 1

        for element in solo_objects:
            # Construct post body
            mx_object = build_mx_object(org_id, 'object', element)

            progress.console.print(
                "Processing object: [blue]'{}'[/] ({} of {})".format(element.text.replace('object network ', ''),
                                                                     str(counter), solo_object_count))

            # Error building object (likely not supported) if this skips
            if mx_object:
                if mx_object["type"] == 'cidr':
                    # Create MX Object (cidr)
                    new_object = dashboard.organizations.createOrganizationPolicyObject(organizationId=org_id,
                                                                                        name=mx_object['name'],
                                                                                        category=mx_object['category'],
                                                                                        type=mx_object["type"],
                                                                                        cidr=mx_object["cidr"])
                else:
                    # Create MX Object (fqdn)
                    new_object = dashboard.organizations.createOrganizationPolicyObject(organizationId=org_id,
                                                                                        name=mx_object['name'],
                                                                                        category=mx_object['category'],
                                                                                        type=mx_object["type"],
                                                                                        fqdn=mx_object["fqdn"])

                # Add new object to list
                objects[new_object['name']] = new_object['id']

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse group network objects
    # Grab existing list of policy object groups, create new dictionary mapping name to id
    policy_object_groups = dashboard.organizations.getOrganizationPolicyObjectsGroups(organizationId=org_id)

    for obj in policy_object_groups:
        object_groups[obj['name']] = obj['id']

    group_objects = parse.find_objects(r'object-group network')
    group_objects = [elem for elem in group_objects if elem.text.startswith('object-group network')]

    group_objects_count = len(group_objects)

    console.print("[blue]Creating Network Objects Groups[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=group_objects_count, transient=True)
        counter = 1

        for element in group_objects:
            # Construct post body
            mx_object = build_mx_object(org_id, 'group', element)

            progress.console.print(
                "Processing object: [blue]'{}'[/] ({} of {})".format(
                    element.text.replace('object-group network ', ''),
                    str(counter), group_objects_count))

            # Error building object (likely not supported) if this skips
            if mx_object:
                # nested group case
                if len(mx_object['group_of_groups']) > 0 and mx_object['name'] not in group_of_groups:
                    group_of_groups[mx_object['name']] = mx_object['group_of_groups']
                else:
                    # Create new object network group
                    new_group = dashboard.organizations.createOrganizationPolicyObjectsGroup(organizationId=org_id,
                                                                                             name=mx_object['name'],
                                                                                             category=mx_object[
                                                                                                 'category'],
                                                                                             objectIds=mx_object[
                                                                                                 'objectIds'])

                    # Add new object to list
                    object_groups[new_group['name']] = new_group['id']

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse network service-object groups (port-object, service-object)
    service_groups = parse.find_objects(r'object-group service')
    service_groups = [elem for elem in service_groups if elem.text.startswith('object-group service')]

    service_groups_count = len(service_groups)

    console.print("[blue]Creating Service Groups (Port Objects)[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=service_groups_count, transient=True)
        counter = 1

        for element in service_groups:
            service_object = build_mx_object(org_id, 'service', element)

            progress.console.print(
                "Processing object: [blue]'{}'[/] ({} of {})".format(
                    element.text.replace('object-group service ', ''),
                    str(counter), service_groups_count))

            if service_object:
                if 'ports' in service_object:
                    # Build port dictionary
                    port_groups[service_object['name']] = service_object['ports']

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse protocol-objects
    objects_protocols = parse.find_objects(r'object-group protocol')
    objects_protocols = [elem for elem in objects_protocols if elem.text.startswith('object-group protocol')]

    objects_protocols_count = len(objects_protocols)

    console.print("[blue]Creating Service Groups (Protocol) [/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=objects_protocols_count, transient=True)
        counter = 1

        for element in objects_protocols:
            protocol_object = build_mx_object(org_id, 'protocol', element)

            progress.console.print(
                "Processing object: [blue]'{}'[/] ({} of {})".format(
                    element.text.replace('object-group protocol ', ''),
                    str(counter), objects_protocols_count))

            if protocol_object:
                # Build protocol dictionary
                protocol_objects[protocol_object['name']] = protocol_object['protocols']

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse Interfaces (any translation)
    interface_groups = parse.find_objects(r'interface')
    interface_groups = [elem for elem in interface_groups if elem.text.startswith('interface')]

    interface_groups_count = len(interface_groups)

    console.print("[blue]Creating Interface Table[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=interface_groups_count, transient=True)
        counter = 1

        for element in interface_groups:
            interface_object = build_mx_object(org_id, 'interface', element)

            progress.console.print(
                "Processing interface: [blue]'{}'[/] ({} of {})".format(element.text.replace('interface ', ''),
                                                                        str(counter), interface_groups_count))

            if interface_object and len(interface_object) > 0:
                # Build interface dictionary
                interfaces[interface_object['name']] = interface_object['cidr']

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse Routes (any translation)
    routes_objects = parse.find_objects(r'route')
    routes_objects = [elem for elem in routes_objects if elem.text.startswith('route')]

    routes_count = len(routes_objects)

    console.print("[blue]Creating Route Table[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=routes_count, transient=True)
        counter = 1

        for element in routes_objects:
            routes_object = build_mx_object(org_id, 'route', element)

            progress.console.print(
                "Processing object: [blue]'{}'[/] ({} of {})".format(element.text.replace('route ', ''),
                                                                     str(counter), routes_count))
            if routes_object:
                if routes_object['name'] in routes:
                    routes[routes_object['name']].append(routes_object['cidr'])
                else:
                    routes[routes_object['name']] = [routes_object['cidr']]

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse Access-Groups (any translation)
    access_groups = parse.find_objects(r'access-group')
    access_groups = [elem for elem in access_groups if elem.text.startswith('access-group')]

    access_groups_count = len(access_groups)

    console.print("[blue]Creating Access Groups Table[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=access_groups_count, transient=True)
        counter = 1

        for element in access_groups:
            access_object = build_mx_object(org_id, 'access-group', element)

            progress.console.print(
                "Processing object: [blue]'{}'[/] ({} of {})".format(element.text.replace('access-group ', ''),
                                                                     str(counter), access_groups_count))

            # Don't add nat_acls to any translation (this doesn't make sense)
            if access_object and access_object['name'] not in ACL_TYPES['nat_set']:
                any_translation[access_object['name']] = access_object['cidr']

            counter += 1
            progress.update(overall_progress, advance=1)

    return


def parse_line(line):
    """
    Parse each ASA ACL line. Match lines to regex pattern, process individual pieces utilizing object constructs created previously.
    :param line: ACL line
    :return: Meraki compatible rule pieces in the form of a dictionary
    """
    global CURRENT_REMARK, ANY_FLAG, NAT_FLAG

    # Strip leading spaces and newlines
    line = line.strip("")

    # Skip Inactive Lines!
    if "inactive" in line:
        return None

    # Remark functionality
    if "remark" in line:
        search = re.search(r'remark (.*)', line)

        if search:
            remark = search.group()

            content = remark[len("remark"):]

            if content not in CURRENT_REMARK:
                CURRENT_REMARK += content if CURRENT_REMARK == "" else " + " + content

            return {}

    for pattern in regex_patterns:
        match = re.search(pattern, line)

        if match:
            acl = match.groupdict()

            # Set NAT flag if acl name is in nat list
            if acl['acl_name'] in ACL_TYPES['nat_set']:
                NAT_FLAG = True
            else:
                NAT_FLAG = False

            # add remark
            acl['comment'] = CURRENT_REMARK

            # Process protocol groups
            if 'protocol_group' in acl and acl['protocol_group']:
                # NAT rules don't support protocol groups
                if NAT_FLAG:
                    return None

                if acl['protocol_group'] in protocol_objects:
                    protocols = protocol_objects[acl['protocol_group']]
                    acl["protocol"] = protocols
                else:
                    return None

            # src ip processing (host, any, object, object group, group-of-groups)
            if "src_ip" in acl:

                # Convert any4 to any or special translation (using 'any' table)
                if acl["src_ip"] == "any4":
                    if acl["acl_name"] in any_translation and ANY_FLAG:
                        acl["src"] = ','.join(any_translation[acl['acl_name']])
                    else:
                        acl["src"] = "any"
                else:
                    # host case
                    acl["src"] = acl["src_ip"] + "/32"
            # subnet case
            elif "src_subnet" in acl:
                acl["src"] = acl["src_subnet"] + '/' + SUBNET_MASKS[acl["src_mask"]]

            # Note: FQDN in the src not support by Meraki... rules ignored

            # Object case
            elif "src_obj" in acl:
                # NAT rules don't support objects
                if NAT_FLAG:
                    return None

                acl["src_obj"] = acl["src_obj"].replace('.', '_')

                # If object found, use ID as source
                if acl["src_obj"] in objects:
                    obj_id = objects[acl["src_obj"]]
                    acl["src"] = f"OBJ[{obj_id}]"
                else:
                    return None

            # Object group case
            elif "src_obj_group" in acl:
                # NAT rules don't support object groups
                if NAT_FLAG:
                    return None

                acl["src_obj_group"] = acl["src_obj_group"].replace('.', '_')

                # If object found, use ID as source
                if acl["src_obj_group"] in object_groups:
                    obj_id = object_groups[acl["src_obj_group"]]
                    acl["src"] = f"GRP[{obj_id}]"
                # Group of Groups Case
                elif acl["src_obj_group"] in group_of_groups:
                    obj_list = group_of_groups[acl["src_obj_group"]]
                    acl["src"] = [f"GRP[{obj}]" for obj in obj_list]
                else:
                    return None

            # dst ip processing (host, fqdn, any, object, object group)
            if "dst_ip" in acl:
                # Convert any4 to any
                if acl["dst_ip"] == "any4":
                    acl["dst"] = "any"
                # Special case of sub icmp flows (Meraki only supports allow or deny, can't specify sub flows)
                elif "echo" in acl["dst_ip"] or "echo-reply" in acl["dst_ip"] or "time-exceeded" in acl[
                    "dst_ip"] or "unreachable" in acl["dst_ip"]:
                    return None
                else:
                    # host case
                    acl["dst"] = acl["dst_ip"] + "/32"

            elif "dst_subnet" in acl:
                acl["dst"] = acl["dst_subnet"] + '/' + SUBNET_MASKS[acl["dst_mask"]]
            # fqdn case
            elif "dst_fqdn" in acl:
                # NAT rules don't support fqdn
                if NAT_FLAG:
                    return None
                acl["dst"] = acl["dst_fqdn"]
            # Object case
            elif "dst_obj" in acl:
                # NAT rules don't support objects
                if NAT_FLAG:
                    return None

                acl["dst_obj"] = acl["dst_obj"].replace('.', '_')

                # If object found, use ID as destination
                if acl["dst_obj"] in objects:
                    obj_id = objects[acl["dst_obj"]]
                    acl["dst"] = f"OBJ[{obj_id}]"
                else:
                    return None

            elif "dst_obj_group" in acl:
                # NAT rules don't support object groups
                if NAT_FLAG:
                    return None

                acl["dst_obj_group"] = acl["dst_obj_group"].replace('.', '_')

                # If object found, use ID as source
                if acl["dst_obj_group"] in object_groups:
                    obj_id = object_groups[acl["dst_obj_group"]]
                    acl["dst"] = f"GRP[{obj_id}]"
                # Group of Groups Case
                elif acl["dst_obj_group"] in group_of_groups:
                    obj_list = group_of_groups[acl["dst_obj_group"]]
                    acl["dst"] = obj_list
                else:
                    return None

            # dst port processing
            # ranges case
            if "dst_port_range" in acl and acl["dst_port_range"]:
                split = acl["dst_port_range"].split()

                # translate port names
                if not split[0].isdigit():
                    split[0] = str(getservbyname(split[0]))
                elif not split[1].isdigit():
                    split[1] = str(getservbyname(split[1]))

                # Build Meraki valid port range
                acl["dst_port"] = split[0] + '-' + split[1]

            elif "dst_port" in acl and acl['dst_port']:
                # translate port names
                if not acl["dst_port"].isdigit():
                    acl["dst_port"] = str(getservbyname(acl["dst_port"]))

            # Port group case
            elif "dst_port_group" in acl and acl['dst_port_group']:
                # NAT rules don't support port groups
                if NAT_FLAG:
                    return None

                if acl['dst_port_group'] in port_groups:
                    ports = port_groups[acl['dst_port_group']]

                    comma_list = ','.join([port for port in ports if '-' not in port])
                    range_list = ','.join([port for port in ports if '-' in port])

                    acl["dst_port"] = [comma_list, range_list]
                else:
                    return None

            # Found Match, applied current remark, reset remark variable
            CURRENT_REMARK = ""

            # Ignore default any, any, any, any rules (if not doing any translation)
            if not ANY_FLAG and acl['protocol'] == 'ip' and acl["src"] == "any" and acl["dst"] == "any":
                return None

            return acl

    return None


def parse_rules(config_file_name):
    """
    Parse show access-list file rules, process each individual line, extract pieces for MX rules.
    :param config_file_name: file containing show access-list from ASA
    :return:
    """
    global CHILD_FLAG

    # List that holds on to ACL Rules
    acl_list = []

    # List that holds on to nat ACL Rules
    nat_acl_list = []
    with open(config_file_name, 'r') as fp, open('unprocessed_rules.txt', 'w') as broken_fp:

        # Get Count of Rules
        rule_count = sum(1 for _ in fp)
        fp.seek(0)

        with Progress() as progress:
            overall_progress = progress.add_task("Overall Progress", total=rule_count, transient=True)
            counter = 1

            for line in fp:
                # If line doesn't start with spaces and CHILD_FLAG is set already, we are at a new parent element ->
                # reset flag
                if not line.startswith(' ') and CHILD_FLAG:
                    CHILD_FLAG = False

                if not line.startswith(' ') or CHILD_FLAG:
                    # Parse each line, returning dictionary with ASA ACL Entry mapped to key fields for MX L3 Rule (
                    # or nat rule)
                    acl_line = parse_line(line)

                    if acl_line is None:
                        # Write un-processable rules to file
                        broken_fp.write(line)

                        # Process any children elements under the failed line
                        CHILD_FLAG = True

                        progress.console.print(
                            "Error Processing line: [red]'{}'[/] ({} of {})".format(line.strip(), str(counter),
                                                                                    rule_count))
                    # Add to outbound acl rule set
                    elif len(acl_line) > 0 and acl_line['acl_name'] in ACL_TYPES['outbound_set']:
                        acl_list.append(acl_line)
                        progress.console.print(
                            "Processing Outbound line: [green]'{}'[/] ({} of {})".format(line.strip(), str(counter),
                                                                                         rule_count))
                    # Add to nat acl rule set
                    elif len(acl_line) > 0 and acl_line['acl_name'] in ACL_TYPES['nat_set']:
                        nat_acl_list.append(acl_line)
                        progress.console.print(
                            "Processing NAT line: [green]'{}'[/] ({} of {})".format(line.strip(), str(counter),
                                                                                    rule_count))
                else:
                    progress.console.print(
                        "Skipping Child line: [blue]'{}'[/] ({} of {})".format(line.strip(), str(counter), rule_count))

                counter += 1
                progress.update(overall_progress, advance=1)

    return acl_list, nat_acl_list


def create_static_rules(static_file_name, network_id):
    """
    Create static routes on MX Network if file provided.
    :param static_file_name: static file name that contains static routes
    :param network_id: meraki network id
    :return:
    """
    with open(static_file_name, 'r') as fp:

        # load vlans
        routes = json.load(fp)

        # Get list of currently defined vlans
        existing_routes = dashboard.appliance.getNetworkApplianceStaticRoutes(networkId=network_id)
        existing_routes = [d['name'] for d in existing_routes]

        # Get Count of Rules
        route_count = len(routes)

        with Progress() as progress:
            overall_progress = progress.add_task("Overall Progress", total=route_count, transient=True)
            counter = 1

            for route in routes:
                progress.console.print(
                    "Processing route: [yellow]'{}'[/] ({} of {})".format(route['name'], str(counter), route_count))

                # If vlan doesn't exist create it
                if route['name'] not in existing_routes:
                    dashboard.appliance.createNetworkApplianceStaticRoute(networkId=network_id, name=route['name'],
                                                                          subnet=route['subnet'],
                                                                          gatewayIp=route['gatewayIp'])

                counter += 1
                progress.update(overall_progress, advance=1)


def create_vlans(vlan_file_name, network_id):
    """
    Create vlans on target MX network if provided.
    :param vlan_file_name: vlan file name that contains vlans
    :param network_id: meraki network id
    :return:
    """
    with open(vlan_file_name, 'r') as fp:

        # load vlans
        vlans = json.load(fp)

        # Get list of currently defined vlans
        existing_vlans = dashboard.appliance.getNetworkApplianceVlans(networkId=network_id)
        existing_vlans = [d['name'] for d in existing_vlans]

        # Get Count of Rules
        vlan_count = len(vlans)

        with Progress() as progress:
            overall_progress = progress.add_task("Overall Progress", total=vlan_count, transient=True)
            counter = 1

            for vlan in vlans:
                progress.console.print(
                    "Processing vlan: [blue]'{}'[/] ({} of {})".format(vlan['id'], str(counter), vlan_count))

                # If vlan doesn't exist create it
                if vlan['name'] not in existing_vlans:
                    dashboard.appliance.createNetworkApplianceVlan(networkId=network_id, id=vlan['id'],
                                                                   name=vlan['name'], subnet=vlan['subnet'],
                                                                   applianceIp=vlan['applianceIp'],
                                                                   groupPolicyId=vlan['groupPolicyId'])

                counter += 1
                progress.update(overall_progress, advance=1)


def create_mx_rules(org_id, network_id, acl_list):
    """
    Create L3 rules on Meraki MX, using pieces obtaining from object constructs and parsing ACL lines.
    :param org_id: meraki org id
    :param network_id: meraki network id
    :param acl_list: list of MX L3 acl objects (containing pieces of MX rules)
    :return: response of API call
    """
    # If the network was found, add the firewall rules to it
    if org_id is not None and network_id is not None:
        # Convert the Cisco ASA ACL list into Meraki MX firewall rules
        firewall_rules = []
        for acl in acl_list:

            # Build every possible combo of protocol, src, dst, and dst port (cartesian product of lists to create
            # larger list of tuples representing all possible combinations)
            combos = [[], [], [], []]

            # Handle special case for protocol
            if isinstance(acl['protocol'], list):
                combos[0] += acl['protocol']
            # Normal Defined Protocol
            elif acl['protocol'] == 'ip':
                combos[0].append('any')
            # Everything else
            else:
                combos[0].append(acl['protocol'])

            # Handle Special Object Cases for Src
            if isinstance(acl['src'], list):
                combos[1] += acl['src']
            else:
                combos[1].append(acl['src'])

            # Handle Special Object Cases for Dst
            if isinstance(acl['dst'], list):
                combos[2] += acl['dst']
            else:
                combos[2].append(acl['dst'])

            # Handle Port Group
            if isinstance(acl['dst_port'], list):
                comma_string, range_string = acl['dst_port']
                if len(comma_string) > 0:
                    combos[3].append(comma_string)

                if len(range_string) > 0:
                    ranges = range_string.split(',')
                    combos[3] += ranges
            # Normal Defined Port
            elif acl['dst_port']:
                combos[3].append(acl['dst_port'])
            # Everything else
            else:
                combos[3].append('any')

            results = list(itertools.product(*combos))

            for result in results:
                firewall_rule = {
                    'comment': acl['comment'],
                    'policy': 'allow' if acl['action'] == 'permit' else 'deny',
                    'protocol': result[0],
                    'srcPort': 'any',
                    'srcCidr': result[1],
                    'destCidr': result[2],
                    'destPort': result[3]
                }
                firewall_rules.append(firewall_rule)

        # Update the firewall rules in the Meraki MX network
        console.print(
            f"Adding [green]{len(firewall_rules)}[/] Outbound Rules to [blue]{NETWORK_NAME}[/]. Please wait, this may take a few minutes...")
        response = dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(network_id, rules=firewall_rules)

        return response
    return None


def create_nat_rules(org_id, network_id, nat_acl_list):
    """
    Create NAT 1:1 rules on Meraki MX, using pieces obtaining from object constructs and parsing ACL lines.
    :param org_id: meraki org id
    :param network_id: meraki network id
    :param nat_acl_list: list of MX NAT acl objects (containing pieces of MX NAT rules)
    :return:
    """
    # If the network was found, add the firewall rules to it
    if org_id is not None and network_id is not None:
        # Convert the Cisco ASA ACL list into Meraki MX nat rules
        nat_rules = {}
        deny_rules = []
        for acl in nat_acl_list:

            # If action is deny, create l7 deny rule
            if acl['action'] == 'deny':
                deny_rules.append(acl)

            # Skip dst == any (Meraki doesn't support specifying 'any' destination for NAT rule)
            if acl['dst_ip'] == 'any4':
                continue

            # Determine nat rule name
            name = acl['dst_ip'].replace('.', '_')

            # If this is a new nat rule, create the nat rule object and add it to the rules list, else grab existing
            # nat rule
            if name in nat_rules:
                nat_rule = nat_rules[name]
            else:
                nat_rule = {
                    "name": name,
                    "lanIp": acl['dst_ip'],
                    "publicIp": nat_table[acl['dst_ip']],
                    "uplink": "internet1",
                    "allowedInbound": []
                }

            # Build inbound rule
            inboundRule = {
                "protocol": 'any' if acl['protocol'] == 'ip' else acl['protocol'],
                "destinationPorts": ['any'] if acl['dst_port'] == 'any' else [acl['dst_port']],
                "allowedIps": [acl['src']]
            }
            nat_rule['allowedInbound'].append(inboundRule)

            # Add new nat rule
            if name not in nat_rules:
                nat_rules[name] = nat_rule

        # Update the firewall rules in the Meraki MX network
        console.print(
            f"Adding [green]{len(nat_rules)}[/] NAT Rules to [blue]{NETWORK_NAME}[/]. Please wait, this may take a few minutes...")
        response = dashboard.appliance.updateNetworkApplianceFirewallOneToOneNatRules(network_id,
                                                                                      rules=list(nat_rules.values()))

        # Add L7 Deny Rules
        console.print(
            f"Adding [green]{len(deny_rules)}[/] L7 Deny NAT Rules to [blue]{NETWORK_NAME}[/]. Please wait, this may take a few minutes...")
        create_l7_rules(network_id, deny_rules)

        return response
    return None


def create_l7_rules(network_id, deny_rules):
    """
    Create L7 deny rules for NAT ACL rules (NAT only supports permit)
    :param network_id: meraki network id
    :param deny_rules: MX Deny Rules identified in NAT set
    :return:
    """
    rules = []
    for rule in deny_rules:
        # No support for src == 'any' or a specific destination
        if rule['src'] != 'any' and rule['dst'] == 'any':
            rules.append(
                {
                    "policy": "deny",
                    "type": "ipRange",
                    "value": rule['src']
                }
            )

    dashboard.appliance.updateNetworkApplianceFirewallL7FirewallRules(networkId=network_id, rules=rules)


def print_help():
    """
    Print's help line if incorrect input provided to script.
    :return:
    """
    console.print('This script imports ASA ACLs into the target MX network\n')
    console.print(
        'To run the script, enter: python3 asa_to_mx.py -r [yellow]<ASA Show Run file>[/] -a [yellow]<ASA Show ACL>[/] -v [yellow]<optional vlan '
        'json file>[/] -s [yellow]<optional static routes file>[/]')


def main():
    global ANY_FLAG
    console.print(Panel.fit("ASA ACL Config to MX Config"))

    # Get Inputs args
    show_access_list_file = ''
    show_run_file = ''
    vlan_file_name = ''
    static_file_name = ''

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'r:a:v:s:')
    except getopt.GetoptError:
        print_help()
        sys.exit(-2)

    for opt, arg in opts:
        if opt == '-h':
            print_help()
            sys.exit()
        elif opt == '-r':
            show_run_file = arg
        elif opt == '-a':
            show_access_list_file = arg
        elif opt == '-v':
            vlan_file_name = arg
        elif opt == '-s':
            static_file_name = arg

    if len(sys.argv) <= 1:
        print_help()
        sys.exit(-1)

    # Check current directory for show run file
    if not os.path.exists(show_run_file):
        console.print('[red]Error:[/] show run file not found!')
        sys.exit(-1)

    # Check current directory for show acl file
    if not os.path.exists(show_access_list_file):
        console.print('[red]Error:[/] show access-list file not found!')
        sys.exit(-1)

    # Check current directory for vlan file
    if vlan_file_name != '':
        if not os.path.exists(vlan_file_name):
            console.print('[red]Error:[/] vlan file not found!')
            sys.exit(-1)
    else:
        answer = Confirm.ask(
            "No vlan file detected. Please ensure necessary source vlans/static routes are created on the target "
            "MX, otherwise the script will fail. Continue?", default=True)
        if not answer:
            sys.exit(1)

    # Check current directory for static route file
    if static_file_name != '':
        if not os.path.exists(static_file_name):
            console.print('[red]Error:[/] vlan file not found!')
            sys.exit(-1)
    else:
        answer = Confirm.ask(
            "No static file detected. Please ensure necessary source vlans/static routes are created on the target "
            "MX, otherwise the script will fail. Continue?", default=True)
        if not answer:
            sys.exit(1)

    # Determine if 'any' translation must be done
    answer = Confirm.ask(
        "Does your ACL require 'any' source translation? (Example use case: static routes exposing internal VLANs on "
        "a single interface)", default=True)
    if answer:
        ANY_FLAG = True

    # Get Meraki Org Id
    orgs = dashboard.organizations.getOrganizations()

    org_id = None
    for org in orgs:
        if org['name'] == ORG_NAME:
            org_id = org['id']
            break

    # Get the list of Meraki MX networks
    networks = dashboard.organizations.getOrganizationNetworks(org_id)

    # Find the network ID of the network you want to add the firewall rules to
    network_id = None
    for network in networks:
        if network['name'] == NETWORK_NAME:
            network_id = network['id']
            break

    # Parse config, create various object dictionaries
    console.print(Panel.fit("Creating Network Objects, Network Group Objects, Protocol Objects, Port Groups, etc.",
                            title="Step 1"))
    parse = CiscoConfParse(show_run_file, syntax='asa')
    create_objects(org_id, parse)

    # Create VLAN's necessary for ACL Rules
    console.print(Panel.fit("Creating VLAN's", title="Step 2"))
    if vlan_file_name != '':
        create_vlans(vlan_file_name, network_id)

    # Create Static Rules (necessary) for ACL Rules
    console.print(Panel.fit("Creating Static Rules", title="Step 2.5"))
    if static_file_name != '':
        create_static_rules(static_file_name, network_id)

    # Iterate through ACL, parse rules
    console.print(Panel.fit("Parsing ASA ACL Rules", title="Step 3"))

    # Parse normal outbound rules and nat outbound rules
    acl_list, nat_acl_list = parse_rules(show_access_list_file)

    # Creating MX Rules
    console.print(Panel.fit("Creating MX Rules", title="Step 4"))

    # Create outbound rules
    response = create_mx_rules(org_id, network_id, acl_list)
    if not response:
        console.print(
            f'[red]Error:[/] there was a problem adding the outbound rules to the Meraki MX network. {response}')

    # Create nat rules
    response = create_nat_rules(org_id, network_id, nat_acl_list)
    if not response:
        console.print(f'[red]Error:[/] there was a problem adding the nat rules to the Meraki MX network. {response}')

    console.print(f'[green]Success![/] ACL Rules Converted.')


if __name__ == "__main__":
    main()
