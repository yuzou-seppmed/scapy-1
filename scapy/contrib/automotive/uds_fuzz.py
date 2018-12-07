#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from scapy.contrib.automotive.uds import UDS, UDS_DSC, UDS_ER

"""
UDS
"""

UDS.service.fuzzparams['values'] = set([x & ~0x40 for x in range(255)])
UDS_DSC.diagnosticSessionType.fuzzparams['range'] = range(255)
UDS_ER.resetType.fuzzparams['range'] = range(255)
