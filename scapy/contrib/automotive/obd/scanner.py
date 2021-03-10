# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.korb@e-mundo.de>
# Copyright (C) Friedrich Feigel <friedrich.feigel@e-mundo.de>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = OnBoardDiagnosticScanner
# scapy.contrib.status = loads

from scapy.compat import List, Type
from scapy.contrib.automotive.obd.obd import OBD, OBD_S03, OBD_S07, OBD_S0A, \
    OBD_S01, OBD_S06, OBD_S08, OBD_S09, OBD_NR, OBD_S02, OBD_S02_Record
from scapy.config import conf
from scapy.packet import Packet
from scapy.themes import BlackAndWhite

from scapy.contrib.automotive.scanner.test_case import AutomotiveTestCase, \
    AutomotiveTestCaseABC
from scapy.contrib.automotive.scanner.executor import AutomotiveTestCaseExecutor  # noqa: E501


class OBD_Enumerator(AutomotiveTestCase):
    @staticmethod
    def _get_negative_response_code(resp):
        # type: (Packet) -> int
        return resp.response_code

    @staticmethod
    def _get_negative_response_desc(nrc):
        # type: (int) -> str
        return OBD_NR(response_code=nrc).sprintf("%OBD_NR.response_code%")

    @staticmethod
    def _get_negative_response_label(response):
        # type: (Packet) -> str
        return response.sprintf("NR: %OBD_NR.response_code%")

    @property
    def filtered_results(self):
        # type: () -> List[AutomotiveTestCase.FilteredScanResult]
        return self.results_with_positive_response


class OBD_Service_Enumerator(OBD_Enumerator):
    def _get_initial_requests(self, scan_range=range(2, 0x100), **kwargs):
        raise NotImplementedError

    def get_supported(self, socket, state, **kwargs):
        super(OBD_Service_Enumerator, self).execute(
            socket, state, scan_range=range(0, 0xff, 0x20),
            exit_scan_on_first_negative_response=True, **kwargs)

        supported = list()
        for _, _, r, _, _ in self.results_with_positive_response:
            dr = r.data_records[0]
            key = next(iter((dr.lastlayer().fields.keys())))
            supported += [int(i[-2:], 16) for i in
                          getattr(dr, key, ["xxx00"])]
        return [i for i in supported if i % 0x20]

    def execute(self, socket, state, full_scan=False, **kwargs):
        if full_scan:
            super(OBD_Service_Enumerator, self).execute(socket, state, **kwargs)
        else:
            supported_pids = self.get_supported(socket, state, **kwargs)
            del self._request_iterators[state]
            super(OBD_Service_Enumerator, self).execute(
                socket, state, scan_range=supported_pids, **kwargs)

    @staticmethod
    def print_payload(resp):
        backup_ct = conf.color_theme
        conf.color_theme = BlackAndWhite()
        load = repr(resp.data_records[0].lastlayer())
        conf.color_theme = backup_ct
        return load


class OBD_DTC_Enumerator(OBD_Enumerator):
    @staticmethod
    def print_payload(resp):
        backup_ct = conf.color_theme
        conf.color_theme = BlackAndWhite()
        load = repr(resp.dtcs)
        conf.color_theme = backup_ct
        return load


class OBD_S03_Enumerator(OBD_DTC_Enumerator):
    _description = "Available DTCs in OBD service 03"

    def _get_initial_requests(self, **kwargs):
        return [OBD() / OBD_S03()]

    @staticmethod
    def _get_table_entry(tup):
        _, _, res, _, _ = tup
        info = "NR" if res.service == 0x7f else "%d DTCs" % res.count
        label = OBD_Enumerator._get_label(res, OBD_DTC_Enumerator.print_payload)
        return "Service 03", info, label


class OBD_S07_Enumerator(OBD_DTC_Enumerator):
    _description = "Available DTCs in OBD service 07"

    def _get_initial_requests(self, **kwargs):
        return [OBD() / OBD_S07()]

    @staticmethod
    def _get_table_entry(tup):
        _, _, res, _, _ = tup
        info = "NR" if res.service == 0x7f else "%d DTCs" % res.count
        label = OBD_Enumerator._get_label(res, OBD_DTC_Enumerator.print_payload)
        return "Service 07", info, label


class OBD_S0A_Enumerator(OBD_DTC_Enumerator):
    _description = "Available DTCs in OBD service 10"

    def _get_initial_requests(self, **kwargs):
        return [OBD() / OBD_S0A()]

    @staticmethod
    def _get_table_entry(tup):
        _, _, res, _, _ = tup
        info = "NR" if res.service == 0x7f else "%d DTCs" % res.count
        label = OBD_Enumerator._get_label(res, OBD_DTC_Enumerator.print_payload)
        return "Service 0A", info, label


class OBD_S01_Enumerator(OBD_Service_Enumerator):
    _description = "Available data in OBD service 01"

    def _get_initial_requests(self, scan_range=range(0x100), **kwargs):
        return (OBD() / OBD_S01(pid=[x]) for x in scan_range)

    @staticmethod
    def _get_table_entry(tup):
        _, _, res, _, _ = tup
        info = "NR" if res.service == 0x7f \
            else "%s" % res.data_records[0].lastlayer().name
        label = OBD_Enumerator._get_label(
            res, OBD_Service_Enumerator.print_payload)
        return "Service 01", info, label


class OBD_S02_Enumerator(OBD_Service_Enumerator):
    _description = "Available data in OBD service 02"

    def _get_initial_requests(self, scan_range=range(0x100), **kwargs):
        return (OBD() / OBD_S02(requests=[OBD_S02_Record(pid=[x])])
                for x in scan_range)

    @staticmethod
    def _get_table_entry(tup):
        _, _, res, _, _ = tup
        info = "NR" if res.service == 0x7f \
            else "%s" % res.data_records[0].lastlayer().name
        label = OBD_Enumerator._get_label(
            res, OBD_Service_Enumerator.print_payload)
        return "Service 02", info, label


class OBD_S06_Enumerator(OBD_Service_Enumerator):
    _description = "Available data in OBD service 06"

    def _get_initial_requests(self, scan_range=range(0x100), **kwargs):
        return (OBD() / OBD_S06(mid=[x]) for x in scan_range)

    @staticmethod
    def _get_table_entry(tup):
        _, req, res, _, _ = tup
        info = "NR" if res.service == 0x7f else "0x%02x %s" % (
            req.mid[0], res.data_records[0].sprintf("%OBD_S06_PR_Record.mid%"))
        label = OBD_Enumerator._get_label(
            res, OBD_Service_Enumerator.print_payload)
        return "Service 06", info, label


class OBD_S08_Enumerator(OBD_Service_Enumerator):
    _description = "Available data in OBD service 08"

    def _get_initial_requests(self, scan_range=range(0x100), **kwargs):
        return (OBD() / OBD_S08(tid=[x]) for x in scan_range)

    @staticmethod
    def _get_table_entry(tup):
        _, req, res, _, _ = tup
        info = "NR" if res.service == 0x7f else "0x%02x %s" % (
            req.tid[0], res.data_records[0].lastlayer().name)
        label = OBD_Enumerator._get_label(
            res, OBD_Service_Enumerator.print_payload)
        return "Service 08", info, label


class OBD_S09_Enumerator(OBD_Service_Enumerator):
    _description = "Available data in OBD service 09"

    def _get_initial_requests(self, scan_range=range(0x100), **kwargs):
        return (OBD() / OBD_S09(iid=[x]) for x in scan_range)

    @staticmethod
    def _get_table_entry(tup):
        _, req, res, _, _ = tup
        info = "NR" if res.service == 0x7f else "0x%02x %s" % (
            req.iid[0], res.data_records[0].lastlayer().name)
        label = OBD_Enumerator._get_label(
            res, OBD_Service_Enumerator.print_payload)
        return "Service 09", info, label


class OBD_Scanner(AutomotiveTestCaseExecutor):
    @property
    def enumerators(self):
        # type: () -> List[AutomotiveTestCaseABC]
        return self.configuration.test_cases

    @property
    def default_test_case_clss(self):
        # type: () -> List[Type[AutomotiveTestCase]]
        return [OBD_S01_Enumerator, OBD_S02_Enumerator, OBD_S06_Enumerator,
                OBD_S08_Enumerator, OBD_S09_Enumerator, OBD_S03_Enumerator,
                OBD_S07_Enumerator, OBD_S0A_Enumerator]

    def enter_state(self, _, __):
        return True
