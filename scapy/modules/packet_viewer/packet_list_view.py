# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from threading import Lock

from six import PY2
from typing import List, Union
from urwid import AttrMap, SimpleFocusListWalker, CheckBox, SolidCanvas, \
    CanvasCombine

from scapy.packet import Packet
from scapy.modules.packet_viewer.extended_listbox import ExtendedListBox
from scapy.modules.packet_viewer.row_formatter import RowFormatter


class PacketListView(ExtendedListBox):
    """
    Lists all the packets which have been sniffed so far
    or were given in a list.
    """

    signals = ["msg_to_main_thread"]

    def __init__(self, row_formatter):
        # type: (RowFormatter) -> None
        self.row_formatter = row_formatter
        self.packets = []  # type: List[Packet]

        # Ensures that this widget is not changed in the sniffer thread
        # while this widget is drawn in the main thread
        self.lock = Lock()
        super(PacketListView, self).__init__(True, SimpleFocusListWalker([]))

    def update_selected_packet(self):
        # type: () -> None
        text = self.row_formatter.format(self.focus.base_widget.tag)
        self.focus.base_widget.set_label(text)

    # noinspection PyProtectedMember
    def _create_gui_packet(self, pkt):
        # type: (Packet) -> CheckBox
        text = self.row_formatter.format(pkt)
        gui_packet = CheckBox(text)

        # Unfortunately we need to access some protected variables here,
        # to customize the underlying widgets

        # urwid crashes with Py2 and ellipsis
        # Fixed with https://github.com/urwid/urwid/pull/427
        # Todo: Revert fallback to "clip" for PY2 when
        # new urwid version is released.
        # Current 2.1.1
        gui_packet._label.set_layout("left", "clip" if PY2 else "ellipsis")

        # The cursor of `urwid.SelectableIcon` doesn't take a color scheme.
        # So just hide the cursor.
        # len(text) + 1 hides the cursor
        checked_state = gui_packet.states[True]
        unchecked_state = gui_packet.states[False]
        checked_state._cursor_position = len(checked_state.text) + 1
        unchecked_state._cursor_position = len(unchecked_state.text) + 1
        gui_packet.tag = pkt
        return gui_packet

    def add_packet(self, pkt):
        # type: (Packet) -> None

        """
        Creates and appends a Packet widget to the end of the list.
        The cursor in front of the packet content is colored
        in the default background color.
        This way, it is invisible and only the cursor
        in front of the packet in focus is colored.

        :param pkt: packet, which is passed on from the sniffer
        :type pkt: Packet
        :return: None
        """

        if not self.row_formatter.is_pkt_supported(pkt):
            return

        with self.lock:
            self.packets.append(pkt)
            self.body.append(
                AttrMap(self._create_gui_packet(pkt), None, "cyan"))
            self._emit("msg_to_main_thread", "redraw")

    def render(self, size, focus=False):
        # type: (int, bool) -> Union[SolidCanvas, CanvasCombine]
        with self.lock:
            return super(PacketListView, self).render(
                size, focus=focus)
