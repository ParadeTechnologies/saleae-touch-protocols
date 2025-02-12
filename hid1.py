"""
HID-I2C Protocol v1 processor. For use with the Parade Technologies Touch Protocols
High Level Analyzer for the Saleae Logic2 software.
"""

from saleae.analyzers import AnalyzerFrame # type: ignore #pylint: disable=import-error

from pt_protocol import PtProtocol

class HID1 (PtProtocol):
    """
    HID-I2C Protocol Version 1 I2C packet parser.
    """
    # HID Register Addresses
    REGISTER_ADDRESS_HID_DESCRIPTOR = 0x0001
    REGISTER_ADDRESS_REPORT_DESCRIPTOR = 0x0002
    REGISTER_ADDRESS_OUTPUT = 0x0004
    REGISTER_ADDRESS_COMMAND = 0x0005

    # HID Input Report Constants
    IDX_INPUT_REPORT_MIN_LENGTH = 3
    IDX_INPUT_REPORT_PAYLOAD_START = 3
    IDX_INPUT_REPORT_LEN_LSB = 0
    IDX_INPUT_REPORT_LEN_MSB = 1
    IDX_INPUT_REPORT_ID = 2

    # HID Command Constants Common to Cmd and Out Formats
    IDX_REGISTER_ADDRESS_LSB = 0
    IDX_REGISTER_ADDRESS_MSB = 1

    # HID Command Register Constants
    IDX_CMD_REGISTER_MIN_LENGTH = 9
    IDX_CMD_REGISTER_PAYLOAD_START = 9
    IDX_CMD_REGISTER_LENGTH_OF_REPORT_LSB = 6
    IDX_CMD_REGISTER_LENGTH_OF_REPORT_MSB = 7
    IDX_CMD_REGISTER_REPORT_ID = 8

    # HID Output Register Constants
    IDX_OUT_REGISTER_MIN_LENGTH = 5
    IDX_OUT_REGISTER_LENGTH_OF_REPORT_LSB = 2
    IDX_OUT_REGISTER_LENGTH_OF_REPORT_MSB = 3
    IDX_OUT_REGISTER_REPORT_ID = 4
    IDX_OUT_REGISTER_PAYLOAD_START = 5

    # HID Descriptor Constants
    W_HID_DESC_LEN = 0x1E
    IDX_HID_DESCRIPTOR_WMAXINPUTLENGTH = 10

    # Dictionary of known PIP HID report IDs
    REPORT_ID_DICT_PIP3 = {
        0x04: "PIP3 Command",
        0x44: "PIP3 Solicited Response",
        0x45: "PIP3 Unsolicited Report",
    }

    # Dictionary of known Non PIP HID Report IDs
    REPORT_ID_DICT_HID = {
        0x01: "Finger",
        0x02: "Pen",
        0x41: "Vendor Specific Finger",
        0x42: "Vendor Specific Pen",
    }

    # Dictionary of known HID register addresses.
    REGISTER_DICT = {
        REGISTER_ADDRESS_HID_DESCRIPTOR: "HID Descriptor",
        REGISTER_ADDRESS_REPORT_DESCRIPTOR: "HID Report Descriptor",
        REGISTER_ADDRESS_OUTPUT: "Output Register",
        REGISTER_ADDRESS_COMMAND: "Command Register",
    }

    def __init__(self):
        PtProtocol.__init__(self)
        # Frame Data
        self.report_id = 0
        self.report_len = 0
        self.start_time = 0
        self.end_time = 0
        self.register_address = 0
        self.enable_hid_pip3_reports = False
        self.hid_descriptor_request_active = False
        self.max_hid_rpt_len = None

    def process_i2c_packet(self, hla_frames, packet):
        """
        All I2C processing starts here and then goes to lower level processing based on the
        packet contents.
        """
        packet_len = len(packet["data"])

        self.start_time = packet["start_time"]
        self.end_time = packet["end_time"]
        if packet["write"] is True:
            self.transaction_start_time = packet["start_time"]
            self.transaction_end_time = packet["end_time"]
            if packet_len < (1 + max(HID1.IDX_REGISTER_ADDRESS_LSB, HID1.IDX_REGISTER_ADDRESS_MSB)):
                self.append_frame(hla_frames, "HID1", "ERROR: Short Write Packet")
                return
            self.register_address = packet["data"][HID1.IDX_REGISTER_ADDRESS_LSB]
            self.register_address += (packet["data"][HID1.IDX_REGISTER_ADDRESS_MSB] << 8)
            if self.register_address == HID1.REGISTER_ADDRESS_HID_DESCRIPTOR:
                self.hid_descriptor_request_active = True
                self.cmd_cmd_name = HID1.REGISTER_DICT.get(self.register_address)
                self.cmd_len = len(packet["data"])
                self.cmd_payload = "0x " + " ".join([f"{x:02X}" \
                    for x in packet["data"]])
            elif self.register_address == HID1.REGISTER_ADDRESS_REPORT_DESCRIPTOR:
                self.hid_descriptor_request_active = True
                self.cmd_cmd_name = HID1.REGISTER_DICT.get(self.register_address)
                self.cmd_len = len(packet["data"])
                self.cmd_payload = "0x " + " ".join([f"{x:02X}" \
                    for x in packet["data"]])
            elif self.register_address == HID1.REGISTER_ADDRESS_OUTPUT:
                if packet_len >= HID1.IDX_OUT_REGISTER_MIN_LENGTH:
                    self.report_id = packet["data"][HID1.IDX_OUT_REGISTER_REPORT_ID]
                    self.report_len = packet["data"][HID1.IDX_OUT_REGISTER_LENGTH_OF_REPORT_LSB]
                    self.report_len += \
						(packet["data"][HID1.IDX_OUT_REGISTER_LENGTH_OF_REPORT_MSB] << 8)
                    if (self.report_id in HID1.REPORT_ID_DICT_PIP3 and
                        self.enable_hid_pip3_reports
                    ):
                        self.cmd_len = self.report_len
                        self.cmd_cmd_name = HID1.REPORT_ID_DICT_PIP3.get(self.report_id)
                        self.cmd_payload = "0x " + " ".join([f"{x:02X}" \
                            for x in packet["data"][self.IDX_OUT_REGISTER_PAYLOAD_START:self.report_len
                                + self.IDX_OUT_REGISTER_PAYLOAD_START]])
                        self.append_frame(hla_frames, "HID1", "")
            elif self.register_address == HID1.REGISTER_ADDRESS_COMMAND:
                if packet_len >= HID1.IDX_CMD_REGISTER_MIN_LENGTH:
                    self.report_id = packet["data"][HID1.IDX_CMD_REGISTER_REPORT_ID]
                    self.report_len = packet["data"][HID1.IDX_CMD_REGISTER_LENGTH_OF_REPORT_LSB]
                    self.report_len += \
						(packet["data"][HID1.IDX_CMD_REGISTER_LENGTH_OF_REPORT_MSB] << 8)
                    if (self.report_id in HID1.REPORT_ID_DICT_PIP3 and
                        self.enable_hid_pip3_reports
                    ):
                        self.cmd_cmd_name = (
                            f"{HID1.REPORT_ID_DICT_PIP3.get(self.report_id)} "
                            f"({HID1.REGISTER_DICT.get(self.register_address)})"
                        )
                        self.cmd_payload = "0x " + " ".join([f"{x:02X}" \
                            for x in packet["data"][self.IDX_CMD_REGISTER_PAYLOAD_START:self.report_len
                                + self.IDX_CMD_REGISTER_PAYLOAD_START]])
                        self.cmd_len = self.report_len
                        self.append_frame(hla_frames, "HID1", "")
        elif (packet["read"] is True and packet_len >= HID1.IDX_INPUT_REPORT_MIN_LENGTH):
            self.transaction_end_time = packet["end_time"]
            if self.hid_descriptor_request_active:
                if self.cmd_cmd_name == HID1.REGISTER_DICT[self.REGISTER_ADDRESS_HID_DESCRIPTOR]:
                    self.debug("Updating Max Input Length")
                    self.update_max_hid_rpt_length(packet)
                self.rsp_len = len(packet["data"])
                self.rsp_payload = "0x " + " ".join([f"{x:02X}" \
                            for x in packet["data"]])
                self.append_frame(hla_frames, "HID1", "")
                self.hid_descriptor_request_active = False
                return
            self.transaction_start_time = packet["start_time"]
            self.rsp_len = packet["data"][HID1.IDX_INPUT_REPORT_LEN_LSB]
            self.rsp_len += (packet["data"][HID1.IDX_INPUT_REPORT_LEN_MSB] << 8)
            report_id = packet["data"][HID1.IDX_INPUT_REPORT_ID]
            if packet_len >= self.IDX_INPUT_REPORT_PAYLOAD_START:
                self.rsp_payload = "0x " + " ".join([f"{x:02X}" \
                    for x in packet["data"][self.IDX_INPUT_REPORT_PAYLOAD_START:]])
            self.debug(f"{self.enable_hid_pip3_reports}: ID {report_id}")
            if (self.max_hid_rpt_len is not None and not self.is_valid_hid_report_length(hla_frames, packet)):
                self.append_frame(hla_frames, "HID1 Error", "Invalid Hid Report Length")
                return
            if report_id in HID1.REPORT_ID_DICT_PIP3:
                if self.enable_hid_pip3_reports:
                    self.cmd_cmd_name = HID1.REPORT_ID_DICT_PIP3.get(report_id)
                    self.append_frame(hla_frames, "HID1", "")
                else:
                    return
            elif report_id in HID1.REPORT_ID_DICT_HID:
                self.cmd_cmd_name = HID1.REPORT_ID_DICT_HID.get(report_id)
                self.append_frame(hla_frames, "HID1", "")
            else:
                self.debug("Unknown HID packet.")

    def is_valid_hid_report_length(self, hla_frames, packet) -> bool:
        """
        Check if the given packet has a valid HID report length.
        """
        hid_report_len = packet["data"][HID1.IDX_REGISTER_ADDRESS_LSB] + (packet["data"][HID1.IDX_REGISTER_ADDRESS_MSB] << 8)
        if len(packet["data"]) == hid_report_len and hid_report_len <= self.max_hid_rpt_len:
            return True
        else:
            self.debug("Invalid HID Report Length.")
            self.debug(f'Packet length: {len(packet["data"])}')
            self.debug(f'Hid Header Report length: {hid_report_len}')
            self.debug(f'Max Report length: {self.max_hid_rpt_len}')
            return False

    def update_max_hid_rpt_length(self, packet: dict) -> None:
        """
        Update the maximum HID report length based on wMaxInputLength from the HID Descriptor.
        """
        if len(packet["data"]) == HID1.W_HID_DESC_LEN:
            self.max_hid_rpt_len = packet["data"][HID1.IDX_HID_DESCRIPTOR_WMAXINPUTLENGTH]
            self.debug(f'Updating Max Hid Report Length to {self.max_hid_rpt_len}')
        else:
            self.debug(f'Invalid HID Descriptor Length {len(packet["data"])} != {HID1.W_HID_DESC_LEN}')
