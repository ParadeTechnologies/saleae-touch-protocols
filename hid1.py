"""
HID-I2C Protocol v1 processor. For use with the Parade Technologies Touch Protocols
High Level Analyzer for the Saleae Logic2 software.
"""

from saleae.analyzers import AnalyzerFrame #pylint: disable=import-error

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
    IDX_INPUT_REPORT_LEN_LSB = 0
    IDX_INPUT_REPORT_LEN_MSB = 1
    IDX_INPUT_REPORT_ID = 2

    # HID Command Constants Common to Cmd and Out Formats
    IDX_REGISTER_ADDRESS_LSB = 0
    IDX_REGISTER_ADDRESS_MSB = 1

    # HID Command Register Constants
    IDX_CMD_REGISTER_MIN_LENGTH = 9
    IDX_CMD_REGISTER_LENGTH_OF_REPORT_LSB = 6
    IDX_CMD_REGISTER_LENGTH_OF_REPORT_MSB = 7
    IDX_CMD_REGISTER_REPORT_ID = 8

    # HID Output Register Constants
    IDX_OUT_REGISTER_MIN_LENGTH = 5
    IDX_OUT_REGISTER_LENGTH_OF_REPORT_LSB = 2
    IDX_OUT_REGISTER_LENGTH_OF_REPORT_MSB = 3
    IDX_OUT_REGISTER_REPORT_ID = 4

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
        0x42: "Vendor Sepcific Pen",
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
                self.report_len = len(packet["data"])
            elif self.register_address == HID1.REGISTER_ADDRESS_REPORT_DESCRIPTOR:
                self.hid_descriptor_request_active = True
                self.cmd_cmd_name = HID1.REGISTER_DICT.get(self.register_address)
                self.report_len = len(packet["data"])
            elif self.register_address == HID1.REGISTER_ADDRESS_OUTPUT:
                if packet_len >= HID1.IDX_OUT_REGISTER_MIN_LENGTH:
                    self.report_id = packet["data"][HID1.IDX_OUT_REGISTER_REPORT_ID]
                    self.report_len = packet["data"][HID1.IDX_OUT_REGISTER_LENGTH_OF_REPORT_LSB]
                    self.report_len += \
						(packet["data"][HID1.IDX_OUT_REGISTER_LENGTH_OF_REPORT_MSB] << 8)
                    if (self.report_id in HID1.REPORT_ID_DICT_PIP3 and
                        self.enable_hid_pip3_reports
                    ):
                        self.cmd_cmd_name = HID1.REPORT_ID_DICT_PIP3.get(self.report_id)
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
                        self.append_frame(hla_frames, "HID1", "")
        elif (packet["read"] is True and packet_len >= HID1.IDX_INPUT_REPORT_MIN_LENGTH):
            self.transaction_end_time = packet["end_time"]
            if self.hid_descriptor_request_active:
                self.append_frame(hla_frames, "HID1", "")
                self.hid_descriptor_request_active = False
                return
            self.transaction_start_time = packet["start_time"]
            self.cmd_len = packet["data"][HID1.IDX_INPUT_REPORT_LEN_LSB]
            self.cmd_len += (packet["data"][HID1.IDX_INPUT_REPORT_LEN_MSB] << 8)
            report_id = packet["data"][HID1.IDX_INPUT_REPORT_ID]

            self.debug(f"{self.enable_hid_pip3_reports}: ID {report_id}")
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
