"""
HID-I2C Protocol v1 processor. For use with the Parade Technologies Touch Protocols
High Level Analyzer for the Saleae Logic2 software.
"""

from saleae.analyzers import AnalyzerFrame #pylint: disable=import-error

class HID1:
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

    # Dictionary of known HID report IDs
    REPORT_ID_DICT = {
        0x04: "PIP3 Command",
        0x41: "Vendor Specific Finger",
        0x42: "Vendor Sepcific Pen",
        0x44: "PIP3 Solicited Response",
        0x45: "PIP3 Unsolicited Report",
    }

    # Dictionary of known HID register addresses.
    REGISTER_DICT = {
        REGISTER_ADDRESS_HID_DESCRIPTOR: "HID Descriptor",
        REGISTER_ADDRESS_REPORT_DESCRIPTOR: "HID Report Descriptor",
        REGISTER_ADDRESS_OUTPUT: "Output Register",
        REGISTER_ADDRESS_COMMAND: "Command Register",
    }

    def __init__(self):
        # Frame Data
        self.report_id = 0
        self.report_len = 0
        self.start_time = 0
        self.end_time = 0
        self.register_address = 0
        self.z_msg = None

    def process_i2c_packet(self, frames, packet):
        """
        All I2C processing starts here and then goes to lower level processing based on the
        packet contents.
        """
        packet_len = len(packet["data"])
        self.start_time = packet["start_time"]
        self.end_time = packet["end_time"]
        if packet["write"] is True:
            if packet_len < (1 + max(HID1.IDX_REGISTER_ADDRESS_LSB, HID1.IDX_REGISTER_ADDRESS_MSB)):
                self.z_msg = "ERROR: Short Write Packet"
                self.append_command_frame(frames)
                return
            self.register_address = packet["data"][HID1.IDX_REGISTER_ADDRESS_LSB]
            self.register_address += (packet["data"][HID1.IDX_REGISTER_ADDRESS_MSB] << 8)
            if self.register_address == HID1.REGISTER_ADDRESS_HID_DESCRIPTOR:
                self.report_len = len(packet["data"])
                frames.append(AnalyzerFrame(
                    "HID1",
                    self.start_time,
                    self.end_time,
                    data={
                        "Cmd_Name" :"HID Descriptor",
                    }
                ))
            elif self.register_address == HID1.REGISTER_ADDRESS_REPORT_DESCRIPTOR:
                frames.append(AnalyzerFrame(
                    "HID1",
                    self.start_time,
                    self.end_time,
                    data={
                        "Cmd_Name" :"HID Report Descriptor",
                    }
                ))
            elif self.register_address == HID1.REGISTER_ADDRESS_OUTPUT:
                if packet_len >= HID1.IDX_OUT_REGISTER_MIN_LENGTH:
                    self.report_id = packet["data"][HID1.IDX_OUT_REGISTER_REPORT_ID]
                    self.report_len = packet["data"][HID1.IDX_OUT_REGISTER_LENGTH_OF_REPORT_LSB]
                    self.report_len += \
						(packet["data"][HID1.IDX_OUT_REGISTER_LENGTH_OF_REPORT_MSB] << 8)
                    self.append_command_frame(frames)

            elif self.register_address == HID1.REGISTER_ADDRESS_COMMAND:
                if packet_len >= HID1.IDX_CMD_REGISTER_MIN_LENGTH:
                    self.report_id = packet["data"][HID1.IDX_CMD_REGISTER_REPORT_ID]
                    self.report_len = packet["data"][HID1.IDX_CMD_REGISTER_LENGTH_OF_REPORT_LSB]
                    self.report_len += \
						(packet["data"][HID1.IDX_CMD_REGISTER_LENGTH_OF_REPORT_MSB] << 8)
                    self.append_command_frame(frames)

        elif (packet["read"] is True and packet_len >= HID1.IDX_INPUT_REPORT_MIN_LENGTH):
            length_of_report = packet["data"][HID1.IDX_INPUT_REPORT_LEN_LSB]
            length_of_report += (packet["data"][HID1.IDX_INPUT_REPORT_LEN_MSB] << 8)
            report_id = packet["data"][HID1.IDX_INPUT_REPORT_ID]

            if report_id in HID1.REPORT_ID_DICT:
                frames.append(AnalyzerFrame(
                    "HID1",
                    self.start_time,
                    self.end_time,
                    data={
                        "Cmd_Name" :f"{HID1.REPORT_ID_DICT.get(report_id)}",
                        "R Len"    : f"{length_of_report:d}",
                    }
                ))
            else:
                frames.append(AnalyzerFrame(
                    "HID1",
                    self.start_time,
                    self.end_time,
                    data={
                        "R Len"    : f"{length_of_report:d}",
                    }
                ))

    def append_command_frame(self, frames):
        """
        Appends a Saleae HLA frame to the frames object. The frame uses data from the
        PIP3 object (e.g. self.cmd_pkt_cmd) and the method input variables to product
        the frame.
        """

        if self.report_id is None:
            report_name = ""
        else:
            report_name = HID1.REPORT_ID_DICT.get(self.report_id)
        if self.register_address is None:
            report_type = ""
        else:
            report_type = self.REGISTER_DICT.get(self.register_address)

        if self.report_len is None:
            c_len = ""
        else:
            c_len = f"{self.report_len:d}"

        if self.    z_msg is None:
            z_msg = ""
        else:
            z_msg = self.    z_msg

        frames.append(AnalyzerFrame(
            "HID1",
            self.start_time,
            self.end_time,
            data={
                "Cmd_Name" :f"{report_name} ({report_type})",
                "C Len"    :c_len,
                "z_msg"    :z_msg
            }
        ))

        # Reset all fields to None so that data does not carry over from one frame to another.
        self.report_id = None
        self.register_address = None
        self.report_len = None
        self.z_msg = None
