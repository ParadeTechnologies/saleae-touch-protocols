"""
Parade Technologies Packet Interface Protocol v3 processor. For use with the Parade
Technologies Touch Protocols High Level Analyzer for the Saleae Logic2 software.
"""

from typing import List
from saleae.analyzers import AnalyzerFrame # type: ignore #pylint: disable=import-error
from pt_protocol import PtProtocol

class PIP3 (PtProtocol):
    """
    Parade Technologies Packet Interface Protocol Version 3
    I2C packet parser.
    """

    RSP_HID_RPT_ID_ASYNC = 0x45
    RSP_HID_RPT_ID_SOLICITED = 0x44
    IDX_RSP_HID_RPT_ID = 2

    # Segmentation Control
    FRPT_MASK = 0x02
    MRPT_MASK = 0x01

    # PIP3 Header Masks
    PIP_3_HEADER_SEQ_MASK = 0x07
    PIP_3_HEADER_TAG_MASK = 0x08
    PIP_3_HEADER_M_DATA_MASK = 0x10
    PIP_3_HEADER_RESP_MASK = 0x80
    PIP_3_HEADER_CMD_ID_MASK = 0x7f

    # HID CMD REG CMD format
    HID_REPORT_ID = 0x4

    # Dictionary of known PIP3 command IDs.
    CMD_DICT = {
            0x00: "Ping",
            0x01: "Status",
            0x04: "Switch Image",
            0x05: "Switch Active Processor",
            0x07: "Version",
            0x10: "File Open",
            0x11: "File Close",
            0x12: "File Read",
            0x13: "File Write",
            0x14: "File IOCTL",
            0x15: "Flash Info",
            0x16: "Execute",
            0x17: "Get Last Errno",
            0x20: "Get Data Block CRC",
            0x22: "Get Data Block",
            0x23: "Set Data Block",
            0x24: "Get Data Structure",
            0x25: "Load Self Test Param",
            0x26: "Run Self Test",
            0x27: "Get Self Test Results",
            0x29: "Initialize Baselines",
            0x2A: "Execute Scan",
            0x2B: "Retrieve Panel Scan",
            0x2C: "Start Sensor Data",
            0x2D: "Stop Async Debug Data",
            0x2E: "Start Tracking Heatmap",
            0x2F: "Debug Report",
            0x30: "Calibrate",
            0x31: "Soft Reset",
            0x32: "Get Sysinfo",
            0x33: "Suspend Scanning",
            0x34: "Resume Scanning",
            0x35: "Get Param",
            0x36: "Set Param",
            0x37: "Get Noise Metrics",
            0x39: "Enter Easy Wake",
            0x3A: "Set DBG Parameter",
            0x3B: "Get DBG Parameter",
            0x3C: "Set DDI Reg",
            0x3D: "Get DDI Reg",
            0x3E: "Start Sensor Scan",
        }

    # Dictionary of known PIP3 command IDs without a PIP response.
    CMD_NO_RSP_DICT = {
        0x04: "Switch Image",
        0x05: "Switch Active Processor",
        0x16: "Execute",
        0x31: "Soft Reset"
    }

    def __init__(self):
        PtProtocol.__init__(self)
        self.hid_register_address_output = 0x0004
        self.hid_register_address_command = 0x0005
        self.hid_register_address_pip2 = 0x0101

        # HID Command Constants Common to Command and Out Formats
        self.idx_hid_register_address_lsb = 0
        self.idx_hid_register_address_msb = 1

        # PIP3 Generic (Command or Response)

        # PIP3 response only start and end time.
        self.rsp_start_time = None
        self.rsp_end_time = None

        self.pkt_data = []
        self.expecting_cmd_response = False
        self.cmd_end_time = None
        
        # PIP3 Unsolicited Async reports
        self.async_rsp = False
        self.rsp_initiated = False
        self.rsp_interrupted = False
        self.unstitched_async_data = []

        # PIP3 Command
        self.pip3_min_cmd_packet_len = 14
        self.idx_frpt_mrpt = 3 # Special. Only in first report.
        self.cmd_register_header_len = 6
        self.cmd_output_header_len = 5
        self.cmd_header_len = 4
        self.cmd_footer_len = 2

        self.idx_len_lsb = 0
        self.idx_len_msb = 1
        self.idx_mdata_tag_seq = 2
        self.idx_cmd_id = 3
        self.idx_cmd_register_payload_start = 9
        self.idx_output_register_payload_start = 5

        # PIP3 Response
        self.rsp_header_len = 4
        self.rsp_footer_len = 2
        self.idx_rsp_payload_start = 5 # Includes HID wrapper bytes.

        self.rsp_min_len = 5
        self.rsp_idx_len_lsb = 0
        self.rsp_idx_len_msb = 1
        self.rsp_idx_mdata_tag_seq = 2
        self.rsp_idx_cmd_id = 3
        self.rsp_idx_cmd_status = 4
        self.rsp_offset_crc_msb = -1
        self.rsp_offset_crc_lsb = -2

        self.reset_sentinel_len = 2

    def process_i2c_packet(self, hla_frames, packet):
        """
        All I2C processing starts here and then goes to lower level processing based on the
        packet contents.
        """
        packet_len = len(packet["data"])
        if packet_len < self.reset_sentinel_len:
            print("Unknown packet. Less than two bytes")
        elif(packet_len == self.reset_sentinel_len and packet["read"] is True):
            # PIP3 Firmware Reset Sentinel.
            if ((packet["data"][0] == 0x00) and (packet["data"][1] == 0x00)):
                self.transaction_start_time = packet["start_time"]
                self.transaction_end_time = packet["end_time"]
                self.cmd_cmd = None
                self.cmd_cmd_name = "FW Reset Sentinel"
                self.expecting_cmd_response = False
                self.append_frame(hla_frames, "PIP3", "")
        elif packet["write"] is True:
            self.process_command(hla_frames, packet)
        elif (packet["read"] is True and 
            packet["data"][PIP3.IDX_RSP_HID_RPT_ID] == PIP3.RSP_HID_RPT_ID_ASYNC):
            if (self.expecting_cmd_response is True):
                self.transaction_end_time = self.cmd_end_time
                self.expecting_cmd_response = False
                self.append_frame(hla_frames, "PIP3", "")
            self.async_rsp = True
            self.process_response(hla_frames, packet)
        elif (packet["read"] is True and
            packet["data"][PIP3.IDX_RSP_HID_RPT_ID] == PIP3.RSP_HID_RPT_ID_SOLICITED):
            # Solicited response interrupts Unsolicited report
            if self.async_rsp is True:
                self.handle_packet_interrupt(packet, hla_frames)
            self.async_rsp = False
            self.process_response(hla_frames, packet)
        elif packet["read"] is True:
            if self.expecting_cmd_response is True:
                self.append_frame(hla_frames, "PIP3 Error", "PIP3 command with no response")
                self.expecting_cmd_response = False

    def pip3_stitch(self, data):
        """
        Adds a HID input report to the PIP3 packet. See 001-30009 for details on how a
        PIP3 response packet can be broken up into multiple HID input reports.
        """
        self.pkt_data.extend(data[self.cmd_header_len:])

    def pip3_extract_rsp_payload(self):
        """
        Get the payload data bytes from the PIP3 response.
        """
        # Async Reports do not contain a Status byte
        offset = -1 if self.async_rsp else 0

        payload_end_idx = self.rsp_len - self.rsp_footer_len
        if payload_end_idx > self.idx_rsp_payload_start:
            self.rsp_payload = "0x " + " ".join([f"{x:02X}" \
                for x in self.pkt_data[self.idx_rsp_payload_start + offset:payload_end_idx]])

    def pip3_parse_response_header(self):
        """
        Extract the PIP3 header fields into class variables.
        """
        self.rsp_len = self.pkt_data[self.rsp_idx_len_lsb]
        self.rsp_len += (self.pkt_data[self.rsp_idx_len_msb] << 8)
        self.rsp_mdata = (self.pkt_data[self.rsp_idx_mdata_tag_seq] & PIP3.PIP_3_HEADER_M_DATA_MASK) >> 4
        self.rsp_seq = (self.pkt_data[self.rsp_idx_mdata_tag_seq] & PIP3.PIP_3_HEADER_SEQ_MASK)
        self.rsp_tag = (self.pkt_data[self.rsp_idx_mdata_tag_seq] & PIP3.PIP_3_HEADER_TAG_MASK) >> 3
        self.rsp_cmd_id = (self.pkt_data[self.rsp_idx_cmd_id] & PIP3.PIP_3_HEADER_CMD_ID_MASK)
        self.rsp_rsp = (self.pkt_data[self.rsp_idx_cmd_id] & PIP3.PIP_3_HEADER_RESP_MASK) >> 7
        self.rsp_status = self.pkt_data[self.rsp_idx_cmd_status]

        # async reports do not contain a status byte
        if self.async_rsp is True:
            self.rsp_status = None
            self.async_rsp = False

        if (self.async_rsp or not self.expecting_cmd_response) is True:
            self.cmd_cmd = self.pkt_data[self.rsp_idx_cmd_id] & PIP3.PIP_3_HEADER_CMD_ID_MASK
            self.cmd_cmd_name = PIP3.CMD_DICT.get(self.cmd_cmd)

    def handle_packet_interrupt(self, packet, hla_frames):
        """
        Async Report handling when interrupted by commands and Solicited responses
        """
        if self.transaction_start_time is None:
            self.transaction_start_time = packet["start_time"]
        self.transaction_end_time = self.rsp_end_time
        if self.transaction_end_time is None:
            self.transaction_end_time = packet["end_time"]
        self.rsp_interrupted = True
        self.unstitched_async_data = self.pkt_data[:]
        self.pip3_parse_response_header()
        self.pip3_remove_zero_padding()
        self.pip3_extract_rsp_payload()
        self.append_frame(hla_frames, "PIP3", "")

    def pip3_parse_response_crc(self):
        """
        Extracts the crc of a complete response
        """
        if self.rsp_initiated is False:
            self.rsp_crc = self.pkt_data[self.rsp_len + self.rsp_offset_crc_lsb]
            self.rsp_crc += (self.pkt_data[self.rsp_len + self.rsp_offset_crc_msb] << 8)

    def pip3_remove_zero_padding(self):
        """
        The HID layer may pad a response packet with zeros. This method removes that
        padding.
        """
        del self.pkt_data[self.rsp_len:]

    def pip3_is_valid_rsp_len(self) -> bool:
        """
        Validated the PIP3 length of Payload
        """
        valid = len(self.pkt_data) == self.rsp_len
        if not valid:
            self.debug(f'PIP Data Length {len(self.pkt_data)} != reported PIP3 Length of Payload {self.rsp_len}')
        return valid

    def pip3_valid_rsp_id(self, packet) -> bool:
        """
        Validated the response ID matches the command id
        """
        if len(packet["data"]) < (self.cmd_output_header_len + self.rsp_footer_len + self.rsp_header_len):
            return False
        if (packet["data"][self.rsp_header_len + self.rsp_idx_cmd_id] & self.PIP_3_HEADER_CMD_ID_MASK) != self.cmd_cmd:
            return False
        return True

    def process_command(self, hla_frames, packet):
        """
        Parse the given data byte as a PIP3 command.
        """
        data_len = len(packet["data"])
        self.rsp_status = None

        if data_len < (1 + max(
            self.idx_hid_register_address_lsb,
            self.idx_hid_register_address_msb)
			):
            self.transaction_start_time = packet["start_time"]
            self.transaction_end_time = packet["end_time"]
            self.append_frame(hla_frames, "PIP3 Error", "ERROR: Short Write Packet")
            return

        if self.rsp_initiated is True:
            self.handle_packet_interrupt(packet, hla_frames)

        hid_register_address = packet["data"][self.idx_hid_register_address_lsb]
        hid_register_address += (packet["data"][self.idx_hid_register_address_msb] << 8)

        # 1) Determine if the write is in the output or command register format.
        # 2) Set the PIP3 packet payload offset based on the command type.
        if hid_register_address == self.hid_register_address_output:
            offset = self.idx_output_register_payload_start
        elif hid_register_address == self.hid_register_address_command:
            offset = self.idx_cmd_register_payload_start
        elif hid_register_address == self.hid_register_address_pip2:
            return
        else:
            self.debug("Non PIP3 HID Register Address: " + str(hid_register_address))
            self.expecting_cmd_response = False
            return

        # If expecting_cmd_response is True there may have been a command that did not
        # receive a response. In this case output a command frame for the data we have.
        if self.expecting_cmd_response is True:
            self.append_frame(hla_frames, "PIP3 Error", "PIP3 command with no response")

         # Check for Report ID
        if packet["data"][offset - 1] != PIP3.HID_REPORT_ID:
            return

        self.transaction_start_time = packet["start_time"]
        self.transaction_end_time = packet["end_time"]

        # Check that the packet is long enough that a length can be extracted.
        if (data_len < (1 + max(
            offset + self.idx_len_lsb,
            offset + self.idx_len_msb
        ))):
            self.append_frame(hla_frames, "PIP3", "ERROR: Short Write Packet")
            return
        # 3) Process the command.
        self.cmd_len = packet["data"][offset + self.idx_len_lsb] + \
            (packet["data"][offset + self.idx_len_msb] << 8)

        # Check that the packet is as long as the length indicates.
        if self.cmd_len >= data_len:
            self.append_frame(hla_frames, "PIP3", "ERROR: Short Write Packet.")
            return

        payload_end_idx = (offset + self.cmd_len) - \
            (self.cmd_footer_len)
        if (self.cmd_len > (self.cmd_header_len + self.cmd_footer_len)):
            self.cmd_payload = "0x " + " ".join([f"{x:02X}" for x in \
                packet["data"][offset + self.cmd_header_len:payload_end_idx]])
        self.expecting_cmd_response = True 
        self.cmd_seq = packet["data"][offset + self.idx_mdata_tag_seq] & PIP3.PIP_3_HEADER_SEQ_MASK
        self.cmd_tag = (packet["data"][offset + self.idx_mdata_tag_seq] & PIP3.PIP_3_HEADER_TAG_MASK) >> 3
        self.cmd_cmd = packet["data"][offset + self.idx_cmd_id] & PIP3.PIP_3_HEADER_CMD_ID_MASK
        self.cmd_cmd_name = PIP3.CMD_DICT.get(self.cmd_cmd)
        self.cmd_crc = packet["data"][offset + self.idx_len_lsb + self.cmd_len - self.cmd_footer_len]
        self.cmd_crc += (packet["data"][offset + self.idx_len_msb + self.cmd_len - self.cmd_footer_len] << 8)
        self.cmd_end_time = packet["end_time"]

        # Commands with no response
        if self.cmd_cmd in self.CMD_NO_RSP_DICT.keys(): # Commands that have no PIP response on successful execution.
            self.expecting_cmd_response = False
            self.append_frame(hla_frames, "PIP3", "")

    def process_response(self, hla_frames, packet):
        """
        Parse the given data byte as a PIP3 response. If the given data is the end of the
        response add a Saleae logic bubble frame for the command and response.
        """

        pkt_frpt = (packet["data"][self.idx_frpt_mrpt] & PIP3.FRPT_MASK) >> 1
        pkt_mrpt = (packet["data"][self.idx_frpt_mrpt] & PIP3.MRPT_MASK)

        if pkt_frpt and self.expecting_cmd_response and not self.pip3_valid_rsp_id(packet):
            self.append_frame(hla_frames, "PIP3 Error", "Sent Cmd ID != Response Cmd ID")

        self.transaction_end_time = packet["end_time"]
        self.rsp_end_time = packet["end_time"]

        if self.transaction_start_time is None:
            self.transaction_start_time = packet["start_time"]

        if pkt_frpt or self.rsp_interrupted:
            self.rsp_start_time = packet["start_time"]
            if self.rsp_interrupted or not self.expecting_cmd_response:
                self.transaction_start_time = self.rsp_start_time
            self.pkt_data = []
            self.rsp_initiated = True

        if (self.expecting_cmd_response or self.rsp_initiated) is False:
            self.rsp_start_time = packet["start_time"]

        # Stitching interrupted async reports
        if self.rsp_interrupted and self.async_rsp:
            self.pkt_data = self.unstitched_async_data[:]
            self.rsp_interrupted = False

        self.pip3_stitch(packet["data"])

        if not pkt_mrpt:
            if self.async_rsp and self.rsp_start_time < self.transaction_end_time:
                self.transaction_start_time = self.rsp_start_time
            self.expecting_cmd_response = False
            self.rsp_interrupted = False
            self.rsp_initiated = False
            if len(self.pkt_data) < self.rsp_min_len:
                self.append_frame(
                    hla_frames,
                    "PIP3",
                    (
                        f"ERROR:Response is shorter ({len(self.pkt_data)}) "
                        "than the minimum length ({self.rsp_min_len})."
                    )
                )
            else:
                self.pip3_parse_response_header()
                self.pip3_parse_response_crc()
                self.pip3_remove_zero_padding()
                self.pip3_extract_rsp_payload()
                if not self.pip3_is_valid_rsp_len():
                    self.append_frame(hla_frames,"PIP3 Error", "Invalid PIP3 Length of Payload")
                else:
                    self.append_frame(hla_frames, "PIP3", "")
