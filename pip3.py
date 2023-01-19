"""
Parade Technologies Packet Interface Protocol v3 processor. For use with the Parade
Technologies Touch Protocols High Level Analyzer for the Saleae Logic2 software.
"""

from typing import List
from saleae.analyzers import AnalyzerFrame #pylint: disable=import-error
from pt_protocol import PtProtocol

class PIP3 (PtProtocol):
    """
    Parade Technologies Packet Interface Protocol Version 3
    I2C packet parser.
    """
    PACKET_DATA = (0x25, 0x00, 0x44)

    # Dictionary of known PIP3 command IDs.
    CMD_DICT = {
            0x00: "Ping",
            0x01: "Status",
            0x04: "Switch Image",
            0x07: "Version",
            0x10: "File Open",
            0x11: "File Close",
            0x12: "File Read",
            0x13: "File Write",
            0x14: "File IOCTL",
            0x15: "Flash Info",
            0x20: "Get Data Block CRC",
            0x22: "Get Data Block",
            0x23: "Set Data Block",
            0x24: "Get Data Structure",
            0x25: "Load Self Test Param",
            0x26: "Run Self Test",
            0x27: "Get Self Test Results",
            0x29: "Initalize Baseines",
            0x2A: "Execute Scan",
            0x2B: "Retrieve Panel Scan",
            0x2C: "Start Sensor Data",
            0x2D: "Stop Async Debug Data",
            0x2E: "Start Tracking Heatmap",
            0x30: "Calibrate",
            0x31: "Soft Reset",
            0x32: "Get Sysinfo",
            0x33: "Suspend Scanning",
            0x34: "Resume Scannning",
            0x35: "Get Param",
            0x36: "Set Param",
            0x37: "Get Noise Metrics",
            0x38: "?",
            0x39: "Enter Easy Wake",
            0x3A: "Set DBG Parameter",
            0x3B: "Get DBG Parameter",
            0x3C: "Set DDI Reg",
            0x3D: "Get DDI Reg",
            0x3E: "Start Realtime Signal Data",
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

        # PIP3 Command
        self.pip3_min_cmd_packet_len = 14
        self.idx_frpt_mrpt = 3 # Special. Only in first report.
        self.cmd_register_header_len = 6
        self.cmd_output_header_len = 5
        self.cmd_header_len = 4
        self.cmd_footer_len = 2

        #self.cmd_pkt_payload[0] = 0


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
        self.rsp_offset_crc_lsb = -0


    def process_i2c_packet(self, hla_frames, packet):
        """
        All I2C processing starts here and then goes to lower level processing based on the
        packet contents.
        """
        packet_len = len(packet["data"])
        if packet_len < 2:
            print("Unknown packet. Less than two bytes")
        elif(packet_len == 2 and packet["read"] is True):
            # PIP3 Firmware Reset Sentinel.
            if ((packet["data"][0] == 0x00) and (packet["data"][1] == 0x00)):
                self.transaction_start_time = packet["start_time"]
                self.transaction_end_time = packet["end_time"]
                self.cmd_cmd_name = "FW Reset Sentinel"
                self.expecting_cmd_response = False
                self.append_frame(hla_frames, "PIP3", "")
        elif packet["write"] is True:
            self.process_command(hla_frames, packet)
        elif (packet["read"] is True and
            tuple(packet["data"][:len(PIP3.PACKET_DATA)]) == PIP3.PACKET_DATA):
            self.process_response(hla_frames, packet)
        elif packet["read"] is True:
            if self.expecting_cmd_response is True:
                self.append_frame(hla_frames, "PIP3", "PIP3 command with no response")
                self.expecting_cmd_response = False

    def pip3_stitch(self, data):
        """
        Adds a HID input report to the PIP3 packet. See 001-30009 for details on how a
        PIP3 response packet can be broken up in to multiple HID input reports.
        """
        self.pkt_data.extend(data[4:])

    def pip3_extract_rsp_payload(self):
        """
        Get the payload data bytes from the PIP3 response.
        """
        payload_end_idx = self.rsp_len - self.rsp_footer_len
        if payload_end_idx > self.idx_rsp_payload_start:
            self.rsp_payload = "0x " + " ".join([f"{x:02X}" \
                for x in self.pkt_data[self.idx_rsp_payload_start:payload_end_idx]])

    def pip3_parse_response_header(self):
        """
        Extract the PIP3 header fields into class variables.
        """
        self.rsp_len = self.pkt_data[self.rsp_idx_len_lsb]
        self.rsp_len += (self.pkt_data[self.rsp_idx_len_msb] << 8)
        self.rsp_mdata = (self.pkt_data[self.rsp_idx_mdata_tag_seq] & 0x10) >> 4
        self.rsp_seq = (self.pkt_data[self.rsp_idx_mdata_tag_seq] & 0x07)
        self.rsp_tag = (self.pkt_data[self.rsp_idx_mdata_tag_seq] & 0x08) >> 3
        self.rsp_cmd_id = (self.pkt_data[self.rsp_idx_cmd_id] & 0x7F)
        self.rsp_rsp = (self.pkt_data[self.rsp_idx_cmd_id] & 0x80) >> 7
        self.rsp_status = self.pkt_data[self.rsp_idx_cmd_status]

    def pip3_remove_zero_padding(self):
        """
        The HID layer may pad a response packet with zeros. This method removes that
        padding.
        """
        del self.pkt_data[self.rsp_len:]

    def process_command(self, hla_frames, packet):
        """
        Parse the given data byte as a PIP3 command.
        """
        data_len = len(packet["data"])
        if data_len < (1 + max(
            self.idx_hid_register_address_lsb,
            self.idx_hid_register_address_msb)
			):
            self.transaction_start_time = packet["start_time"]
            self.transaction_end_time = packet["end_time"]
            self.append_frame(hla_frames, "PIP3", "ERROR: Short Write Packet")
            return
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

        # If expecting_cmd_response is True we there may have been a command that did not
        # receive a response. In this case output a command frame for the data we have.
        if self.expecting_cmd_response is True:
            self.append_frame(hla_frames, "PIP3 Error", "PIP3 command with no response")

        self.expecting_cmd_response = True
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

        payload_end_idx = (offset + self.idx_cmd_register_payload_start + self.cmd_len) - \
            (self.cmd_header_len + self.cmd_footer_len)
        self.cmd_payload = "0x " + " ".join([f"{x:02X}" for x in \
            packet["data"][offset:payload_end_idx]])
        self.cmd_seq = packet["data"][offset + self.idx_mdata_tag_seq] & 0x07
        self.cmd_tag = (packet["data"][offset + self.idx_mdata_tag_seq] & 0x08) >> 3
        self.cmd_cmd = packet["data"][offset + self.idx_cmd_id] & 0x7F
        self.cmd_cmd_name = PIP3.CMD_DICT.get(self.cmd_cmd)
        self.cmd_crc = (packet["data"][offset + self.idx_len_lsb + self.cmd_len - 2] << 8)
        self.cmd_crc += packet["data"][offset + self.idx_len_msb + self.cmd_len - 2]
        self.rsp_status = None # Clear value in case a response never comes.

        # Commands with no response
        if self.cmd_cmd == 0x04: # Switch Image.
            self.expecting_cmd_response = False
            self.append_frame(hla_frames, "PIP3", "")



    def process_response(self, hla_frames, packet):
        """
        Parse the given data byte as a PIP3 response. If the given data is the end of the
        response add a Saleae logic bubble frame for the command and response.
        """
        pkt_frpt = (packet["data"][self.idx_frpt_mrpt] & 0x02) >> 1
        pkt_mrpt = (packet["data"][self.idx_frpt_mrpt] & 0x01)
        if pkt_frpt:
            self.rsp_start_time = packet["start_time"]
            self.rsp_end_time = packet["end_time"]
            self.pkt_data = []
        if not pkt_mrpt:
            self.rsp_end_time = packet["end_time"]

        self.pip3_stitch(packet["data"])

        if not pkt_mrpt:
            self.expecting_cmd_response = False
            self.transaction_end_time = packet["end_time"]
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
                self.pip3_remove_zero_padding()
                self.pip3_extract_rsp_payload()
                self.append_frame(hla_frames, "PIP3", "")
