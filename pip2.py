"""
Parade Technologies Packet Interface Protocol v2 processor. For use with the Parade
Technologies Touch Protocols High Level Analyzer for the Saleae Logic2 software.
"""
from saleae.analyzers import AnalyzerFrame #pylint: disable=import-error

from pt_protocol import PtProtocol

class PIP2 (PtProtocol):
    """
    Parade Technologies Packet Interface Protocol Version 2
    I2C packet parser.
    """
    # Dictionary of known PIP2 command IDs.
    CMD_DICT = {
        0x00: "Ping",
        0x01: "Status",
        0x02: "CTRL",
        0x03: "CONFIG",
        0x05: "CLEAR",
        0x06: "RESET",
        0x07: "Version",
        0x10: "File Open",
        0x11: "File Close",
        0x12: "File Read",
        0x13: "File Write",
        0x14: "File IOCTL",
        0x15: "Flash Info",
        0x16: "Execute",
        0x17: "Get Last Error No",
        0x18: "Exit Host Mode",
        0x19: "Read GPIO",
    }

    def __init__(self):
        PtProtocol.__init__(self)
        # PIP2 Command
        self.pip2_min_cmd_packet_len = 7
        self.idx_cmd_len_lsb = 2
        self.idx_cmd_len_msb = 3
        self.pip2_index_mdata_tag_seq = 4
        self.pip2_index_cmd_id = 5
        self.cmd_header_len = 6
        self.cmd_footer_len = 2
        self.idx_cmd_payload_start = 6
        self.pip2_index_crc_msb = -1
        self.pip2_index_crc_lsb = -0
        self.cmd_payload = None

        # PIP2 Response
        self.rsp_header_len = 4
        self.rsp_footer_len = 2
        self.idx_rsp_payload_start = 4
        self.idx_rsp_len_lsb = 0
        self.idx_rsp_len_msb = 1
        self.idx_rsp_crc_msb = -2
        self.idx_rsp_crc_lsb = -1

        self.expecting_cmd_response = False

    def process_i2c_packet(self, hla_frames, packet):
        """
        All I2C processing starts here and then goes to lower level processing based on the
        packet contents.
        """
        packet_len = len(packet["data"])
        if (packet["write"] is True and
            (packet_len >= self.pip2_min_cmd_packet_len) and
            (packet["data"][0] == 0x01) and
            (packet["data"][1] == 0x01)
            ):
            self.process_command(hla_frames, packet)
        elif (packet["read"] is True and
            packet_len >= 6
            ):
            self.process_response(hla_frames, packet)

    def process_command(self, hla_frames, packet):
        """
        If expecting_cmd_response is True we there may have been a command that did not
        receive a response. In this case output a command frame for the data we have.
        """
        if self.expecting_cmd_response is True:
            self.cmd_cmd_name = PIP2.CMD_DICT.get(self.cmd_cmd)
            self.debug("C1")
            self.append_frame(hla_frames, "PIP2 Error", "PIP2 command with no response")
        self.expecting_cmd_response = True
        self.transaction_start_time = packet["start_time"]
        self.transaction_end_time = packet["end_time"]
        self.cmd_len = packet["data"][self.idx_cmd_len_lsb] + \
            (packet["data"][self.idx_cmd_len_msb] << 8)
        self.cmd_seq = packet["data"][self.pip2_index_mdata_tag_seq] & 0x07
        self.cmd_tag = (packet["data"][self.pip2_index_mdata_tag_seq] & 0x08) >> 3
        self.cmd_cmd = packet["data"][self.pip2_index_cmd_id] & 0x7F
        self.cmd_cmd_name = PIP2.CMD_DICT.get(self.cmd_cmd)
        self.cmd_crc = (packet["data"][self.cmd_len - self.pip2_index_crc_msb] << 8)
        self.cmd_crc += packet["data"][self.cmd_len - self.pip2_index_crc_lsb]
        self.cmd_payload = (
            "0x " + " ".join([f"{x:02X}" for x in
            packet["data"][self.idx_cmd_payload_start:self.cmd_len]])
        )

        # Commands with no response.
        if self.cmd_cmd == 0x06: # Reset.
            self.expecting_cmd_response = False
            self.append_frame(hla_frames, "PIP2", "")

    def process_response(self, hla_frames, packet):
        """
        Parse the given data byte as a PIP2 response. If the given data is the end of the
        response add a Saleae logic bubble frame for the command and response.
        """
        if self.expecting_cmd_response is True:
            packet_len = len(packet["data"])
            if packet_len < max(self.idx_rsp_len_lsb, self.idx_rsp_len_msb):
                self.debug("1")
                self.append_frame(
                    hla_frames,
                    "PIP2 Error",
                    "Short Response Packet. Can't determine length."
                )
                return
            self.rsp_len = (
                packet["data"][self.idx_rsp_len_lsb] +
                (packet["data"][self.idx_rsp_len_msb] << 8)
                )
            if packet_len < max(
                self.rsp_len + self.idx_rsp_crc_msb,
                self.rsp_len + self.idx_rsp_crc_lsb
                ):
                self.debug(f"packet_len: {packet_len}, self.rsp_len: {self.rsp_len}")
                self.append_frame(
                    hla_frames,
                    "PIP2 Error",
                    "Short Response Packet. Can't read CRC."
                )
                return

            self.rsp_crc = (packet["data"][self.rsp_len + self.idx_rsp_crc_msb] << 8)
            self.rsp_crc += packet["data"][self.rsp_len + self.idx_rsp_crc_lsb]
            payload_end  = self.rsp_len - self.rsp_footer_len
            self.rsp_payload = (
                "0x " + \
                " ".join([f"{x:02X}" for x in
                    packet["data"][self.idx_rsp_payload_start:payload_end]])
            )
            self.transaction_end_time = packet["end_time"]
            self.expecting_cmd_response = False
            self.append_frame(hla_frames, "PIP2", "")
