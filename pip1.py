"""
Parade Technologies Packet Interface Protocol v1 processor. For use with the
Parade Technologies Touch Protocols High Level Analyzer for the Saleae Logic2
software.
"""

from saleae.analyzers import AnalyzerFrame # type: ignore #pylint: disable=import-error

from pt_protocol import PtProtocol
class PIP1 (PtProtocol):
    """
    Parade Technologies Packet Interface Protocol Version 1
    I2C packet parser.
    """

    # PIP1 Command
    CMD_OUTPUT_REPORT_ID    = 0x2F
    OUTPUT_RPT_REG_LSB      = 0x04
    OUTPUT_RPT_REG_MSB      = 0x00
    IDX_CMD_RPT_REG_LSB     = 0x00
    IDX_CMD_RPT_REG_MSB     = 0x01
    LEN_MIN_CMD_PACKET      = 7
    IDX_CMD_RPT_ID          = 4
    IDX_CMD_LEN_LSB         = 2
    IDX_CMD_LEN_MSB         = 3
    IDX_CMD_CMD_ID          = 6
    IDX_CMD_PAYLOAD_START   = 7
    LEN_CMD_REG_HEADER      = 1

    # PIP1 Response
    CMD_INPUT_REPORT_ID     = 0x1F
    LEN_MIN_RSP             = 5
    LEN_MIN_ASYNC_RSP       = 7
    IDX_RSP_PAYLOAD_START   = 5
    IDX_RSP_LEN_LSB         = 0
    IDX_RSP_LEN_MSB         = 1
    IDX_RSP_RPT_ID          = 2
    IDX_RSP_CMD_ID          = 4
    IDX_RSP_TAG             = 4
    SHIFT_MSB               = 8
    IDX_PIP2_CMD_REG_LSB    = 5
    IDX_PIP2_CMD_REG_MSB    = 6

    IDX_ASYNC_RPT_START     = 3
    
    # Misc
    BIT_SHIFT_TGL           = 0x07
    MASK_CMD_ID             = 0x7F
    MASK_TGL                = 0x80
    CMD_ID_START_BOOTLOADER = 0x01
    PIP2_CMD_REG            = 0x0101

    # Dictionary of known PIP1 command IDs.
    CMD_DICT = {
        0x00: "Ping",
        0x01: "Start Bootloader",
        0x02: "Get System Information",
        0x03: "Suspend Scanning",
        0x04: "Start Scanning",
        0x05: "Get Parameter",
        0x06: "Set Parameter",
        0x07: "Get Noise Metrics",
        0x08: "Operating Mode Change",
        0x09: "Enter EasyWake State",
        0x20: "Verify Data Block CRC",
        0x21: "Get Data Row Size",
        0x22: "Read Data Block",
        0x23: "Write Data Block",
        0x24: "Retrieve Data Structure",
        0x25: "Load Self Test Parameters",
        0x26: "Run Self Test",
        0x27: "Get Self Test Results",
        0x28: "Calibrate IDACs",
        0x29: "Initialize Baselines",
        0x2A: "Execute Panel Scan",
        0x2B: "Retrieve Panel Scan",
        0x2C: "Start Sensor Data Mode",
        0x2D: "Revert to Normal Reporting Mode",
        0x2E: "Start Tracking eat Map Mode",
        0x2F: "Start Full Self-Cap Reporting Mode",
        0x30: "Calibrate Device (Extended)",
        0x40: "Interrupt Pin Override",
        0x60: "Store Panel Scan",
        0x61: "Process Panel Scan",
        0x70: "Set Debug Parameter",
        0x71: "Get Debug Parameter"
    }

    RPT_ID_DICT = {
        0x01: "Touch panel touch report",
        0x03: "CapSense Button Report",
        0x04: "Wakeup Event Report",
        0x06: "PushButton Report",
        0x0D: "Full Self-Cap Input Report",
        0x0E: "Tracking Heat Map Mode Input Report",
        0x0F: "Sensor Data Mode Input Report"
    }

    def __init__(self):
        PtProtocol.__init__(self)
        self.cmd_payload = None
        self.expecting_cmd_response = False

    def process_i2c_packet(self, la_frames, packet):
        """
        All I2C processing starts ere and then goes to lower level processing based on the
        packet contents.
        """
        packet_len = len(packet["data"])
        if (packet["write"] is True and
                (packet_len >= PIP1.LEN_MIN_CMD_PACKET) and
                (packet["data"][PIP1.IDX_CMD_RPT_REG_LSB] == PIP1.OUTPUT_RPT_REG_LSB) and
                (packet["data"][PIP1.IDX_CMD_RPT_REG_MSB] == PIP1.OUTPUT_RPT_REG_MSB) and 
                (packet["data"][PIP1.IDX_CMD_RPT_ID] == PIP1.CMD_OUTPUT_REPORT_ID)
                ):
            self.process_command(la_frames, packet)
        elif (packet["read"] is True and
                packet_len >= PIP1.LEN_MIN_RSP
                ):
            if packet["data"][PIP1.IDX_RSP_RPT_ID] == PIP1.CMD_INPUT_REPORT_ID:
                self.process_response(la_frames, packet)
            elif (packet_len < PIP1.LEN_MIN_ASYNC_RSP or
                  self.bytes_to_int(packet, PIP1.IDX_PIP2_CMD_REG_LSB, PIP1.IDX_PIP2_CMD_REG_MSB) == PIP1.PIP2_CMD_REG):
                return
            elif packet["data"][PIP1.IDX_RSP_RPT_ID] in PIP1.RPT_ID_DICT.keys():
                self.process_async_response(la_frames, packet)

    def valid_rsp_for_cmd(self, packet):
        """
        Validates the response contains same Command ID
        as the Command expecting a response.
        Returns:
            Bool: True when the response packet matches
            the command expecting a response
        """
        packet_len = self.bytes_to_int(packet, PIP1.IDX_RSP_LEN_LSB, PIP1.IDX_RSP_LEN_MSB)
        if (packet_len >= PIP1.LEN_MIN_RSP and
                packet["data"][PIP1.IDX_RSP_CMD_ID] & PIP1.MASK_CMD_ID == self.cmd_cmd):
            return True
        return False
    
    def process_command(self, la_frames, packet):
        """
        If expecting_cmd_response is True we there may ave been a command that did not
        receive a response. In this case output a command frame for the data we have.
        """
        if self.expecting_cmd_response is True:
            self.cmd_cmd_name = PIP1.CMD_DICT.get(self.cmd_cmd)
            self.append_frame(la_frames, "PIP1 Error", "PIP1 command with no response")
        self.expecting_cmd_response = True
        self.transaction_start_time = packet["start_time"]
        self.transaction_end_time = packet["end_time"]
        self.cmd_len = self.bytes_to_int(packet, PIP1.IDX_CMD_LEN_LSB, PIP1.IDX_CMD_LEN_MSB)

        self.cmd_cmd = packet["data"][PIP1.IDX_CMD_CMD_ID] & PIP1.MASK_CMD_ID
        self.cmd_cmd_name = PIP1.CMD_DICT.get(self.cmd_cmd)

        if self.cmd_len + PIP1.LEN_CMD_REG_HEADER > PIP1.LEN_MIN_CMD_PACKET:
            self.cmd_payload = (
                "0x " + " ".join([f"{x:02X}" for x in
                packet["data"][PIP1.IDX_CMD_PAYLOAD_START:self.cmd_len]])
            )

        # Commands with no response.
        if self.cmd_cmd == PIP1.CMD_ID_START_BOOTLOADER:
            self.expecting_cmd_response = False
            self.append_frame(la_frames, "PIP1", "")

    def process_async_response(self, la_frames, packet):
        """
        If expecting_cmd_response is True we there may ave been a command that did not
        receive a response. In this case output a command frame for the data we have.
        """
        if self.expecting_cmd_response is True:
            self.cmd_cmd_name = PIP1.CMD_DICT.get(self.cmd_cmd)
            self.append_frame(la_frames, "PIP1", "")
            self.expecting_cmd_response = False

        self.transaction_start_time = packet["start_time"]
        self.transaction_end_time = packet["end_time"]
        self.cmd_len = self.bytes_to_int(packet, PIP1.IDX_RSP_LEN_LSB, PIP1.IDX_RSP_LEN_MSB)

        self.cmd_cmd = packet["data"][PIP1.IDX_RSP_RPT_ID]
        self.cmd_cmd_name = PIP1.RPT_ID_DICT.get(self.cmd_cmd)

        if self.cmd_len + PIP1.LEN_CMD_REG_HEADER > PIP1.LEN_MIN_CMD_PACKET:
            self.rsp_payload = (
                "0x " + " ".join([f"{x:02X}" for x in
                packet["data"][PIP1.IDX_ASYNC_RPT_START:self.cmd_len]])
            )

        self.append_frame(la_frames, "PIP1", "")

    def process_response(self, la_frames, packet):
        """
        Parse the given data byte as a PIP1 response. If the given data is the end of the
        response add a Saleae logic bubble frame for the command and response.
        """
        if self.expecting_cmd_response is False:
            return

        packet_len = len(packet["data"])
        if packet_len < max(PIP1.IDX_RSP_LEN_LSB, PIP1.IDX_RSP_LEN_MSB):
            self.append_frame(
                la_frames,
                "PIP1 Error",
                "Sort Response Packet. Can't determine length."
            )
            return

        if self.valid_rsp_for_cmd(packet) is False:
            self.expecting_cmd_response = False
            self.append_frame(la_frames, "PIP1 Error", "PIP1 command with no response")
            return

        self.rsp_len = self.bytes_to_int(packet, PIP1.IDX_RSP_LEN_LSB, PIP1.IDX_RSP_LEN_MSB)

        self.cmd_tag = (packet["data"][PIP1.IDX_RSP_TAG] & PIP1.MASK_TGL) >> PIP1.BIT_SHIFT_TGL
        if self.rsp_len > PIP1.LEN_MIN_RSP:
            self.rsp_payload = (
                "0x " + \
                " ".join([f"{x:02X}" for x in
                    packet["data"][PIP1.IDX_RSP_PAYLOAD_START:packet_len]])
            )
        self.transaction_end_time = packet["end_time"]
        self.expecting_cmd_response = False
        self.append_frame(la_frames, "PIP1", "")

    def bytes_to_int(self, packet, lsb, msb) -> int:
        """
        Converts two bytes from a packet's data field into a uint.

        Args:
            packet (dict): A dictionary containing a "data" key with a list of byte values.
            lsb (int): The index of the least significant byte (LSB) in the data list.
            msb (int): The index of the most significant byte (MSB) in the data list.

        Returns:
            int: The two byte uint value.
        """
        return packet["data"][lsb] + (packet["data"][msb] << PIP1.SHIFT_MSB)