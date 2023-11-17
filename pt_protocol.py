"""
Parade Technologies base class for Saleae Logic2 High Level Analyzers.
"""
from typing import List
from saleae.analyzers import AnalyzerFrame #pylint: disable=import-error

class PtProtocol:
    """
    Parade Technologies base class for Saleae Logic2 High Level Analyzers.
    This base class should be used for all Parade specific protocols. It
    May also be used for non Parade specific protocols, such as HID. By
    it self this base class is not a useful Saleae HLA.
    """
    VERBOSE_NONE = 0
    VERBOSE_FATAL = 1
    VERBOSE_ERROR = 2
    VERBOSE_WARN = 3
    VERBOSE_INFO = 4
    VERBOSE_DEBUG = 5
    VERBOSE_TRACE = 6
    def __init__(self):
        """
        Initialize base class.
        """
        # Keep track of the start and end time of transaction for use by
        # other methods in this class.
        self.transaction_start_time = None
        self.transaction_end_time = None
        # Verbose Levels are
        # 0: No Messages
        # 1: Fatal
        # 2: Error
        # 3: Warning
        # 4: Info
        # 5: Debug
        # 6: Trace
        self.verbose_level = PtProtocol.VERBOSE_INFO

        self.cmd_len = None
        self.cmd_seq = None
        self.cmd_tag = None
        self.cmd_cmd = None
        self.cmd_cmd_name = ""
        self.cmd_crc = None
        self.cmd_payload = None
        self.rsp_len = None
        self.rsp_mdata = None
        self.rsp_tag = None
        self.rsp_seq = None
        self.rsp_rsp = None
        self.rsp_cmd_id = None
        self.rsp_payload = None
        self.rsp_status = None
        self.rsp_crc = None


    def append_frame(self, hla_frames: List[AnalyzerFrame], frame_type: str, message: str):
        """
        Appends a Saleae HLA frame to the hla_frames object. The columns are defined by the
        keys put into the data dictionary. To avoid many sparsely populated columns this
        class controls the list of possible keys. All key values are set to None at the end
        of this method. If a key's value is none at the start of this method and that key
        is not added to the dictionary. This ensures that only the columns that are used
        show up in the Saleae Logic2 GUI.
        """
        data = {}
        if self.cmd_tag is not None:
            data["Tag"] = f"{self.cmd_tag:d}"
        elif self.rsp_tag is not None:
            data["Tag"] = f"{self.rsp_tag:d}"
        if self.cmd_seq is not None:
            data["Seq"] = f"{self.cmd_seq:d}"
        elif self.rsp_seq is not None:
            data["Seq"] = f"{self.rsp_seq:d}"
        if self.cmd_cmd is not None:
            data["Cmd"] = f"0x{self.cmd_cmd:02X}"
        if self.cmd_cmd_name is not None:
            data["Cmd_Name"] = self.cmd_cmd_name
        else:
            data["Cmd_Name"] = "Unknown Command"
        if self.cmd_len is not None:
            data["C Len"] = f"{self.cmd_len:d}"
        if self.cmd_payload is not None :
            data["C Payload"] = f"{self.cmd_payload}"
        if self.cmd_crc is not None:
            data["C CRC"] = f"0x{self.cmd_crc:04X}"
        if self.rsp_len is not None:
            data["R Len"] = f"{self.rsp_len:d}"
        if self.rsp_payload is not None:
            data["R Payload"] = f"{self.rsp_payload}"
        if self.rsp_crc is not None:
            data["R CRC"] = f"0x{self.rsp_crc:04X}"
        if self.rsp_status is not None:
            data["Status"] = f"0x{self.rsp_status:02X}"
        if message is not None:
            data["ZMsg"] = message
        hla_frames.append(AnalyzerFrame(
            frame_type,
            self.transaction_start_time,
            self.transaction_end_time,
            data
        ))
        self.cmd_tag = None
        self.cmd_seq = None
        self.cmd_cmd = None
        self.cmd_cmd_name = None
        self.cmd_len = None
        self.cmd_payload = None
        self.cmd_crc = None
        self.rsp_len = None
        self.rsp_payload = None
        self.rsp_crc = None
        self.transaction_start_time = None
        self.transaction_end_time = None

    def set_verbose_level(self, level):
        """
        Set the verbose level between 0 (None) and 6 (Trace)
        None, Fatal, Warning, Info, Debug, Trace. Default
        value is Info.
        """
        if level.isnumeric():
            if level < PtProtocol.VERBOSE_NONE:
                self.verbose_level = PtProtocol.VERBOSE_NONE
            elif level > PtProtocol.VERBOSE_TRACE:
                self.verbose_level = PtProtocol.VERBOSE_TRACE
            else:
                self.verbose_level = level
        elif level == "None":
            self.verbose_level = PtProtocol.VERBOSE_NONE
        elif level == "Fatal":
            self.verbose_level = PtProtocol.VERBOSE_FATAL
        elif level == "Warning":
            self.verbose_level = PtProtocol.VERBOSE_WARN
        elif level == "Info":
            self.verbose_level = PtProtocol.VERBOSE_INFO
        elif level == "Debug":
            self.verbose_level = PtProtocol.VERBOSE_DEBUG
        elif level == "Trace":
            self.verbose_level = PtProtocol.VERBOSE_TRACE
        else:
            self.verbose_level = PtProtocol.VERBOSE_INFO

    def process_i2c_packet(self, hla_frames, packet):
        """
        Protocols must implement this method. This is the method that
        PtTouchHLA will call when a packet of data is ready to be
        processed.
        """
        self.transaction_start_time = packet["start_time"]
        self.fatal(f"{self.__class__.__name__} not supported yet.")

    def debug(self, message):
        """
        Debug method that only outputs when debug is enabled in the user preferences.
        """
        if self.verbose_level >= PtProtocol.VERBOSE_DEBUG:
            self.output("Debug", message)

    def fatal(self, message):
        """
        Fatal method that only outputs when debug is enabled in the user preferences.
        """
        if self.verbose_level >= PtProtocol.VERBOSE_FATAL:
            self.output("Fatal", message)

    def info(self, message):
        """
        Info method that only outputs when debug is enabled in the user preferences.
        """
        if self.verbose_level >= PtProtocol.VERBOSE_FATAL:
            self.output("Info ", message)

    def output(self, prefix, message):
        """
        Outputs the given message with the format "time: prefix: message"
        """
        print(f"{self.transaction_start_time}: {prefix}: {message}")
