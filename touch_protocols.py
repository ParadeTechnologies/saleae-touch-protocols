"""
High Level Analyzer
For more information and documentation, please go to
https://support.saleae.com/extensions/high-level-analyzer-extensions
"""

from saleae.analyzers import HighLevelAnalyzer #pylint: disable=import-error
from saleae.analyzers import AnalyzerFrame     #pylint: disable=import-error
from saleae.analyzers import ChoicesSetting    #pylint: disable=import-error

from hid1 import HID1
from pip1 import PIP1
from pip2 import PIP2
from pip3 import PIP3

class PtTouchHLA(HighLevelAnalyzer):
    """
    Parade Technologies subclass of the Saleae HighLevelAnalyser class.
    """
    selected_protocol = ChoicesSetting(
        ["HID-I2C", "PIP1", "PIP2", "PIP3"], label="Protocol"
    )
    selected_debug_level = ChoicesSetting(
        ["Fatal", "None", "Warning", "Info", "Debug", "Trace"], label="Terminal Verbose Level"
    )

    enable_hid_pip3_reports = ChoicesSetting(
        ["No", "Yes"], label="Include PIP3 Reports in HID Analyzer"
    )

    SUPPORTED_PROTOCOLS = {
        "PIP1": PIP1,
        "PIP2": PIP2,
        "PIP3": PIP3,
        "HID-I2C": HID1,
    }
    # The list of result_types provides a way to customize the frames (colored blocks)
    # that are shown in the Logic 2 timeline view.
    # TODO: How to move these definitions into the relevant class, e.g. pip3.py.
    result_types = {
        "HID1": {
            "format": "{{data.Cmd_Name}}"
        },
        "HID1 Error": {
            "format": "ERROR: {{data.Cmd_Name}}"
        },
        "sentinel": {
            "format": "FW Reset Sentinel"
        },
        "PIP3": {
            "format": "{{data.Cmd_Name}} {{data.Status}}"
        },
        "PIP3 Error": {
            "format": "ERROR: {{data.Cmd_Name}} {{data.Status}}"
        },
        "PIP2": {
            "format": "{{data.Cmd_Name}}"
        },
        "PIP2 Error": {
            "format": "ERROR: {{data.Cmd_Name}}"
        },
        "PIP1": {
            "format": "{{data.Cmd_Name}}: {{data.Status}}"
        }
    }

    def __init__(self):
        """
        Initialize HLA.
        """
        # I2C packet variables. A packet is from the start bit to stop bit.
        self.packet = {
            "start_time": None,
            "end_time:": None,
            "data": None,
            "read": False,
            "write": False,
        }

        try:
            self.protocol = PtTouchHLA.SUPPORTED_PROTOCOLS[self.selected_protocol] ()
        except KeyError:
            print(f"ERROR: Unknown Protocol Setting {self.selected_protocol}")
        self.protocol.set_verbose_level(self.selected_debug_level)
        if self.selected_protocol == "HID-I2C":
            print(self.enable_hid_pip3_reports)
            if self.enable_hid_pip3_reports == "No":
                self.protocol.enable_hid_pip3_reports = False
                print("false")
            else:
                self.protocol.enable_hid_pip3_reports = True
                print("true")

    def decode(self, frame: AnalyzerFrame):
        """
        Process a frame from the input analyzer, and optionally return a single
        `AnalyzerFrame` or a list of `AnalyzerFrame`s.
        """
        frames = []
        self.packet["end_time"] = frame.end_time
        # The I2C start bit is used to reset variables used to parse the I2C packet.
        if frame.type == "start":
            self.packet["start_time"] = frame.start_time
            self.packet["data"] = []

        # Store the I2C address and the transaction type (read or write).
        elif frame.type == "address":
            if frame.data["read"] is True:
                self.packet["read"] = True
                self.packet["write"] = False
            else:
                self.packet["read"] = False
                self.packet["write"] = True
        # The I2C stop bit indicates the end of an I2C packet.
        elif frame.type == "stop":
            if (self.packet["start_time"] is not None) and (self.packet["end_time"] is not None):
                self.protocol.process_i2c_packet(frames, self.packet)
            else:
                print("Got stop bit with either start_time or end_time not set.")
            # When the I2C stop bit is seen always reset packet values.
            self.packet["start_time"] = None
            self.packet["end_time"] = None
        # Accumulate the data bytes in the I2C packet for later processing.
        elif frame.type == "data":
            self.packet["data"].append(frame.data["data"][0])
        else:
            print(f"Unsupported frame.type: {frame.type}")
        return frames
