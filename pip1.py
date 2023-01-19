"""
Parade Technologies Packet Interface Protocol v1 processor. For use with the
Parade Technologies Touch Protocols High Level Analyzer for the Saleae Logic2
software.
"""

from saleae.analyzers import AnalyzerFrame #pylint: disable=import-error

from pt_protocol import PtProtocol
class PIP1 (PtProtocol):
    """
    Parade Technologies Packet Interface Protocol Version 1
    I2C packet parser.
    """

    def __init__(self):
        PtProtocol.__init__(self)
        print("TODO: PIP v1 not implemented yet.")
