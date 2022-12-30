# Parade Technologies TrueTouch Protocols
High-Level Analyzer (HLA) extension for Saleae Logic2 software.
This analyzer supports the Parade Technologies Packet Interface Protocol
version 1, 2, and 3 (PIP1, PIP2, and PIP3), as well as the HID-I2C protocol.
As shown in the screen shot below add this analyzer once for each protocol you
want to decode. In the screen shot the default analyzer name,
"Parade Technologies", has been edited to define the selected protocol.

![screenshot][Overview of the HLA GUI]

## Configuration
1. Input Analyzer: I2C
2. Protocol: Either PIP1, PIP2, PIP3, or HID-I2C.
3. Save
4. Edit the analyzer name to include the protocol. This can be done by double
    clicking on the analyzer name.
5. To decode more than one protocol, add the analyzer multiple times.

## Tips
- In the Logic2 Data Table view, right click on the column headings to enable
    or disable columns.

## Column Meanings
The data table column order can not be controled by the HLA. When it makes
sense a column heading is reused across protocols to limit the total number
of data table columns. We hope the column names are self explanitory. Below
are a few notes on the less obvious names.
* "R " prefix: response or report packet.
* "C " prefix: command packet.
* "ZMsg": A string message from the HLA to the user. This message is not
decoded from the input I2C data stream.

## Issue Reporting
If you encounter an issue with this HLA please send a Saleae capture and 
description of the issue to support@paradetech.com. Please add timing markers
to your saved capture to indicate the error and any relevant preconditions.


[Overview of the HLA GUI]: ./screenshots/overview.png