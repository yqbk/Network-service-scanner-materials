import pcap
import sys

    # Twisted Imports
from twisted.internet import abstract, protocol

    # Sibling Imports
import pcapprotocol

class PcapIO(abstract.FileDescriptor):
    def __init__(self, protocol, dev):
        abstract.FileDescriptor.__init__(self)
        p = pcap.pcapObject()
        p.open_live(dev, 1600, 0, 100)
        p.setnonblock(1)

        self.fn = p.fileno()
        self.pcap = p
        self.protocol = protocol
        self.protocol.makeConnection(self)
        self.startReading()

    def fileno(self):
        return self.fn

    def doRead(self):
        try:
            output = self.pcap.next()
        except IOError, ioe:
            if ioe.args[0] == errno.EAGAIN:
                return
            else:
                return CONNECTION_LOST
        if not output:
            return CONNECTION_LOST
        self.protocol.dataReceived(output)

    def connectionLost(self, reason):
        self.protocol.connectionLost()
