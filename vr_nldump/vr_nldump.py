# Copyright 2015 Sylvain Afchain <safchain@gmail.com>
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import socket
import datetime

import pcapy
from pyroute2.netlink.generic import GenericNetlinkSocket
from pyroute2.netlink import genlmsg
from pyroute2.netlink import NLMSG_DONE
from pyroute2.netlink import NLM_F_MULTI
from pyroute2.netlink.nlsocket import Marshal

from gen_py.vr import ttypes
from pysandesh.Thrift import TType
from pysandesh.transport import TTransport
from pysandesh.protocol import TBinaryProtocol


class NLVRouterMessage(genlmsg):

    nla_map = (('NL_ATTR_UNSPEC', 'none'),
               ('NL_ATTR_VR_MESSAGE_PROTOCOL', 'cdata'))


class VRouterNetLink(GenericNetlinkSocket):
    pass


class VrouterNetlinkSniffer(object):

    def __init__(self, interface):

        self._interface = interface
        self._vrl = VRouterNetLink()
        self._pcap = pcapy.open_live(interface, 65535, 1, 10)
        self._msgs = {}

    def get_sandesh_class(self, raw):
        transport = TTransport.TMemoryBuffer(raw)
        protocol_factory = TBinaryProtocol.TBinaryProtocolFactory()
        protocol = protocol_factory.getProtocol(transport)
        (length, sandesh_name) = protocol.readSandeshBegin()
        if not sandesh_name:
            return

        try:
            return eval('ttypes.' + sandesh_name)
        except:
            return

    def dump(self, msg, obj):
        header = msg['header']
        nlink = '%s, pid = %d  seq = %d  type = %d' % (
            datetime.datetime.now().strftime('%H:%M:%S.%f'),
            header['pid'],
            header['sequence_number'],
            header['type'])
        print nlink
        print obj.log()

    def parse(self, msg_seq):
        for msg in self._msgs[msg_seq]:
            raw = msg.get_attr('NL_ATTR_VR_MESSAGE_PROTOCOL')            
            while raw:
                sandesh_class = self.get_sandesh_class(raw)
                if not sandesh_class:
                    break

                try:
                    obj = sandesh_class()
                except:
                    continue

                # XXX(safchain): why ?, seems to be not correctly implemented
                raw += '\0' * 4

                transport = TTransport.TMemoryBuffer(raw)
                protocol_factory = TBinaryProtocol.TBinaryProtocolFactory()
                protocol = protocol_factory.getProtocol(transport)
                length = obj.read(protocol)

                self.dump(msg, obj)

                raw = raw[length:]

        self._msgs[msg_seq] = []

    def packet_handler(self, header, data):
        data = data[16:]
        msgs = self._vrl.marshal.parse(data)
        for msg in msgs:
            msg_seq = msg['header']['sequence_number']

            if msg_seq not in self._msgs:
                self._msgs[msg_seq] = []

            if (msg['header']['type'] == NLMSG_DONE or
                not msg['header']['flags'] & NLM_F_MULTI):
                self._msgs[msg_seq].append(msg)
                self.parse(msg_seq)
            elif isinstance(msg, NLVRouterMessage):
                self._msgs[msg_seq].append(msg)
        print ""

    def start(self):
        print "Listening on %s" % self._interface
        self._vrl.bind('vrouter', NLVRouterMessage)
        self._pcap.loop(-1, self.packet_handler)


def main():
    parser = argparse.ArgumentParser(
        description='Dump sandesh netlink message.')
    parser.add_argument('-i', '--interface', help='Interface to capture.',
                        required=True)
    args = parser.parse_args()

    vr = VrouterNetlinkSniffer(args.interface)
    vr.start()


if __name__ == '__main__':
    main()
