#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#

from vr_nldump.pysandesh.protocol.TProtocol import *
from struct import pack, unpack

class TBinaryProtocol(TProtocolBase):

  """Binary implementation of the Thrift protocol driver."""

  # NastyHaxx. Python 2.4+ on 32-bit machines forces hex constants to be
  # positive, converting this into a long. If we hardcode the int value
  # instead it'll stay in 32 bit-land.

  # VERSION_MASK = 0xffff0000
  VERSION_MASK = -65536

  # VERSION_1 = 0x80010000
  VERSION_1 = -2147418112

  TYPE_MASK = 0x000000ff

  def __init__(self, trans, strictRead=False, strictWrite=True):
    TProtocolBase.__init__(self, trans)
    self.strictRead = strictRead
    self.strictWrite = strictWrite

  def writeSandeshBegin(self, name):
    self.writeString(name)
    return 0

  def readContainerElementBegin(self):
    return 0

  def readContainerElementEnd(self):
    return 0

  def writeSandeshEnd(self):
    return 0

  def writeContainerElementBegin(self):
    return 0

  def writeContainerElementEnd(self):
    return 0

  def writeMessageBegin(self, name, type, seqid):
    if self.strictWrite:
      self.writeI32(TBinaryProtocol.VERSION_1 | type)
      self.writeString(name)
      self.writeI32(seqid)
    else:
      self.writeString(name)
      self.writeByte(type)
      self.writeI32(seqid)
    return 0

  def writeMessageEnd(self):
    return 0

  def writeStructBegin(self, name):
    return 0

  def writeStructEnd(self):
    return 0

  def writeFieldBegin(self, name, type, id, annotations):
    self.writeByte(type)
    self.writeI16(id)
    return 0

  def writeFieldEnd(self):
    return 0

  def writeFieldStop(self):
    self.writeByte(TType.STOP);
    return 0

  def writeMapBegin(self, ktype, vtype, size):
    self.writeByte(ktype)
    self.writeByte(vtype)
    self.writeI32(size)
    return 0

  def writeMapEnd(self):
    return 0

  def writeListBegin(self, etype, size):
    self.writeByte(etype)
    self.writeI32(size)
    return 0

  def writeListEnd(self):
    return 0

  def writeSetBegin(self, etype, size):
    self.writeByte(etype)
    self.writeI32(size)
    return 0

  def writeSetEnd(self):
    return 0

  def writeBool(self, bool):
    if bool:
      self.writeByte(1)
    else:
      self.writeByte(0)
    return 0

  def writeByte(self, byte):
    buff = pack("!B", byte)
    self.trans.write(buff)
    return 0

  def writeI16(self, i16):
    buff = pack("!h", i16)
    self.trans.write(buff)
    return 0

  def writeI32(self, i32):
    buff = pack("!i", i32)
    self.trans.write(buff)
    return 0

  def writeU32(self, i32):
    buff = pack("!I", i32)
    self.trans.write(buff)
    return 0

  def writeI64(self, i64):
    buff = pack("!q", i64)
    self.trans.write(buff)
    return 0

  def writeDouble(self, dub):
    buff = pack("!d", dub)
    self.trans.write(buff)
    return 0

  def writeString(self, str):
    self.writeI32(len(str))
    self.trans.write(str)
    return 0

  def writeXML(self, str):
    self.writeI32(len(str))
    self.trans.write(str)
    return 0

  def readSandeshBegin(self):
    length, name = self.readString()
    return length, name

  def readSandeshEnd(self):
    return 0

  def readMessageBegin(self):
    total_length = 0
    length, sz = self.readI32()
    total_length += length
    if sz < 0:
      version = sz & TBinaryProtocol.VERSION_MASK
      if version != TBinaryProtocol.VERSION_1:
        raise TProtocolException(type=TProtocolException.BAD_VERSION, message='Bad version in readMessageBegin: %d' % (sz))
      type = sz & TBinaryProtocol.TYPE_MASK
      length, name = self.readString()
      total_length += length
      length, seqid = self.readI32()
      total_length += length
    else:
      if self.strictRead:
        raise TProtocolException(type=TProtocolException.BAD_VERSION, message='No protocol version header')
      name = self.trans.readAll(sz)
      length, type = self.readByte()
      total_length += length
      length, seqid = self.readI32()
      total_length += length
    return (total_length, name, type, seqid)

  def readMessageEnd(self):
    return 0

  def readStructBegin(self):
    return 0

  def readStructEnd(self):
    return 0

  def readFieldBegin(self):
    total_length = 0
    length, type = self.readByte()
    total_length += length
    if type == TType.STOP:
      return (total_length, None, type, 0)
    length, id = self.readI16()
    total_length += length
    return (total_length, None, type, id)

  def readFieldEnd(self):
    return 0

  def readMapBegin(self):
    total_length = 0
    length, ktype = self.readByte()
    total_length += length
    length, vtype = self.readByte()
    total_length += length
    length, size = self.readI32()
    total_length += length
    return (length, ktype, vtype, size)

  def readMapEnd(self):
    return 0

  def readListBegin(self):
    total_length = 0
    length, etype = self.readByte()
    total_length += length
    length, size = self.readI32()
    total_length += length
    return (length, etype, size)

  def readListEnd(self):
    return 0

  def readSetBegin(self):
    total_length = 0
    length, etype = self.readByte()
    total_length += length
    length, size = self.readI32()
    total_length += length
    return (length, etype, size)

  def readSetEnd(self):
    return 0

  def readBool(self):
    length, byte = self.readByte()
    if byte == 0:
      return length, False
    return length, True

  def readByte(self):
    buff = self.trans.readAll(1)
    val, = unpack('!b', buff)
    return (1, val)

  def readI16(self):
    buff = self.trans.readAll(2)
    val, = unpack('!h', buff)
    return (2, val)

  def readI32(self):
    buff = self.trans.readAll(4)
    val, = unpack('!i', buff)
    return (4, val)

  def readI64(self):
    buff = self.trans.readAll(8)
    val, = unpack('!q', buff)
    return (8, val)

  def readDouble(self):
    buff = self.trans.readAll(8)
    val, = unpack('!d', buff)
    return (8, val)

  def readString(self):
    total_length = 0
    length, len = self.readI32()
    total_length += length
    str = self.trans.readAll(len)
    total_length += len
    return (total_length, str)

  def readXML(self):
    total_length = 0
    length, len = self.readI32()
    total_length += length
    str = self.trans.readAll(len)
    otal_length += len
    return (total_length, str)

class TBinaryProtocolFactory:
  def __init__(self, strictRead=False, strictWrite=True):
    self.strictRead = strictRead
    self.strictWrite = strictWrite

  def getProtocol(self, trans):
    prot = TBinaryProtocol(trans, self.strictRead, self.strictWrite)
    return prot


class TBinaryProtocolAccelerated(TBinaryProtocol):

  """C-Accelerated version of TBinaryProtocol.

  This class does not override any of TBinaryProtocol's methods,
  but the generated code recognizes it directly and will call into
  our C module to do the encoding, bypassing this object entirely.
  We inherit from TBinaryProtocol so that the normal TBinaryProtocol
  encoding can happen if the fastbinary module doesn't work for some
  reason.  (TODO(dreiss): Make this happen sanely in more cases.)

  In order to take advantage of the C module, just use
  TBinaryProtocolAccelerated instead of TBinaryProtocol.

  NOTE:  This code was contributed by an external developer.
         The internal Thrift team has reviewed and tested it,
         but we cannot guarantee that it is production-ready.
         Please feel free to report bugs and/or success stories
         to the public mailing list.
  """

  pass


class TBinaryProtocolAcceleratedFactory:
  def getProtocol(self, trans):
    return TBinaryProtocolAccelerated(trans)
