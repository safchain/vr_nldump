#
# Autogenerated by Sandesh Compiler (1.0)
#
# DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
#
#  options string: py:new_style
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

from vr_nldump.pysandesh.Thrift import TType, TMessageType, TException

from vr_nldump.pysandesh.transport import TTransport
from vr_nldump.pysandesh.protocol import TBinaryProtocol, TProtocol
try:
  from vr_nldump.pysandesh.protocol import fastbinary
except:
  fastbinary = None

import cStringIO
import uuid


class SandeshType(object):
  INVALID = 0
  SYSTEM = 1
  REQUEST = 2
  RESPONSE = 3
  TRACE = 4
  BUFFER = 5
  UVE = 6
  OBJECT = 7
  FLOW = 8
  TRACE_OBJECT = 9
  SYSLOG = 10
  ALARM = 11

  _VALUES_TO_NAMES = {
    0: "INVALID",
    1: "SYSTEM",
    2: "REQUEST",
    3: "RESPONSE",
    4: "TRACE",
    5: "BUFFER",
    6: "UVE",
    7: "OBJECT",
    8: "FLOW",
    9: "TRACE_OBJECT",
    10: "SYSLOG",
    11: "ALARM",
  }

  _NAMES_TO_VALUES = {
    "INVALID": 0,
    "SYSTEM": 1,
    "REQUEST": 2,
    "RESPONSE": 3,
    "TRACE": 4,
    "BUFFER": 5,
    "UVE": 6,
    "OBJECT": 7,
    "FLOW": 8,
    "TRACE_OBJECT": 9,
    "SYSLOG": 10,
    "ALARM": 11,
  }

class SandeshLevel(object):
  SYS_EMERG = 0
  SYS_ALERT = 1
  SYS_CRIT = 2
  SYS_ERR = 3
  SYS_WARN = 4
  SYS_NOTICE = 5
  SYS_INFO = 6
  SYS_DEBUG = 7
  UT_START = 200
  UT_EMERG = 200
  UT_ALERT = 201
  UT_CRIT = 202
  UT_ERR = 203
  UT_WARN = 204
  UT_NOTICE = 205
  UT_INFO = 206
  UT_DEBUG = 207
  UT_END = 207
  INVALID = 2147483647

  _VALUES_TO_NAMES = {
    0: "SYS_EMERG",
    1: "SYS_ALERT",
    2: "SYS_CRIT",
    3: "SYS_ERR",
    4: "SYS_WARN",
    5: "SYS_NOTICE",
    6: "SYS_INFO",
    7: "SYS_DEBUG",
    200: "UT_START",
    200: "UT_EMERG",
    201: "UT_ALERT",
    202: "UT_CRIT",
    203: "UT_ERR",
    204: "UT_WARN",
    205: "UT_NOTICE",
    206: "UT_INFO",
    207: "UT_DEBUG",
    207: "UT_END",
    2147483647: "INVALID",
  }

  _NAMES_TO_VALUES = {
    "SYS_EMERG": 0,
    "SYS_ALERT": 1,
    "SYS_CRIT": 2,
    "SYS_ERR": 3,
    "SYS_WARN": 4,
    "SYS_NOTICE": 5,
    "SYS_INFO": 6,
    "SYS_DEBUG": 7,
    "UT_START": 200,
    "UT_EMERG": 200,
    "UT_ALERT": 201,
    "UT_CRIT": 202,
    "UT_ERR": 203,
    "UT_WARN": 204,
    "UT_NOTICE": 205,
    "UT_INFO": 206,
    "UT_DEBUG": 207,
    "UT_END": 207,
    "INVALID": 2147483647,
  }


class SandeshHeader(object):
  """
  Attributes:
   - Namespace
   - Timestamp
   - Module
   - Source
   - Context
   - SequenceNum
   - VersionSig
   - Type
   - Hints
   - Level
   - Category
   - NodeType
   - InstanceId
   - IPAddress
   - Pid
  """

  thrift_spec = (
    None, # 0
    (1, TType.STRING, 'Namespace', None, 0, ), # 1
    (2, TType.I64, 'Timestamp', None, 0, ), # 2
    (3, TType.STRING, 'Module', None, 0, ), # 3
    (4, TType.STRING, 'Source', None, 0, ), # 4
    (5, TType.STRING, 'Context', None, 0, ), # 5
    (6, TType.I32, 'SequenceNum', None, 0, ), # 6
    (7, TType.I32, 'VersionSig', None, 0, ), # 7
    (8, TType.I32, 'Type', None, 0, ), # 8
    (9, TType.I32, 'Hints', None, 0, ), # 9
    (10, TType.I32, 'Level', None, 0, ), # 10
    (11, TType.STRING, 'Category', None, 0, ), # 11
    (12, TType.STRING, 'NodeType', None, 0, ), # 12
    (13, TType.STRING, 'InstanceId', None, 0, ), # 13
    (14, TType.STRING, 'IPAddress', None, 0, ), # 14
    (15, TType.I32, 'Pid', None, 0, ), # 15
  )

  def __init__(self, Namespace=None, Timestamp=None, Module=None, Source=None, Context=None, SequenceNum=None, VersionSig=None, Type=None, Hints=None, Level=None, Category=None, NodeType=None, InstanceId=None, IPAddress=None, Pid=None,):
    self.Namespace = Namespace
    self.Timestamp = Timestamp
    self.Module = Module
    self.Source = Source
    self.Context = Context
    self.SequenceNum = SequenceNum
    self.VersionSig = VersionSig
    self.Type = Type
    self.Hints = Hints
    self.Level = Level
    self.Category = Category
    self.NodeType = NodeType
    self.InstanceId = InstanceId
    self.IPAddress = IPAddress
    self.Pid = Pid

  def read(self, iprot):
    if iprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None and fastbinary is not None:
      fastbinary.decode_binary(self, iprot.trans, (self.__class__, self.thrift_spec))
      return 0
    read_cnt = 0
    length = iprot.readStructBegin()
    if length < 0: return -1
    read_cnt += length
    while True:
      (length, fname, ftype, fid) = iprot.readFieldBegin()
      if length < 0: return -1
      read_cnt += length
      if ftype == TType.STOP:
        break
      if fid == 1:
        if ftype == TType.STRING:
          (length, self.Namespace) = iprot.readString();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 2:
        if ftype == TType.I64:
          (length, self.Timestamp) = iprot.readI64();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 3:
        if ftype == TType.STRING:
          (length, self.Module) = iprot.readString();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 4:
        if ftype == TType.STRING:
          (length, self.Source) = iprot.readString();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 5:
        if ftype == TType.STRING:
          (length, self.Context) = iprot.readString();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 6:
        if ftype == TType.I32:
          (length, self.SequenceNum) = iprot.readI32();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 7:
        if ftype == TType.I32:
          (length, self.VersionSig) = iprot.readI32();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 8:
        if ftype == TType.I32:
          (length, self.Type) = iprot.readI32();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 9:
        if ftype == TType.I32:
          (length, self.Hints) = iprot.readI32();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 10:
        if ftype == TType.I32:
          (length, self.Level) = iprot.readI32();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 11:
        if ftype == TType.STRING:
          (length, self.Category) = iprot.readString();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 12:
        if ftype == TType.STRING:
          (length, self.NodeType) = iprot.readString();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 13:
        if ftype == TType.STRING:
          (length, self.InstanceId) = iprot.readString();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 14:
        if ftype == TType.STRING:
          (length, self.IPAddress) = iprot.readString();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      elif fid == 15:
        if ftype == TType.I32:
          (length, self.Pid) = iprot.readI32();
          if length < 0: return -1
          read_cnt += length
        else:
          iprot.skip(ftype)
      else:
        iprot.skip(ftype)
      length = iprot.readFieldEnd()
      if length < 0: return -1
      read_cnt += length
    length = iprot.readStructEnd()
    if length < 0: return -1
    read_cnt += length
    return read_cnt

  def write(self, oprot):
    if oprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and self.thrift_spec is not None and fastbinary is not None:
      oprot.trans.write(fastbinary.encode_binary(self, (self.__class__, self.thrift_spec)))
      return 0
    if oprot.writeStructBegin('SandeshHeader') < 0: return -1
    if self.Namespace is not None:
      annotations = {}
      if oprot.writeFieldBegin('Namespace', TType.STRING, 1, annotations) < 0: return -1
      if oprot.writeString(self.Namespace) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.Timestamp is not None:
      annotations = {}
      if oprot.writeFieldBegin('Timestamp', TType.I64, 2, annotations) < 0: return -1
      if oprot.writeI64(self.Timestamp) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.Module is not None:
      annotations = {}
      if oprot.writeFieldBegin('Module', TType.STRING, 3, annotations) < 0: return -1
      if oprot.writeString(self.Module) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.Source is not None:
      annotations = {}
      if oprot.writeFieldBegin('Source', TType.STRING, 4, annotations) < 0: return -1
      if oprot.writeString(self.Source) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.Context is not None:
      annotations = {}
      if oprot.writeFieldBegin('Context', TType.STRING, 5, annotations) < 0: return -1
      if oprot.writeString(self.Context) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.SequenceNum is not None:
      annotations = {}
      if oprot.writeFieldBegin('SequenceNum', TType.I32, 6, annotations) < 0: return -1
      if oprot.writeI32(self.SequenceNum) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.VersionSig is not None:
      annotations = {}
      if oprot.writeFieldBegin('VersionSig', TType.I32, 7, annotations) < 0: return -1
      if oprot.writeI32(self.VersionSig) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.Type is not None:
      annotations = {}
      if oprot.writeFieldBegin('Type', TType.I32, 8, annotations) < 0: return -1
      if oprot.writeI32(self.Type) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.Hints is not None:
      annotations = {}
      if oprot.writeFieldBegin('Hints', TType.I32, 9, annotations) < 0: return -1
      if oprot.writeI32(self.Hints) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.Level is not None:
      annotations = {}
      if oprot.writeFieldBegin('Level', TType.I32, 10, annotations) < 0: return -1
      if oprot.writeI32(self.Level) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.Category is not None:
      annotations = {}
      if oprot.writeFieldBegin('Category', TType.STRING, 11, annotations) < 0: return -1
      if oprot.writeString(self.Category) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.NodeType is not None:
      annotations = {}
      if oprot.writeFieldBegin('NodeType', TType.STRING, 12, annotations) < 0: return -1
      if oprot.writeString(self.NodeType) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.InstanceId is not None:
      annotations = {}
      if oprot.writeFieldBegin('InstanceId', TType.STRING, 13, annotations) < 0: return -1
      if oprot.writeString(self.InstanceId) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.IPAddress is not None:
      annotations = {}
      if oprot.writeFieldBegin('IPAddress', TType.STRING, 14, annotations) < 0: return -1
      if oprot.writeString(self.IPAddress) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if self.Pid is not None:
      annotations = {}
      if oprot.writeFieldBegin('Pid', TType.I32, 15, annotations) < 0: return -1
      if oprot.writeI32(self.Pid) < 0: return -1
      if oprot.writeFieldEnd() < 0: return -1
    if oprot.writeFieldStop() < 0: return -1
    if oprot.writeStructEnd() < 0: return -1
    return 0

  def validate(self):
    return


  def log(self):
    log_str = cStringIO.StringIO()
    if self.Namespace is not None:
      log_str.write('Namespace = ')
      log_str.write(self.Namespace)
      log_str.write('  ')
    if self.Timestamp is not None:
      log_str.write('Timestamp = ')
      log_str.write(str(self.Timestamp))
      log_str.write('  ')
    if self.Module is not None:
      log_str.write('Module = ')
      log_str.write(self.Module)
      log_str.write('  ')
    if self.Source is not None:
      log_str.write('Source = ')
      log_str.write(self.Source)
      log_str.write('  ')
    if self.Context is not None:
      log_str.write('Context = ')
      log_str.write(self.Context)
      log_str.write('  ')
    if self.SequenceNum is not None:
      log_str.write('SequenceNum = ')
      log_str.write(str(self.SequenceNum))
      log_str.write('  ')
    if self.VersionSig is not None:
      log_str.write('VersionSig = ')
      log_str.write(str(self.VersionSig))
      log_str.write('  ')
    if self.Type is not None:
      log_str.write('Type = ')
      log_str.write(str(self.Type))
      log_str.write('  ')
    if self.Hints is not None:
      log_str.write('Hints = ')
      log_str.write(str(self.Hints))
      log_str.write('  ')
    if self.Level is not None:
      log_str.write('Level = ')
      log_str.write(str(self.Level))
      log_str.write('  ')
    if self.Category is not None:
      log_str.write('Category = ')
      log_str.write(self.Category)
      log_str.write('  ')
    if self.NodeType is not None:
      log_str.write('NodeType = ')
      log_str.write(self.NodeType)
      log_str.write('  ')
    if self.InstanceId is not None:
      log_str.write('InstanceId = ')
      log_str.write(self.InstanceId)
      log_str.write('  ')
    if self.IPAddress is not None:
      log_str.write('IPAddress = ')
      log_str.write(self.IPAddress)
      log_str.write('  ')
    if self.Pid is not None:
      log_str.write('Pid = ')
      log_str.write(str(self.Pid))
      log_str.write('  ')
    return log_str.getvalue()

  def __repr__(self):
    L = ['%s=%r' % (key, value)
      for key, value in self.__dict__.iteritems()]
    return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

  def __ne__(self, other):
    return not (self == other)


_SANDESH_REQUEST_LIST = [
]


_SANDESH_UVE_LIST = [
]


_SANDESH_UVE_DATA_LIST = [
]


_SANDESH_ALARM_LIST = [
]


_SANDESH_ALARM_DATA_LIST = [
]
