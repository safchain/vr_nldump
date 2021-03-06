#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

#
# Sandesh UVE
#

import importlib
import copy
from vr_nldump.pysandesh.gen_py.sandesh.ttypes import SandeshType

class SandeshUVETypeMaps(object):

    def __init__(self, logger):
        self._logger = logger
        self._uve_global_map = {}
        self._uve_data_type_map = {}
    #end __init__

    def get_uve_global_map(self):
        return self._uve_global_map
    #end get_uve_global_map

    def get_uve_type_name(self, uve_data_type_name):
        try:
            uve_name = self._uve_data_type_map[uve_data_type_name]
        except KeyError:
            self._logger.error('UVE data "%s" not present in the '
                               'UVE Data Type map' % (uve_data_type_name))
            return None
        else:
            return uve_name
    #end get_uve_type_name

    def add_uve_data_type_mapping(self, uve_data_type_name, uve_type_name):
        try:
            uve_type = self._uve_data_type_map[uve_data_type_name]
        except KeyError:
            self._uve_data_type_map[uve_data_type_name] = uve_type_name
        else:
            self._logger.error('UVE data type "%s" to UVE "%s" already added' %
                (uve_data_type_name, uve_type_name))
            assert 0
    #end add_uve_data_type_mapping

    def register_uve_type_map(self, uve_type_key, uve_type_map):
        try:
            uve_map = self._uve_global_map[uve_type_key]
        except KeyError:
            self._uve_global_map[uve_type_key] = uve_type_map
        else:
            self._logger.error('UVE type "%s" already added' % (uve_type_key))
            assert 0
    #end register_uve_type_map

    def get_uve_type_map(self, uve_type_key):
        try:
            uve_map = self._uve_global_map[uve_type_key]
        except KeyError:
            self._logger.error('UVE type "%s" not present in the '
                               'UVE global map' % (uve_type_key))
            return None
        else:
            return uve_map
    #end get_uve_type_map

    def update_uve_type_map(self, uve_type_key, uve_type_map):
        try:
            uve_map = self._uve_global_map[uve_type_key]
        except KeyError:
            self._logger.error('UVE type "%s" not present in the '
                               'UVE global map' % (uve_type_key))
            assert 0
        else:
            self._uve_global_map[uve_type_key] = uve_type_map
    #end update_uve_type_map

    def sync_all_uve_types(self, inmap, sandesh_instance):
        for uve_type, uve_type_map in self._uve_global_map.iteritems():
            try:
                in_seqno = inmap[uve_type]
            except KeyError:
                uve_type_map.sync_uve(None, 0, '', False, sandesh_instance)
            else:
                uve_type_map.sync_uve(None, in_seqno, '', False, sandesh_instance)
    #end sync_all_uve_types

    def get_object_types(self, sandesh_type):
        object_types = set()
        for uve_type, uve_type_map in self._uve_global_map.iteritems():
            if uve_type_map.sandesh_type() is sandesh_type:
                tables = uve_type_map.get_object_types()
                if tables is not None:
                    object_types = object_types.union(tables)
        return list(object_types)
    # end get_object_types

#end class SandeshUVETypeMaps

class SandeshUVEPerTypeMap(object):

    class UVEMapEntry(object):
        def __init__(self, data, seqno):
            self.data = data
            self.seqno = seqno
            self.update_count = 0
        #end __init__

    #end class UVEMapEntry

    def __init__(self, sandesh, sandesh_type,
                 uve_type_name, uve_data_type_name, uve_module):
        self._sandesh = sandesh
        self._logger = self._sandesh.logger()
        self._sandesh_type = sandesh_type # UVE or ALARM
        self._uve_type = uve_type_name
        self._uve_data_type = uve_data_type_name
        self._uve_module = uve_module
        self._uve_map = {}
        sandesh._uve_type_maps.register_uve_type_map(uve_type_name, self)
        sandesh._uve_type_maps.add_uve_data_type_mapping(uve_data_type_name,
            uve_type_name)
    #end __init__

    def sandesh_type(self):
        return self._sandesh_type
    # end sandesh_type

    def uve_data_type(self):
        return self._uve_data_type
    #end uve_data_type

    def get_object_types(self):
        object_types = []
        for object_type, _ in self._uve_map.iteritems():
            object_types.append(object_type)
        return object_types
    # end get_object_types

    def uve_type_seqnum(self):
        seqnum = 0
        try:
            imp_module = importlib.import_module(self._uve_module)
        except ImportError:
            self._logger.error('Failed to import Module "%s"' %
                               (self._uve_module))
        else:
            seqnum = getattr(imp_module, self._uve_type).lseqnum()
        return seqnum
    #end uve_type_seqnum

    def update_uve(self, uve_sandesh):
        uve_name = uve_sandesh.data.name
        uve_table = uve_sandesh.data._table
        if uve_table is None or uve_table is '':
            self._logger.error('UVE update failed. Table None or "" for '
                               '<%s:%s>' % (self._uve_type, uve_name))
            return False
        if self._uve_map.get(uve_table) is None:
            self._uve_map[uve_table] = {}
        try:
            uve_entry = self._uve_map[uve_table][uve_name]
        except KeyError:
            self._logger.debug('Add uve <%s, %s> in the [%s:%s] map' \
                % (uve_name, uve_sandesh.seqnum(), uve_table, self._uve_type))
            self._uve_map[uve_table][uve_name] = \
                SandeshUVEPerTypeMap.UVEMapEntry( \
                    copy.deepcopy(uve_sandesh.data), uve_sandesh.seqnum())
        else:
            if uve_entry.data.deleted is True:
                if uve_sandesh.data.deleted is not True:
                    # The uve entry in the cache has been marked for deletion and
                    # a new uve entry with the same key has been created. Replace the
                    # deleted uve entry in the cache with this new entry.
                    self._logger.debug('Re-add uve <%s, %s> in the [%s:%s] map' \
                        % (uve_name, uve_sandesh.seqnum(), uve_table,
                           self._uve_type))
                    self._uve_map[uve_table][uve_name] = \
                        SandeshUVEPerTypeMap.UVEMapEntry(uve_sandesh.data, uve_sandesh.seqnum())
                else:
                    # Duplicate uve delete. Do we need to update the seqnum here?
                    self._logger.error('Duplicate uve delete <%s>' % (uve_name))
            else:
                uve_entry.data = uve_sandesh.update_uve(uve_entry.data)
                uve_entry.seqno = uve_sandesh.seqnum()
                uve_entry.update_count = uve_entry.update_count + 1
                self._uve_map[uve_table][uve_name] = uve_entry
        # Now, update the uve_global_map
        self._sandesh._uve_type_maps.update_uve_type_map(self._uve_type, self)
        return True
    #end update_uve

    def sync_uve(self, table, seqno, ctx, more, sandesh_instance):
        count = 0
        try:
            imp_module = importlib.import_module(self._uve_module)
        except ImportError:
            self._logger.error('Failed to import Module "%s"' %
                               (self._uve_module))
        else:
            for uve_table, uve_map in self._uve_map.iteritems():
                if table is not None and uve_table != table:
                    continue
                for uve_name, uve_entry in uve_map.iteritems():
                    if seqno == 0 or seqno < uve_entry.seqno:
                        try:
                            uve_type = getattr(imp_module, self._uve_type)
                        except AttributeError:
                            self._logger.error('Failed to create sandesh UVE "%s"' \
                                % (self._uve_type))
                            break
                        else:
                            sandesh_uve = uve_type(sandesh=sandesh_instance)
                            sandesh_uve.data = uve_entry.data
                            self._logger.debug('send sync_uve <%s: %s> in the '
                                '[%s:%s] map' % (uve_entry.data.name,
                                uve_entry.seqno, uve_table, self._uve_type))
                            sandesh_uve.send(True, uve_entry.seqno, ctx,
                                             more, sandesh_instance)
                            count += 1
        return count
    #end sync_uve

    def send_uve(self, table, name, ctx, more, sandesh_instance):
        try:
            imp_module = importlib.import_module(self._uve_module)
        except ImportError:
            self._logger.error('Failed to import Module "%s"' %
                               (self._uve_module))
        else:
            for uve_table, uve_map in self._uve_map.iteritems():
                if table is not None and uve_table != table:
                    continue
                uve_entry = uve_map.get(name)
                if uve_entry:
                    try:
                        uve_type = getattr(imp_module, self._uve_type)
                    except AttributeError:
                        self._logger.error('Failed to create sandesh UVE "%s"' \
                            % (self._uve_type))
                    else:
                        sandesh_uve = uve_type(sandesh_instance)
                        sandesh_uve.data = uve_entry.data
                        sandesh_uve.send(True, uve_entry.seqno, ctx, more,
                            sandesh_instance)
                    return True
        return False
    #end send_uve

#end class SandeshUVEPerTypeMap
