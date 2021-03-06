import random

from lighthouse import *
from lighthouse_ontology import Attributes


class XGen:
    rows = 0
    connected_comp = 1
    data = []
    temp = []
    linked_nodes = []

    def __init__(self, rows, linked_nodes, connected_comp=1):
        self.connected_comp = connected_comp
        self.rows = rows
        self.linked_nodes = linked_nodes

    def add_nodes(self, s, e):
        for i in range(1, self.r(2, 4)):
            self.data.append([s, e, self.attr(), self.attr(), self.attr()])

    def append_to_temp(self, val):
        if val not in self.temp:
            self.temp.append(val)

    def attr(self):
        return 'A-' + str(random.randint(1, self.rows))

    def r(self, s=1, e=10):
        return random.randint(s, e)


class GPlainGen(XGen):
    __count = 0

    def gen(self, offset):
        for i in range(self.rows):
            self.add_nodes(i + offset * self.rows, i + 1 + offset * self.rows)

    def run(self):
        self.__count = self.__count + 1
        self.add_nodes(0, 1)
        self.add_nodes(0, 2)
        self.add_nodes(0, 3)
        self.add_nodes(0, 4)
        self.add_nodes(0, 5)
        self.add_nodes(0, 6)
        self.add_nodes(0, 7)
        self.add_nodes(0, 8)
        self.add_nodes(0, 9)
        self.add_nodes(1, 2)
        self.add_nodes(1, 3)
        self.add_nodes(1, 4)
        self.add_nodes(1, 5)
        self.add_nodes(1, 6)
        self.add_nodes(1, 7)
        self.add_nodes(1, 8)
        self.add_nodes(1, 9)
        self.add_nodes(2, 3)
        self.add_nodes(2, 4)
        self.add_nodes(2, 5)
        self.add_nodes(2, 6)
        self.add_nodes(2, 7)
        self.add_nodes(2, 8)
        self.add_nodes(2, 9)
        self.add_nodes(3, 4)
        self.add_nodes(3, 5)
        self.add_nodes(3, 6)
        self.add_nodes(3, 7)
        self.add_nodes(3, 8)
        self.add_nodes(3, 9)
        self.add_nodes(4, 5)
        self.add_nodes(4, 6)
        self.add_nodes(4, 7)
        self.add_nodes(4, 8)
        self.add_nodes(4, 9)
        self.add_nodes(5, 6)
        self.add_nodes(5, 7)
        self.add_nodes(5, 8)
        self.add_nodes(5, 9)
        self.add_nodes(6, 7)
        self.add_nodes(6, 8)
        self.add_nodes(6, 9)
        self.add_nodes(7, 8)
        self.add_nodes(7, 9)
        self.add_nodes(8, 9)
        return self.data


# tree simple chain
class GSimpleChainGen(XGen):
    __count = 0

    def gen(self, offset):
        for i in range(self.rows):
            self.add_nodes(i + offset * self.rows, i + 1 + offset * self.rows)

    def run(self):
        self.__count = self.__count + 1
        for cc in range(0, self.connected_comp):
            self.gen(cc)
        return self.data


# tree type graph
class GTreeGen(XGen):
    __count = 0

    def gen(self, offset):
        for i in range(self.rows):
            parent = self.r(0 + offset * i, (self.__count - 1) + offset * i)
            self.add_nodes(parent, self.__count)
            self.append_to_temp(parent)
            self.append_to_temp(self.__count)
            self.__count = self.__count + 1
        self.add_linked_nodes()

    def add_linked_nodes(self):
        for child in self.linked_nodes:
            if child not in self.temp:
                self.data.append([0, child, self.attr(), self.attr(), self.attr()])
                self.temp.append(child)

    def run(self):
        self.__count = self.__count + 1
        for cc in range(0, self.connected_comp):
            self.gen(cc)
        return self.data


# trivial type graph
class GTrivialGen(XGen):

    def gen(self, parent, offset):
        self.append_to_temp(parent)
        for child in random.sample(range(1 + offset * self.rows, self.rows + offset * self.rows), self.rows - 1):
            self.add_nodes(parent, child)
            self.append_to_temp(child)
        self.add_linked_nodes(parent)

    def add_linked_nodes(self, parent):
        for child in self.linked_nodes:
            if child not in self.temp:
                self.data.append([parent, child, self.attr(), self.attr(), self.attr()])
                self.temp.append(child)

    def run(self):
        for cc in range(0, self.connected_comp):
            self.gen(cc + cc * self.rows, cc)
        return self.data


# random 1 graph
class GRandomGen(XGen):

    def grs(self):
        for i in range(1, self.rows):
            n1 = random.randint(0, self.rows)
            n2 = random.randint(0, self.rows)
            # self.data.append(
            #     [n1, n2, self.attr(), self.attr(),
            #      self.attr()])
            self.add_nodes(n1, n2)
            self.append_to_temp(n1)
            self.append_to_temp(n2)

        self.add_linked_nodes()

    def add_linked_nodes(self):
        for i in self.linked_nodes:
            if i not in self.temp:
                for j in self.temp:
                    self.data.append([i, j, self.attr(), self.attr(), self.attr()])
                self.temp.append(i)

    def run(self):
        self.grs()
        return self.data


# full graph
class GFullGen(XGen):
    def gen(self, offset):
        parent = offset * (self.rows + 1)
        while parent < self.rows + offset * self.rows:
            child = parent + 1
            self.append_to_temp(parent)
            while child <= self.rows + offset * self.rows:
                self.add_nodes(parent, child)
                self.append_to_temp(child)
                child = child + 1
            parent = parent + 1
        self.add_linked_nodes()

    def add_linked_nodes(self):
        for parent in self.linked_nodes:
            if parent not in self.temp:
                for child in self.temp:
                    self.data.append([parent, child, self.attr(), self.attr(), self.attr()])
                self.temp.append(parent)

    def run(self):
        for cc in range(0, self.connected_comp):
            self.gen(cc)
        return self.data


# xgraph
class GSegGen:
    __sgm_count = 0
    __nodes_count = 0
    __linked_nodes = []
    __sgm = []
    __graph = []
    __temp = []
    __connected_comp = 1

    def __init__(self, sgm_count, nodes_count, linked_nodes, connected_comp=1):
        self.__sgm_count = sgm_count
        self.__nodes_count = nodes_count
        self.__linked_nodes = linked_nodes
        self.connected_comp = connected_comp

    def __r(self, s=1, e=10):
        return random.randint(s, e)

    def __sgm_gen(self, next_node):
        for i in range(self.__sgm_count):
            self.__sgm.append(list(
                range(i * self.__nodes_count + next_node, self.__nodes_count + i * self.__nodes_count + next_node)))
        self.__add_linked_nodes()
        return len(self.__sgm) * self.__nodes_count + next_node

    def __add_linked_nodes(self):
        n = 0
        for i in self.__linked_nodes:
            if i not in self.__sgm[n]:
                self.__sgm[n].append(i)
            n = n + 1
            if n >= len(self.__sgm):
                n = 0

    def __attr(self):
        return 'A-' + str(random.randint(1, self.__nodes_count))

    def __get_map(self, sgm):
        arr = random.sample(sgm, random.randint(1, len(sgm) - 1))
        return arr

    def __build_links(self, src_sgm, dst_sgm):
        for s in src_sgm:
            for n in self.__get_map(dst_sgm):
                if [s, n] not in self.__temp and [n, s] not in self.__temp:
                    for i in range(1, self.__r(1, 3)):
                        self.__graph.append([s, n, self.__attr(), self.__attr(), self.__attr()])

                    self.__temp.append([s, n])

    def run(self):
        next_node = 0
        for cc in range(0, self.connected_comp):
            self.__sgm.clear()
            next_node = self.__sgm_gen(next_node)
            for s in self.__sgm:
                for d in self.__sgm:
                    if s != d:
                        self.__build_links(s, d)

        return self.__graph


class GHierarchy(XGen):
    node_index = 1

    level_len = 8
    levels = []

    def gen(self, s, e):
        n = []
        for x in range(1, self.r(s, e)):
            n.append(self.node_index)
            self.node_index = self.node_index + 1
        return n

    def add_linked_nodes(self, parent, children):
        for child in children:
            self.add_nodes(parent, child)

    def run(self):
        for cc in range(0, self.connected_comp):

            self.levels.clear()

            self.levels.append([self.node_index, [self.node_index]])
            for i in range(1, self.level_len):
                self.levels.append([i, self.gen(3, 10)])

            for i in range(self.level_len - 1):
                for n in self.levels[i][1]:
                    self.add_linked_nodes(n,
                                          random.sample(self.levels[i + 1][1], self.r(1, len(self.levels[i + 1][1]))))

            self.node_index = self.node_index + 1

        return self.data


class GenHeader(metaclass=Header):
    display_name = 'Gen table'

    Field1 = Field('Field1', ValueType.Integer)
    Field2 = Field('Field2', ValueType.Integer)
    Attr1 = Field('Attr1', ValueType.String)
    Attr2 = Field('Attr2', ValueType.String)
    Attr3 = Field('Attr3', ValueType.String)
    Markup = Field('Markup', ValueType.String)


class FieldType(metaclass=Object):
    name = 'Field type'
    FieldX = Attribute('FieldX', ValueType.Integer)
    Attr1 = Attribute('Attr1', ValueType.String)
    Attr2 = Attribute('Attr2', ValueType.String)
    Attr3 = Attribute('Attr3', ValueType.String)
    Markup = Attribute('Markup', ValueType.String)
    IdentAttrs = [FieldX]
    CaptionAttrs = [FieldX]


class Field1TypeToField2Type(metaclass=Link):
    name = 'Gen Link'

    Attr1 = Attribute('Attr1', ValueType.String)

    Begin = FieldType
    End = FieldType


class GenSchema(metaclass=Schema):
    name = 'Gen!'
    Header = GenHeader

    # f1type = SchemaObject(FieldType, mapping={FieldType.FieldX: Header.Field1})
    # f2type = SchemaObject(FieldType, mapping={FieldType.FieldX: Header.Field2})

    f1type = SchemaObject(FieldType, mapping={FieldType.FieldX: Header.Field1, FieldType.Markup: Header.Markup})
    f2type = SchemaObject(FieldType, mapping={FieldType.FieldX: Header.Field2, FieldType.Markup: Header.Markup})

    connection = SchemaLink(Field1TypeToField2Type, mapping={Field1TypeToField2Type.Attr1: Header.Attr1},
                            begin=f1type, end=f2type)


class GenTask(Task):

    def get_id(self):
        return 'b795762d-6a93-4bc6-8a42-6440d400107e'

    def get_category(self):
        return 'Gen tasks'

    def get_display_name(self):
        return 'Gen task'

    def get_headers(self):
        return HeaderCollection(GenHeader)

    def get_graph_macros(self):
        return MacroCollection(
            Macro(name='Gen lookup', mapping_flags=[GraphMappingFlags.Completely], schemas=[GenSchema])
        )

    def get_enter_params(self):
        return EnterParamCollection(
            EnterParamField('rows', 'Rows', ValueType.Integer, is_array=False, required=True, default_value=10,
                            category='Required', description='Rows count'),
            EnterParamField('connected_component', 'Connected component', ValueType.Integer, is_array=False,
                            required=True, default_value=1,
                            category='Required', description='Rows count'),
            EnterParamField('segments', 'Segments', ValueType.Integer, is_array=False, required=True, default_value=2,
                            category='Required', description='Segments count'),
            EnterParamField('nodes', 'Nodes', ValueType.Integer, is_array=False, required=True, default_value=3,
                            category='Required', description='Nodes count'),
            EnterParamField('graphType', 'GraphType', ValueType.String,
                            predefined_values=['Plain', 'Trivial', 'SimpleChain', 'Tree', 'Random', 'Full', 'XGraph',
                                               'Hierarchy'],
                            category='Required',
                            description='Graph types', default_value='Trivial'),
            EnterParamField('fieldx', 'FieldX', ValueType.String, is_array=True,
                            value_sources=[ValueSource(FieldType.FieldX)])
        )

    def get_schemas(self):
        return GenSchema

    def __fill_result(self, result_writer, data):
        for i in data:
            result_writer.write_line({
                GenHeader.Field1: i[0],
                GenHeader.Field2: i[1],
                GenHeader.Attr1: i[2],
                GenHeader.Attr2: i[3],
                GenHeader.Attr3: i[4],
                GenHeader.Markup: self.__get_content(random.randint(0, 2))
            })

    def __get_content(self, selector):
        if selector == 0:
            return """
            <style>
            #customers {
              font-family: Arial, Helvetica, sans-serif;
              border-collapse: collapse;
              width: 100%;
            }

            #customers td, #customers th {
              border: 1px solid #ddd;
              padding: 8px;
            }

            #customers th {
              padding-top: 12px;
              padding-bottom: 12px;
              text-align: left;
              background-color: #4CAF50;
              color: white;
            }
            </style>
            <table id="customers">
               <tr>
                 <th> Company </th>
                 <th> <img width="68" height="68" src="data: image/jpeg; base64,/ 9j / 4AAQSkZJRgABAQEAYABgAAD / 4RCaRXhpZgAATU0AKgAAAAgABAE7AAIAAAANAAAISodpAAQAAAABAAAIWJydAAEAAAAaAAAQeOocAAcAAAgMAAAAPgAAAAAc6gAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHZpdGFseSBwb3BvdgAAAAHqHAAHAAAIDAAACGoAAAAAHOoAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHYAaQB0AGEAbAB5ACAAcABvAHAAbwB2AAAA / +EKZWh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8APD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4NCjx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iPjxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI + PHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9InV1aWQ6ZmFmNWJkZDUtYmEzZC0xMWRhLWFkMzEtZDMzZDc1MTgyZjFiIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iLz48cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0idXVpZDpmYWY1YmRkNS1iYTNkLTExZGEtYWQzMS1kMzNkNzUxODJmMWIiIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyI + PGRjOmNyZWF0b3I + PHJkZjpTZXEgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj48cmRmOmxpPnZpdGFseSBwb3BvdjwvcmRmOmxpPjwvcmRmOlNlcT4NCgkJCTwvZGM6Y3JlYXRvcj48L3JkZjpEZXNjcmlwdGlvbj48L3JkZjpSREY + PC94OnhtcG1ldGE + DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDw / eHBhY2tldCBlbmQ9J3cnPz7 / 2wBDAAcFBQYFBAcGBQYIBwcIChELCgkJChUPEAwRGBUaGRgVGBcbHichGx0lHRcYIi4iJSgpKywrGiAvMy8qMicqKyr / 2wBDAQcICAoJChQLCxQqHBgcKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKir / wAARCABEAEQDASIAAhEBAxEB / 8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL / 8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4 + Tl5ufo6erx8vP09fb3 + Pn6 / 8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL / 8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3 + Pn6 / 9oADAMBAAIRAxEAPwD6IooooAK5fxL8QfDvhJhHrWopHOeRBGC8hHrtHOPeuG + Knxeu / C2rnRNAija7VA088wyse7oAO5xz + IrwTU5r641CS51Z5ZLi5 / eu8vVgeQfpTSLUG9T6i0f4weDtaultrfU / IlY4Auo2iBPpkjFdtHIJEDIwZSMgg5yPWvh5HaNv3ZOR2xn8wa95 + CPxAbUJm8Oapjzkj8y1kU8Mo6rjsR7cU3G2wSj2PbKKKKkgsL90fSihfuj6UUAV6KKQ0AfM3xE8PNqnx1vbGaQxLfbJg2M / IIgDj / vg1v3Oh2msJFp + o6FJHawKIoLrzBvUAYHTkCr3xRWXSfGWn6zcxExLdoom29IyuCue3JP51rLDFFI0pbBYfMxPBrzcVVlzKx9DgqMOTXU4oeB9O0stFHpE2rRyHczSSBTF9DwT9K6X4Y6FpunfErVRa2SxBLKKSHIOYix + YVcSKG4dnY + YUY7SG4FUvAxudS + KupXdoW + zW6pBK4 + 62ByM / jRhqs5T1DGUacaWmh7QOlFAor0j54sL90fSihfuj6UUAV6KKKAMnX9Fttd0qSzu4Y5lLB1DjIDKcqfzArzfVPD1hqNwE1m1eYxfL5ZkZQPwBFeuk1534seefxA / 2R1VI0Cn3bvXFilZKadmj1culzSdJq6Zh2HhjSbG + WTRrGS2kb5dqzuwb2IJwa9G8OaDa + H9OMNrCsbTSGWbHdz1Ncx4U8yHWla7lDhlKj0zXoNLC3lecndhmD5GqMVZLUWiiiu48osL90fSihfuj6UUAVHZVUs + FVeST0 + teS + LvijcTzzWXht / IhQ7WugMu / 8AuZ4A9 + p9utdJ8VNZfTfCn2W3bEt +/ lN / 1zx835jj8a8SB9eaaR0UoJ6s6bTtRvzciWS7kMrDBYuct35rbj1c4 / exZPcq3WuT065AILdU4P0rSN4n / LNa8nHRftEz6 / KYQqUWmtmbcmrsP9XHt / 2m7VhalqWo / ajNbXciyoBhlkI / Ig003b1n31z5YwfvPRgYvnbFmtOFOikluzt / CHxQuFuYrDxIyyxOdqXfQoe28dCPf869bVgyhlIIIyCO9fLNe5fDDV21Lwosc775bNzCWPUrjI / Q16zPkasEtUd6v3R9KKF + 4PpRSOc8i + M5IbRh2xOf1jryrzSOOOKKKpHbS + Elt52SdCuBuODWzuNFFedjd0fVZHtP5Bu + lYs0zPcHdg4NFFPB9Qzz7HzIjK2egr1j4MuTBqq9vMQ / pRRXoPY + Vq / Az1tfuj6UUUVJxH//2Q=="> Contact </th>
                 <th> Country </th>
               </tr>
               <tr>
                 <td> Alfreds Futterkiste </td>
                    <td> Maria Anders </td>
                       <td> Germany </td>
                     </tr>
                     <tr>
                       <td> Berglunds snabbköp </td>
                          <td> Christina Berglund </td>
                             <td> Sweden </td>
                           </tr>
                           <tr>
                             <td> Centro comercial Moctezuma</td>
                                <td>Francisco Chang</td>
                <td>Mexico</td>
                              </tr>
              <tr>
                <td>Ernst Handel</td>
                <td>Roland Mendel</td>
                <td>Austria</td>
                              </tr>
              <tr>
                <td>Island Trading</td>
                <td>Helen Bennett</td>
                <td>UK</td>
                              </tr>
              <tr>
                <td>Königlich Essen</td>
                <td>Philip Cramer</td>
                <td>Germany</td>
                              </tr>
              <tr>
                <td>Laughing Bacchus Winecellars</td>
                                <td>Yoshi Tannamuri</td>
                <td>Canada</td>
                              </tr>
              <tr>
                <td>Magazzini Alimentari Riuniti</td>
                                <td>Giovanni Rovelli</td>
                <td>Italy</td>
                              </tr>
              <tr>
                <td>North/South</td>
                                <td>Simon Crowther</td>
                <td>UK</td>
                              </tr>
              <tr>
                <td>Paris spécialités</td>
                <td>Marie Bertrand</td>
                <td>France</td>
                              </tr>
            </table>
            ";
        """

        if selector == 1:
            return """
            <script src="https://www.google.com/jsapi"></script>
			<div id="####"></div>
			<script>
               google.load("visualization", "1", {packages:["corechart"]});
               google.setOnLoadCallback(drawChart);
               function drawChart() {
                var data = google.visualization.arrayToDataTable([
                 ['Газ', 'Объём'],
                 ['Азот',     78.09],
                 ['Кислород', 20.95],
                 ['Аргон',    0.93],
                 ['Углекислый газ', 0.03]
                ]);
                var options = {
                 title: 'Состав воздуха',
                 is3D: true,
                 pieResidueSliceLabel: 'Остальное'
                };
                var chart = new google.visualization.PieChart(document.getElementById("####"));
                 chart.draw(data, options);
               }
              </script>
        """

        if selector == 2:
            return """
          <img width="68" height="68" src="data: image / jpeg; base64,/ 9j / 4AAQSkZJRgABAQEAYABgAAD / 4RCaRXhpZgAATU0AKgAAAAgABAE7AAIAAAANAAAISodpAAQAAAABAAAIWJydAAEAAAAaAAAQeOocAAcAAAgMAAAAPgAAAAAc6gAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHZpdGFseSBwb3BvdgAAAAHqHAAHAAAIDAAACGoAAAAAHOoAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHYAaQB0AGEAbAB5ACAAcABvAHAAbwB2AAAA / +EKZWh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8APD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4NCjx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iPjxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI + PHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9InV1aWQ6ZmFmNWJkZDUtYmEzZC0xMWRhLWFkMzEtZDMzZDc1MTgyZjFiIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iLz48cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0idXVpZDpmYWY1YmRkNS1iYTNkLTExZGEtYWQzMS1kMzNkNzUxODJmMWIiIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyI + PGRjOmNyZWF0b3I + PHJkZjpTZXEgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj48cmRmOmxpPnZpdGFseSBwb3BvdjwvcmRmOmxpPjwvcmRmOlNlcT4NCgkJCTwvZGM6Y3JlYXRvcj48L3JkZjpEZXNjcmlwdGlvbj48L3JkZjpSREY + PC94OnhtcG1ldGE + DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDw / eHBhY2tldCBlbmQ9J3cnPz7 / 2wBDAAcFBQYFBAcGBQYIBwcIChELCgkJChUPEAwRGBUaGRgVGBcbHichGx0lHRcYIi4iJSgpKywrGiAvMy8qMicqKyr / 2wBDAQcICAoJChQLCxQqHBgcKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKir / wAARCABEAEQDASIAAhEBAxEB / 8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL / 8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4 + Tl5ufo6erx8vP09fb3 + Pn6 / 8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL / 8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3 + Pn6 / 9oADAMBAAIRAxEAPwD6IooooAK5fxL8QfDvhJhHrWopHOeRBGC8hHrtHOPeuG + Knxeu / C2rnRNAija7VA088wyse7oAO5xz + IrwTU5r641CS51Z5ZLi5 / eu8vVgeQfpTSLUG9T6i0f4weDtaultrfU / IlY4Auo2iBPpkjFdtHIJEDIwZSMgg5yPWvh5HaNv3ZOR2xn8wa95 + CPxAbUJm8Oapjzkj8y1kU8Mo6rjsR7cU3G2wSj2PbKKKKkgsL90fSihfuj6UUAV6KKQ0AfM3xE8PNqnx1vbGaQxLfbJg2M / IIgDj / vg1v3Oh2msJFp + o6FJHawKIoLrzBvUAYHTkCr3xRWXSfGWn6zcxExLdoom29IyuCue3JP51rLDFFI0pbBYfMxPBrzcVVlzKx9DgqMOTXU4oeB9O0stFHpE2rRyHczSSBTF9DwT9K6X4Y6FpunfErVRa2SxBLKKSHIOYix + YVcSKG4dnY + YUY7SG4FUvAxudS + KupXdoW + zW6pBK4 + 62ByM / jRhqs5T1DGUacaWmh7QOlFAor0j54sL90fSihfuj6UUAV6KKKAMnX9Fttd0qSzu4Y5lLB1DjIDKcqfzArzfVPD1hqNwE1m1eYxfL5ZkZQPwBFeuk1534seefxA / 2R1VI0Cn3bvXFilZKadmj1culzSdJq6Zh2HhjSbG + WTRrGS2kb5dqzuwb2IJwa9G8OaDa + H9OMNrCsbTSGWbHdz1Ncx4U8yHWla7lDhlKj0zXoNLC3lecndhmD5GqMVZLUWiiiu48osL90fSihfuj6UUAVHZVUs + FVeST0 + teS + LvijcTzzWXht / IhQ7WugMu / 8AuZ4A9 + p9utdJ8VNZfTfCn2W3bEt +/ lN / 1zx835jj8a8SB9eaaR0UoJ6s6bTtRvzciWS7kMrDBYuct35rbj1c4 / exZPcq3WuT065AILdU4P0rSN4n / LNa8nHRftEz6 / KYQqUWmtmbcmrsP9XHt / 2m7VhalqWo / ajNbXciyoBhlkI / Ig003b1n31z5YwfvPRgYvnbFmtOFOikluzt / CHxQuFuYrDxIyyxOdqXfQoe28dCPf869bVgyhlIIIyCO9fLNe5fDDV21Lwosc775bNzCWPUrjI / Q16zPkasEtUd6v3R9KKF + 4PpRSOc8i + M5IbRh2xOf1jryrzSOOOKKKpHbS + Elt52SdCuBuODWzuNFFedjd0fVZHtP5Bu + lYs0zPcHdg4NFFPB9Qzz7HzIjK2egr1j4MuTBqq9vMQ / pRRXoPY + Vq / Az1tfuj6UUUVJxH//2Q==">
        """

        return "<h3>The given selector isn't acceptable</h3>"

    def execute(self, enter_params, result_writer, log_writer, temp_directory):
        if enter_params.graphType == 'Plain':
            self.__fill_result(result_writer, GPlainGen(enter_params.rows, enter_params.fieldx,
                                                        enter_params.connected_component).run())
        if enter_params.graphType == 'Trivial':
            self.__fill_result(result_writer, GTrivialGen(enter_params.rows, enter_params.fieldx,
                                                          enter_params.connected_component).run())
        if enter_params.graphType == 'SimpleChain':
            self.__fill_result(result_writer,
                               GSimpleChainGen(enter_params.rows, enter_params.fieldx,
                                               enter_params.connected_component).run())

        if enter_params.graphType == 'Tree':
            self.__fill_result(result_writer,
                               GTreeGen(enter_params.rows, enter_params.fieldx, enter_params.connected_component).run())

        if enter_params.graphType == 'Random':
            self.__fill_result(result_writer, GRandomGen(enter_params.rows, enter_params.fieldx).run())
        if enter_params.graphType == 'Full':
            self.__fill_result(result_writer,
                               GFullGen(enter_params.rows, enter_params.fieldx, enter_params.connected_component).run())
        if enter_params.graphType == 'XGraph':
            self.__fill_result(result_writer,
                               GSegGen(enter_params.segments, enter_params.nodes, enter_params.fieldx,
                                       enter_params.connected_component).run())
        if enter_params.graphType == 'Hierarchy':
            self.__fill_result(result_writer, GHierarchy(enter_params.rows, [], enter_params.connected_component).run())
