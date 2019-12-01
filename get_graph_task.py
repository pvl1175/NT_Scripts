import random

from lighthouse import *


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
            self.__sgm.append(list(range(i * self.__nodes_count + next_node, self.__nodes_count + i * self.__nodes_count + next_node)))
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
                    self.add_linked_nodes(n, random.sample(self.levels[i + 1][1], self.r(1, len(self.levels[i + 1][1]))))

            self.node_index = self.node_index + 1

        return self.data


class GenHeader(metaclass=Header):
    display_name = 'Gen table'

    Field1 = Field('Field1', ValueType.Integer)
    Field2 = Field('Field2', ValueType.Integer)
    Attr1 = Field('Attr1', ValueType.String)
    Attr2 = Field('Attr2', ValueType.String)
    Attr3 = Field('Attr3', ValueType.String)


class FieldType(metaclass=Object):
    name = 'Field type'
    FieldX = Attribute('FieldX', ValueType.Integer)
    Attr1 = Attribute('Attr1', ValueType.String)
    Attr2 = Attribute('Attr2', ValueType.String)
    Attr3 = Attribute('Attr3', ValueType.String)
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

    f1type = SchemaObject(FieldType, mapping={FieldType.FieldX: Header.Field1})
    f2type = SchemaObject(FieldType, mapping={FieldType.FieldX: Header.Field2})
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
                            predefined_values=['Trivial', 'Tree', 'Random', 'Full', 'XGraph', 'Hierarchy'],
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
                GenHeader.Attr3: i[4]
            })

    def execute(self, enter_params, result_writer, log_writer, temp_directory):
        if enter_params.graphType == 'Trivial':
            self.__fill_result(result_writer, GTrivialGen(enter_params.rows, enter_params.fieldx,
                                                          enter_params.connected_component).run())
        if enter_params.graphType == 'Tree':
            self.__fill_result(result_writer, GTreeGen(enter_params.rows, enter_params.fieldx, enter_params.connected_component).run())
        if enter_params.graphType == 'Random':
            self.__fill_result(result_writer, GRandomGen(enter_params.rows, enter_params.fieldx).run())
        if enter_params.graphType == 'Full':
            self.__fill_result(result_writer, GFullGen(enter_params.rows, enter_params.fieldx, enter_params.connected_component).run())
        if enter_params.graphType == 'XGraph':
            self.__fill_result(result_writer,
                               GSegGen(enter_params.segments, enter_params.nodes, enter_params.fieldx, enter_params.connected_component).run())
        if enter_params.graphType == 'Hierarchy':
            self.__fill_result(result_writer, GHierarchy(enter_params.rows, [], enter_params.connected_component).run())
            # self.__fill_result(result_writer, GHierarchy(enter_params.rows, enter_params.fieldx).run())
