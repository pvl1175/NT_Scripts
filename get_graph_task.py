import random

from lighthouse import *


class XGen:
    rows = 0
    data = []
    temp = []
    linked_nodes = []

    def __init__(self, rows, liked_nodes):
        self.rows = rows
        self.linked_nodes = liked_nodes

    def add_nodes(self, s, e):
        for i in range(1, self.r(1, 3)):
            self.data.append([s, e, self.attr(), self.attr(), self.attr()])

    def append_to_temp(self, val):
        if val not in self.temp:
            self.temp.append(val)

    def attr(self):
        return 'A-' + str(random.randint(1, self.rows))


# tree type graph
class GTreeGen(XGen):
    __count = 0

    def r(self, s=1, e=10):
        return random.randint(s, e)

    def grs(self):
        for i in range(self.rows):
            c = self.r(0, self.__count - 1)
            self.data.append([c, self.__count, self.attr(), self.attr(), self.attr()])
            #self.add_nodes(c, self.__count)
            self.append_to_temp(c)
            self.append_to_temp(self.__count)
            self.__count = self.__count + 1
        self.add_linked_nodes()

    def add_linked_nodes(self):
        for i in self.linked_nodes:
            if i not in self.temp:
                self.data.append([0, i, self.attr(), self.attr(), self.attr()])
                self.temp.append(i)

    def run(self):
        self.__count = self.__count + 1
        self.grs()
        return self.data


# trivial type graph
class GTrivialGen(XGen):

    def grs(self, f1):
        self.append_to_temp(f1)
        for i in random.sample(range(1, self.rows), self.rows - 1):
            #self.data.append([f1, i, self.attr(), self.attr(), self.attr()])
            self.add_nodes(f1, i)
            self.append_to_temp(i)
        self.add_linked_nodes(f1)

    def add_linked_nodes(self, f1):
        for i in self.linked_nodes:
            if i not in self.temp:
                self.data.append([f1, i, self.attr(), self.attr(), self.attr()])
                self.data.append([f1, i, self.attr(), self.attr(), self.attr()])
                self.temp.append(i)

    def run(self):
        self.grs(0)
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
    def grs(self):
        r = 0
        while r < self.rows:
            j = r + 1
            self.append_to_temp(r)
            while j <= self.rows:
                # self.data.append([r, j, self.attr(), self.attr(), self.attr()])
                self.add_nodes(r, j)
                self.append_to_temp(j)
                j = j + 1
            r = r + 1

        self.add_linked_nodes()
        return self.data

    def add_linked_nodes(self):
        for i in self.linked_nodes:
            if i not in self.temp:
                for j in self.temp:
                    self.data.append([i, j, self.attr(), self.attr(), self.attr()])
                self.temp.append(i)

    def run(self):
        self.grs()
        return self.data


# xgraph
class GSegGen:
    __sgm_count = 0
    __nodes_count = 0
    __linked_nodes = []
    __sgm = []
    __graph = []
    __temp = []

    def __init__(self, sgm_count, nodes_count, linked_nodes):
        self.__sgm_count = sgm_count
        self.__nodes_count = nodes_count
        self.__linked_nodes = linked_nodes

    def __sgm_gen(self):
        for i in range(self.__sgm_count):
            self.__sgm.append(list(range(0 + i * self.__nodes_count, self.__nodes_count + i * self.__nodes_count)))
        self.__add_linked_nodes()

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
                    for i in range(1, self.r(1, 3)):
                        self.__graph.append([s, n, self.__attr(), self.__attr(), self.__attr()])

                    self.__temp.append([s, n])

    def run(self):
        self.__sgm_gen()

        for s in self.__sgm:
            for d in self.__sgm:
                if s != d:
                    self.__build_links(s, d)

        return self.__graph


class GHierarchy(XGen):
    node_index = 1

    level_len = 8
    levels = []

    def r(self, s=1, e=10):
        return random.randint(s, e)

    def gen_nodes(self, s, e):
        n = []
        for x in range(1, self.r(s, e)):
            n.append(self.node_index)
            self.node_index = self.node_index + 1
        return n

    def add_linked_nodes(self, parent, children):
        for i in children:
            self.data.append([parent, i, self.attr(), self.attr(), self.attr()])

    def run(self):
        self.levels.append([0, [0]])
        for i in range(1, self.level_len):
            self.levels.append([i, self.gen_nodes(3, 10)])
            # arr = self.gen_nodes(3, 10)
            # self.levels.append([i, random.sample(arr, 2)])

        for i in range(self.level_len - 1):
            for n in self.levels[i][1]:
                # self.add_linked_nodes(n, self.levels[i + 1][1])
                self.add_linked_nodes(n, random.sample(self.levels[i + 1][1], self.r(1, len(self.levels[i + 1][1]))))

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
            EnterParamField('segments', 'Segments', ValueType.Integer, is_array=False, required=True, default_value=2,
                            category='Required', description='Segments count'),
            EnterParamField('nodes', 'Nodes', ValueType.Integer, is_array=False, required=True, default_value=3,
                            category='Required', description='Nodes count'),
            EnterParamField('graphType', 'GraphType', ValueType.String,
                            predefined_values=['Trivial', 'Tree', 'Random', 'Full', 'XGraph', 'Hierarchy'], category='Required',
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
            self.__fill_result(result_writer, GTrivialGen(enter_params.rows, enter_params.fieldx).run())
        if enter_params.graphType == 'Tree':
            self.__fill_result(result_writer, GTreeGen(enter_params.rows, enter_params.fieldx).run())
        if enter_params.graphType == 'Random':
            self.__fill_result(result_writer, GRandomGen(enter_params.rows, enter_params.fieldx).run())
        if enter_params.graphType == 'Full':
            self.__fill_result(result_writer, GFullGen(enter_params.rows, enter_params.fieldx).run())
        if enter_params.graphType == 'XGraph':
            self.__fill_result(result_writer,
                               GSegGen(enter_params.segments, enter_params.nodes, enter_params.fieldx).run())
        if enter_params.graphType == 'Hierarchy':
            self.__fill_result(result_writer, GHierarchy(enter_params.rows, []).run())
            # self.__fill_result(result_writer, GHierarchy(enter_params.rows, enter_params.fieldx).run())
