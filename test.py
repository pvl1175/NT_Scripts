import random


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


# g = GSimpleChainGen(2000, [], 1)
# d = g.run()

g = GTreeGen(100, [], 1)
d = g.run()

for i in d:
    print(i[0], '\t', i[1])

with open('somefile.txt', 'a') as the_file:
    for i in d:
        the_file.write(str(i[0]) + '\t' + str(i[1]) + '\n')
# import networkx as nx
# G=nx.Graph()
#
# for i in d:
#     G.add_node(i[0])
#
#
# for i in d:
#     G.add_edge(i[0], i[1])
#
# nx.write_graphml(G, 'test2.graphml')
