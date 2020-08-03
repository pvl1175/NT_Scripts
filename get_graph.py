import random
import sys


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

    def p(self, d, fn):
        for i in d:
            print(i[0], '\t', i[1])

        with open(fn, 'w') as the_file:
            for i in d:
                the_file.write(str(i[0]) + '\t' + str(i[1]) + '\n')


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
            self.add_nodes(parent, parent)
            self.add_nodes(child, child)
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
    __gen_type = 0

    def __init__(self, sgm_count, nodes_count, linked_nodes, gen_type=0, connected_comp=1):
        self.__sgm_count = sgm_count
        self.__nodes_count = nodes_count
        self.__linked_nodes = linked_nodes
        self.__connected_comp = connected_comp
        self.__gen_type = gen_type

    def __r(self, s=1, e=10):
        return random.randint(s, e)

    def __sgm_gen(self, next_node):
        if self.__gen_type == 0:
            for i in range(self.__sgm_count):
                self.__sgm.append(list(
                    range(i * self.__nodes_count + next_node, self.__nodes_count + i * self.__nodes_count + next_node)))
            self.__add_linked_nodes()

        elif self.__gen_type == 1:
            for i in range(self.__sgm_count):
                self.__sgm.append(list(
                    range(i * self.__nodes_count + next_node,
                          self.__r(2, self.__nodes_count) + i * self.__nodes_count + next_node)))
            self.__add_linked_nodes()

        elif self.__gen_type == 2:
            for i in range(self.__sgm_count):
                if i == 0:
                    self.__sgm.append(list(
                        range(i * self.__nodes_count + next_node,
                              self.__nodes_count + i * self.__nodes_count + next_node)))
                else:
                    self.__sgm.append(list(
                        range(i * self.__nodes_count + next_node, 3 + i * self.__nodes_count + next_node)))
            self.__add_linked_nodes()

        elif self.__gen_type == 3:
            for i in range(self.__sgm_count):
                if i == 0:
                    self.__sgm.append(list(
                        range(i * self.__nodes_count + next_node,
                              self.__nodes_count + i * self.__nodes_count + next_node)))
                else:
                    self.__sgm.append(list(
                        range(i * self.__nodes_count + next_node,
                              self.__r(2, self.__nodes_count) + i * self.__nodes_count + next_node)))
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
        for cc in range(0, self.__connected_comp):
            self.__sgm.clear()
            next_node = self.__sgm_gen(next_node)
            for s in self.__sgm:
                for d in self.__sgm:
                    if s != d:
                        self.__build_links(s, d)

        return self.__graph

    def p(self, d, fn):
        for i in d:
            print(i[0], '\t', i[1])

        with open(fn, 'w') as the_file:
            for i in d:
                the_file.write(str(i[0]) + '\t' + str(i[1]) + '\n')


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


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('arguments for: [simple tree hierarchy trivial random full seg]')
        sys.exit(1)

    if sys.argv[1] == 'simple':
        print('arguments for simple: rows connected_components')
        if len(sys.argv) < 3:
            print('(simple) arguments is not enough')
            sys.exit(1)
        g = GSimpleChainGen(int(sys.argv[2]), [], int(sys.argv[3]))
        d = g.run()
        g.p(d, 'simplechain.txt')

    if sys.argv[1] == 'tree':
        print('arguments for tree: rows connected_components')
        if len(sys.argv) < 3:
            print('(tree) arguments is not enough')
            sys.exit(1)
        g = GTreeGen(int(sys.argv[2]), [], int(sys.argv[3]))
        d = g.run()
        g.p(d, 'tree.txt')

    if sys.argv[1] == 'hierarchy':
        print('arguments for hierarchy: rows connected_components')
        if len(sys.argv) < 3:
            print('(hierarchy) arguments is not enough')
            sys.exit(1)
        g = GHierarchy(int(sys.argv[2]), [], int(sys.argv[3]))
        d = g.run()
        g.p(d, 'hierarhy.txt')

    if sys.argv[1] == 'trivial':
        print('arguments for trivial: rows connected_components')
        if len(sys.argv) < 3:
            print('(trivial) arguments is not enough')
            sys.exit(1)
        g = GTrivialGen(int(sys.argv[2]), [], int(sys.argv[3]))
        d = g.run()
        g.p(d, 'trivial.txt')

    if sys.argv[1] == 'random':
        print('arguments for random: rows connected_components')
        if len(sys.argv) < 3:
            print('(random) arguments is not enough')
            sys.exit(1)
        g = GRandomGen(int(sys.argv[2]), [], int(sys.argv[3]))
        d = g.run()
        g.p(d, 'random.txt')

    if sys.argv[1] == 'full':
        print('arguments for full: rows connected_components')
        if len(sys.argv) < 3:
            print('(full) arguments is not enough')
            sys.exit(1)
        g = GFullGen(int(sys.argv[2]), [], int(sys.argv[3]))
        d = g.run()
        g.p(d, 'full.txt')


    # def __init__(self, sgm_count, nodes_count, linked_nodes, gen_type=0, connected_comp=1):

    if sys.argv[1] == 'seg':
        print('arguments for seg: sgm nodes connected_components')
        if len(sys.argv) < 4:
            print('(seg) arguments is not enough')
            sys.exit(1)
        g = GSegGen(int(sys.argv[2]), int(sys.argv[3]), [], int(sys.argv[4]))
        d = g.run()
        g.p(d, 'seg.txt')
