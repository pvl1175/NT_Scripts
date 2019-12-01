import random


class XGen:
    rows = 0
    cc = 1
    data = []
    temp = []
    linked_nodes = []

    def __init__(self, rows, liked_nodes, cc=1):
        self.cc = cc
        self.rows = rows
        self.linked_nodes = liked_nodes

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


class GTrivialGen(XGen):

    def grs(self, f, m):
        self.append_to_temp(f)
        for i in random.sample(range(1 + m * self.rows, self.rows + m * self.rows), self.rows - 1):
            self.add_nodes(f, i)
            self.append_to_temp(i)
        self.add_linked_nodes(f)

    def add_linked_nodes(self, f):
        for i in self.linked_nodes:
            if i not in self.temp:
                self.data.append([f, i, self.attr(), self.attr(), self.attr()])
                # self.data.append([f, str(i), self.attr(), self.attr(), self.attr()])
                self.temp.append(i)

    def run(self):
        m = 0
        for i in range(0, self.cc):
            self.grs(i + i * self.rows, i)
        return self.data


class GFullGen(XGen):
    def grs(self, m):
        r = m * (self.rows + 1)
        while r < self.rows + m * self.rows:
            j = r + 1
            self.append_to_temp(r)
            while j <= self.rows + m * self.rows:
                # self.data.append([r, j, self.attr(), self.attr(), self.attr()])
                self.add_nodes(r, j)
                self.append_to_temp(j)
                j = j + 1
            r = r + 1

        self.add_linked_nodes()
        # self.data

    def add_linked_nodes(self):
        for i in self.linked_nodes:
            if i not in self.temp:
                for j in self.temp:
                    self.data.append([i, j, self.attr(), self.attr(), self.attr()])
                self.temp.append(i)

    def run(self):
        for i in range(0, self.cc):
            self.grs(i)
        return self.data


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


g = GSegGen(2, 3, [], 3)
d = g.run()

for i in d:
    print(i)
