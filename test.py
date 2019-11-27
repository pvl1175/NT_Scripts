import random


class XGen:
    rows = 0
    data = []
    temp = []
    linked_nodes = []

    def __init__(self, rows, liked_nodes):
        self.rows = rows
        self.linked_nodes = liked_nodes

    def append_to_temp(self, val):
        if val not in self.temp:
            self.temp.append(val)

    def attr(self):
        return 'A-' + str(random.randint(1, self.rows))

    def r(self, s=1, e=10):
        return random.randint(s, e)


class GTrivialGen(XGen):

    def grs(self, f1):
        self.append_to_temp(f1)
        for i in random.sample(range(1, self.rows), self.rows - 1):
            self.data.append([f1, i, self.attr(), self.attr(), self.attr()])
            self.append_to_temp(i)
        self.add_linked_nodes(f1)

    def add_linked_nodes(self, f1):
        for i in self.linked_nodes:
            if i not in self.temp:
                self.data.append([f1, i, self.attr(), self.attr(), self.attr()])
                self.temp.append(i)

    def run(self):
        self.grs(0)
        return self.data


class GHierarchy(XGen):
    node_index = 1

    level_len = 4
    levels = []

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

        for i in range(self.level_len - 1):
            for n in self.levels[i][1]:
                self.add_linked_nodes(n, self.levels[i + 1][1])

        for i in self.levels:
            print(i)

        print('\n')

        for i in self.data:
            print(i)


h = GHierarchy(10, [])
h.run()