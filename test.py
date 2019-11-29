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

# g = GTrivialGen(10, [], 2)
# d = g.run()

g = GFullGen(3, [], 2)
d = g.run()

for i in d:
    print(i)

