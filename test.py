import random

from my_task import GTreeGen


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


# c = GTrivialGen(2, [])
# c.run()

# class GTreeGen:
#     __count = 0
#     __rows = 0
#     __data = []
#
#     def __init__(self, rows):
#         self.__rows = rows
#
#     def __r(self, s=1, e=10):
#         return random.randint(s, e)
#
#     def __attr(self):
#         return 'A-' + str(random.randint(1, self.__rows))
#
#     def __grs(self, f1):
#         for i in range(self.__rows):
#             c = self.__r(0, self.__count - 1)
#             self.__data.append([c, self.__count, self.__attr(), self.__attr(), self.__attr()])
#             self.__count = self.__count + 1
#
#     def run(self):
#         f1 = self.__count
#         self.__count = self.__count + 1
#         self.__grs(f1)
#         return self.__data

c = GTreeGen(6, [])
d = c.run()
for i in d:
    print(i)

# c = GTreeGen(6)
# d = c.run()
# for i in d:
#     print(i)
