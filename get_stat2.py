import sqlite3 as lite
from lighthouse import *


class Stat:
    def __init__(self, db_path):
        self.con = lite.connect(db_path)
        self.cur = self.con.cursor()

    def __query(self, num1, num2, table_name):
        return '''
        select x.number, out_y.out_n, in_y.in_n
        from (
        select distinct x.number
        from (
        select {0} as number
        from {2}
        union
        select {1} as number
        from {2}
        ) x 
        ) x

        join
        (select {0}, count({0}) as out_n
        from {2}
        group by {0}
        ) out_y
        on x.number=out_y.num1

        join
        (select {1}, count({1}) as in_n
        from {2}
        group by {1}
        ) in_y
        on x.number=in_y.num2
        '''.format(num1, num2, table_name)

    def __get_data(self, num1, num2, table):
        data = []
        for row in self.cur.execute(self.__query(num1, num2, table)):
            data.append(row)
        return data

    def __tables(self):
        table_items = self.cur.execute("SELECT name FROM sqlite_master WHERE type='table' and name='table_items'").fetchone()

        tables = []
        for id in self.cur.execute("SELECT id FROM {0} WHERE header_id='3cb7bbc7-2bc4-4987-9b6b-1f533b4f174e'".format(table_items[0])):
            for table in self.cur.execute("SELECT name FROM sqlite_master WHERE type='table' and name like '%{0}'".format(id[0].replace('-', ''))):
                tables.append(table)

        return tables

    def reports(self, num1, num2):
        resources = []
        for table in self.__tables():
            data = self.__get_data(num1, num2, table[0])
            files = []
            for row in data:
                file_name = '{0}_{1}.txt'.format(table[0], row[0])
                stat_str = '{0};{1};{2}'.format(row[0], row[1], row[2])
                files.append([file_name, bytearray(stat_str.encode())])

            resources.append(files)

        return resources


class StatHeader(metaclass=Header):
    display_name = 'Stat2'
    resource_txt = Field('TXT', ValueType.String, binary_type=BinaryType.Resource)

class SqliteTask(Task):

    def get_id(self):
        return 'b795762d-6a93-4bc6-8a42-6440d400107c'

    def get_category(self):
        return 'Stat2Task'

    def get_display_name(self):
        return 'Stat2 Task'

    def get_headers(self):
        return HeaderCollection(StatHeader)

    def get_enter_params(self):
        return EnterParamCollection(
            EnterParamField('path', 'Path', ValueType.String, is_array=False, required=True, file_path=True,
                            default_value='', category='Required', description='Path'))

    @staticmethod
    def __fill_result(result_writer, resources):
        for resource in resources:
            for file in resource:
                line = StatHeader.create_empty()
                line[StatHeader.resource_txt] = Resource(file[0], file[1])
                result_writer.write_line(line, header_class=StatHeader)

    def execute(self, enter_params, result_writer, log_writer, temp_directory):
        stat = Stat(enter_params.path)
        self.__fill_result(result_writer, stat.reports('num1', 'num2'))
