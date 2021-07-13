import sqlite3 as lite
from lighthouse import *


class SqliteData:
    def __init__(self, db_path):
        self.con = lite.connect(db_path)
        self.cur = self.con.cursor()

    def tables(self):
        cur = self.con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        return cur.fetchall()

    def columns(self, table):
        self.cur.execute('PRAGMA table_info({table_name})'.format(table_name=table))
        return self.cur.fetchall()

    @staticmethod
    def append_string(str, value):
        if str == '':
            return value
        else:
            return str + ',' + value

    @staticmethod
    def sqlite_types(field_type):
        if field_type == 'integer':
            return 'integer'
        if field_type == 'text':
            return 'string'
        if field_type == 'boolean':
            return 'Boolean'
        return ''

    def find_columns(self, required_columns, table):
        any_column_exists = False
        columns_str = ''
        for required_column in required_columns:
            found_column = ''
            for column in self.columns(table):
                if required_column[0] == column[1] and required_column[1] == self.sqlite_types(column[2]):
                    found_column = column[1]
                    any_column_exists = True
                    break

            if found_column != '':
                columns_str = self.append_string(columns_str, found_column)
            else:
                columns_str = self.append_string(columns_str, '\'\' as {col}'.format(col=required_column))

        return (any_column_exists, columns_str)

    def data(self, columns, table):
        self.cur.execute('SELECT {cols} FROM {tbl}'.format(cols=columns, tbl=table))
        return self.cur.fetchall()

    def data_from_tables(self, required_columns, tables):
        result_data = []
        for table in tables:
            columns = self.find_columns(required_columns, table[0])
            if columns[0]:
                for row in self.data(columns[1], table[0]):
                    result_data.append(row)

        return result_data


class SqliteGen:
    data = []
    path = ''

    def __init__(self, path):
        self.path = path

    def run(self, fields_list):
        sql_data = SqliteData(self.path)
        for item in sql_data.data_from_tables(fields_list, sql_data.tables()):
            self.data.append(item)
        return self.data


class SqliteHeader(metaclass=Header):
    display_name = 'Sqlite Header'
    id = Field('Id', ValueType.Integer)
    num1 = Field('Num1', ValueType.String)
    num2 = Field('Num2', ValueType.String)
    imei = Field('Imei', ValueType.String)


class SqliteTask(Task):

    def get_id(self):
        return 'b795762d-6a93-4bc6-8a42-6440d400107b'

    def get_category(self):
        return 'SqliteTask'

    def get_display_name(self):
        return 'Sqlite Task'

    def get_headers(self):
        return HeaderCollection(SqliteHeader)

    def get_enter_params(self):
        return EnterParamCollection(
            EnterParamField('path', 'Path', ValueType.String, is_array=False, required=True, file_path=True,
                            default_value='', category='Required', description='Path'))

    @staticmethod
    def __fill_result(result_writer, data):
        for item_data in data:
            i = 0
            data_dic = {}
            for field_name in SqliteHeader.get_fields().values():
                data_dic[field_name] = item_data[i]
                i = i + 1
            result_writer.write_line(data_dic)

    def execute(self, enter_params, result_writer, log_writer, temp_directory):
        fields = []
        for item in SqliteHeader.get_fields().values():
            fields.append([item.system_name, item.type])
        self.__fill_result(result_writer, SqliteGen(enter_params.path).run(fields))
