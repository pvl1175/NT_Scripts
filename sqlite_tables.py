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
        self.cur.execute('PRAGMA table_info({table_name})'.format(table_name = table))
        return self.cur.fetchall()

    @staticmethod
    def append_string(str, value):
        if str == '':
            return value
        else:
            return str + ',' + value

    @staticmethod
    def sqlite_types(field_type):
        if field_type == 'INT':
            return 'Integer'
        if field_type == 'TEXT':
            return 'String'
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
                columns_str = self.append_string(columns_str, '\'\' as {col}'.format(col = required_column))

        return (any_column_exists, columns_str)

    def data(self, columns, table):
        self.cur.execute('SELECT {cols} FROM {tbl}'.format(cols = columns, tbl = table))
        return self.cur.fetchall()

    def data_from_tables(self, required_columns, tables):
        result_data = []
        for table in tables:
            columns = self.find_columns(required_columns, table[0])
            if columns[0]:
                for row in self.data(columns[1], table[0]):
                    result_data.append(row)
        return result_data


data = SqliteData('D:/dev/nt/lampyre/master/AS/AS.UV/bin/Debug/net472/!sqlite_project/mlm2nqbd.jvi/ca6b84c20b7644a3b9fbf6170876f3bf.sqlite')
print(data.data_from_tables([['url', 'String']], data.tables()))
