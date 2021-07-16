import sqlite3 as lite
import pdfkit
from htmldocx import HtmlToDocx


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
        cur = self.con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' and name like 't_Соед%'")
        return cur.fetchall()

    def reports(self, num1, num2):
        path = 'd:/temp'
        header = '''
<!DOCTYPE html>
<html>
<head>
<style>
    table, th, td { border: 1px solid black; }
</style>
</head>
<body>
        '''
        table_header = '''
    <br>
    <table style="width:100%">
        <tr>
            <th>Номер</th>
            <th>Количество исходящих</th> 
            <th>Количество входящих</th>
        </tr>  
        '''
        table_footer = '\n\t</table>'
        footer = '''
</body>
</html>
        '''
        body = ''

        for table in self.__tables():
            body = body + table_header
            data = self.__get_data(num1, num2, table[0])
            for row in data:
                body = body + '<tr>'
                body = body + '\n' + '\t\t<td>' + row[0] + '</td>'
                body = body + '\n' + '\t\t<td>' + str(row[1]) + '</td>'
                body = body + '\n' + '\t\t<td>' + str(row[2]) + '</td>'
                body = body + '\n' + '\t</tr>\n\t'
            body = body + table_footer

            # build html file
            f = open('{0}/{1}.html'.format(path, table[0]), 'w')
            f.write(header + body + footer)
            f.close()

            # convert to docx
            new_parser = HtmlToDocx()
            new_parser.parse_html_file('{0}{1}.html'.format(path, table[0]), table[0])

            # convert to pdf
            pdfkit.from_file('{0}{1}.html'.format(path, table[0]), '{0}.pdf'.format(table[0]))

stat = Stat(
    'D:\dev\nt\lampyre\master\AS\AS.UV\bin\Debug\net472\!sqlite_project\mmey1asp.xuv\')

column1 = 'num1'
column2 = 'num2'

# build html file
stat.reports(column1, column2)
