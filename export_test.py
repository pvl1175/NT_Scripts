import sqlite3 as lite
import pdfkit
from htmldocx import HtmlToDocx


class Stat:
    def __init__(self, db_path):
        self.con = lite.connect(db_path)
        self.cur = self.con.cursor()

    @staticmethod
    def query():
        return '''
        select x.number, out_y.out_n, in_y.in_n
        from (
        select distinct x.number
        from (
        select num1 as number
        from t_Соединения_по_списку_идентификаторов___Звонки_57ad0a2076e14f48a426f39ad2dad11e
        union
        select num2 as number
        from t_Соединения_по_списку_идентификаторов___Звонки_57ad0a2076e14f48a426f39ad2dad11e
        ) x 
        ) x
        
        join
        (select num1, count(num1) as out_n
        from t_Соединения_по_списку_идентификаторов___Звонки_57ad0a2076e14f48a426f39ad2dad11e
        group by num1
        ) out_y
        on x.number=out_y.num1
        
        join
        (select num2, count(num2) as in_n
        from t_Соединения_по_списку_идентификаторов___Звонки_57ad0a2076e14f48a426f39ad2dad11e
        group by num2
        ) in_y
        on x.number=in_y.num2
        '''

    def run(self):
        data = []
        for row in self.cur.execute(Stat.query()):
            data.append(row)
        return data

    def build_html(self, data):
        header = '''
        <!DOCTYPE html>
        <html>
        <head>
        <style>
        table, th, td {
          border: 1px solid black;
        }
        </style>
        </head>
        <body>
        <h2>Table With Border</h2>
        <table style="width:100%">
        <tr>
        <th>Номер</th>
        <th>Количество исходящих</th> 
        <th>Количество входящих</th>
        </tr>  
        '''
        footer = '''
        </table>
        </body>
        </html>
        '''
        body = ''

        for row in data:
            body = body + '\n' + '<tr>'
            body = body + '\n' + '<td>' + row[0] + '</td>'
            body = body + '\n' + '<td>' + str(row[1]) + '</td>'
            body = body + '\n' + '<td>' + str(row[2]) + '</td>'
            body = body + '\n' + '</tr>'

        f = open("test.html", "w")
        f.write(header + body + footer)
        f.close()

stat = Stat('D:/dev/nt/lampyre/master/AS/AS.UV/bin/Debug/net472/!sqlite_project/mlm2nqbd.jvi/ca6b84c20b7644a3b9fbf6170876f3bf.sqlite')
stat.build_html(stat.run())

new_parser = HtmlToDocx()
new_parser.parse_html_file('test.html', 'test')

pdfkit.from_file('test.html', 'test.pdf')
