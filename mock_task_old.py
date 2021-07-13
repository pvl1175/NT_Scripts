from lighthouse import *
from lighthouse_ontology import *

from datetime import datetime, timedelta


class Specials:
    DateTimeFormat = 'datetime_format'
    Hidden = 'hidden'
    MultilineWidth = 'multiline_width'
    Coordinates = 'coordinates'
    Latitude = 'latitude'
    Longitude = 'longitude'


class MockHeader(metaclass=Header):
    display_name = 'Mock header'

    StringField = Field('Simple string field', ValueType.String)
    StringField2 = Field('Simple string field 2', ValueType.String)
    StringField3 = Field('Simple string field 3', ValueType.String)
    IntField = Field('Int field', ValueType.Integer)
    FloatField = Field('Float field', ValueType.Float)
    BooleanField = Field('Boolean field', ValueType.Boolean)
    DatetimeField = Field('Datetime field', ValueType.Datetime)
    Image = Field('String image', ValueType.String, binary_type=BinaryType.Image)
    Color = Field('Color field', ValueType.String, binary_type=BinaryType.Color)

    FormattedDate = Field('DateTime with format', ValueType.Datetime)
    HiddenField = Field('Hidden field', ValueType.String)
    ShortField = Field('Limited width field', ValueType.String)
    CoordinatesField = Field('Coordinates field', ValueType.String)
    Latitude = Field('Latitude field', ValueType.String)
    Longitude = Field('Longitude field', ValueType.String)


class CustomObjType(metaclass=Object):
    name = 'Custom object type'

    CustomAttr = Attribute('Custom attribute', ValueType.String,
                           image='iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IAr'
                                 's4c6QAAAARnQU1BAACxjwv8YQUAAAHWSURBVHgBpVO/SyNBFP5mvdzt6R23B4cEbNbmELRYOzuTTrDQxsJKLQ'
                                 'SxUf+CmE6wcK1ELLRVm1goaONaCFq5gkVAMGMhqAFZf2SVZJPxzSYbV01E8Gt2Zt573/tm3rcMb9ERi0GgD2D'
                                 '9tNMrpzbtbURKSdgWD6ez6sqIafDYtNaoTEz2/sJQ90/ozd/K1Zk87HMPyfV78OuiWSFyXghkcYHtDsebjLnh'
                                 'P9AaGWrByZWQXLuDuZUjNSIuSRr8yL/WGeravzCqQY3ULpZQvzP0dKrg2WL0+KyoIpvZZtRd1/9GMkezza86s'
                                 '4ELiPWWd+tASev4JZz7UlxBQUkkBn7XlV0LWpOCCXonNKCPoT1+RN0NQ49Uu32EQAm/9kjFFZcEIizvM1cI5y'
                                 'j4IuSgOcnRg5mHr1BrHSiR3iDD2aRApFYst5ooE4KkemufgBfkKREwbMxv5eC4Ap+FbyhyJeij4MSynFzRnFp'
                                 '2XiWFu719wGlyI896JtIWLzuxRT+0z7yeW1dEu/7/qOtG2XlsycHijmvDxQgc/lQmuORPRLJ6kM6rq/uPXb6p'
                                 'GENUK4flzM3NBwyaNzg8zZt+MQ//TGG0xXQaboIiBoWNyilHSaQgWArp3b1w+jPct9TjEEoZ4gAAAABJRU5Er'
                                 'kJggg==')

    IdentAttrs = CaptionAttrs = [CustomAttr]

    Image = 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACx' \
            'jwv8YQUAAANnSURBVHgBxVc9TxRRFD1vZNGAHxv8wMRm6Aw0Q6I1S20BFFhpXFtjAhTQsltrAhTasiZWUgB/QIbagi2E2DEWNmB0o4Eg' \
            'Hzve82be7AoDzK47epLdefN2ds69991733kKSeHkstjHsIwGoJQDBRs+svo3hYqMPRmUgaqLDJZRditJXqvOfcLJ2TjAmJDmI8JEUCVk' \
            'qkUxxDvzKZxOnMWhKgjpmJnK9V3E0P1LyPW2w+7OINsR/L2y66O8uY+yd4DlD3tw13/VU8xi/f1EYwZor9WKjGze5nMdmH54FfbNC0gC' \
            'b/sIhXc/8MbdjaaQ8QfjoqFiyB0hXyS5fasNi5NdcOwMmgENGSx8hbd1GBjh+yPYcMunG1DneX6wEzP5a1GYm0Vlp4qnr75jSZYGMZGw' \
            'zMBfy2cN+bCs8/yz7F+TE9lOC4tT1/FElpHv1hzMr+MGqMefCwjDPv+8C63GrEST7w6MsKYjXv0dhH6Tw83Xt89MNjX6RV/9hTuJ5uvB' \
            'Sumf2g5uMn4PlyKIQGgRsz1ppjcDp6fdLAV0bwGXQK+Hn+cNSy1tFCIOaWzCbYXtVTeZNL03IAe5BJL0GGqDsgYkArrDxcGsbbPzcTkx' \
            'dO9i0C195CQHfIeTzTabZhBGQKAc1oWtDZAEiUPSbE9SBQZhObIGbVaBbgqtaDpJweZkhhb+M2iAFg7cUv8VuD+YIRfDk4/DHSsuEdOo' \
            'AuqG4EewE/p6e/xTRKQLtuTQgnKbWLEq2Zinkhl/cPnEw2lUQbg1swpcC+1YkmGFEQiFQ6ogx+pGGAERr1agXv0S74sLP5E2CobDF07h' \
            'DsrwCHO8lETDRQmSAuh9pBOrKPJS6z59uRm5Hedmsfayu+WNiaXXP7mldaK4L0rZ1Uq51ogyYpGUBR+YmE90pmgI1IWaXDj8t9mima8Z' \
            'wFyoimCUB7gUIy++taQ50fO8EaU8PQmH6l+KPDwZ516R5RBZLhsFl2OlcKO2eTQI1jsdMZ7L1zmy3OCuaERL1KuqO5iMXklsCJON2R4l' \
            'XOg5PiU5mISgTFePvGkmppkbkCMZJTu3brZts6sxzPTS/binQx3VefCmWexIfnnxh9XzU11HA9P6cJoczKeSeD4X53VjBhjYIl47zPEc' \
            'zBMbiE7LbGZy9EKZ7VU8Xj7N4+P4DRzPfeGezl4uAAAAAElFTkSuQmCC'


class MockSchema(metaclass=Schema):
    name = 'Mock Schema'
    Header = MockHeader

    MockEmail = Email.schematic({Email.Email: Header.StringField}, conditions=[
        Condition(Header.StringField, Operations.Equals, 'test@test.test'),
        Condition(Header.StringField, Operations.NotEqual, 'some'),
        Condition(Header.StringField2, Operations.Contains, 'text'),
        Condition(Header.StringField2, Operations.NotContain, 'text2'),
        Condition(Header.StringField3, Operations.StartsWith, 't'),
        Condition(Header.StringField3, Operations.EndsWith, 't')
    ], condition_union_mode=UnionMode.And, condition_ignore_case=True)

    MockIP = IPAddress.schematic({IPAddress.IPAddress: Header.StringField})
    MockIP2 = IPAddress.schematic({IPAddress.IPAddress: Header.StringField})
    MockIP2.set_properties(color_source=Header.Color.system_name)
    MockIP2.set_properties(text_source=Header.HiddenField.system_name)
    MockHash = Hash.schematic({Hash.Hash: Header.StringField2, Hash.HashingAlgorithm: Header.StringField3})

    HTI = HashToIPAddress.between(MockHash, MockIP, {HashToIPAddress.DateTime: Header.DatetimeField}, conditions=[
        Condition(Header.DatetimeField, Operations.NotEqual, '')
    ])


class MockSchema2(metaclass=Schema):
    name = 'Mock Schema 2'
    Header = MockHeader

    MockImage = CustomObjType.schematic({CustomObjType.CustomAttr: Header.StringField3})
    MockImage.set_properties(image_source=Header.Image.system_name)


MockSchema.set_scopes(SchemaScope.Graph)
MockSchema.set_category('Schema category 1')


eps = EnterParamCollection(
            EnterParamField('main', 'All options param', ValueType.String, is_array=True, required=False,
                            geo_json=False, file_path=False, default_value=['default_1', 'default_2'],
                            predefined_values=['default', 'not default'],
                            value_sources=[ValueSource(Attributes.System.IPAddress, 'kilos', 1)],
                            category='Category 1', description='Some parameter'),
            EnterParamField('x', 'X', ValueType.String, is_array=False, required=False,
                            geo_json=False, file_path=False, default_value='value_X',
                            predefined_values=['xxxxxxxx', '1', '2', '3', '4', '5', 'cwdcd', 'ccecece', 'weded3ew', 'dedew', 'dew', 'ferf', 'fref', 'cdcd', 'tgbtgb', 'vfvfr', 'ynuy', 'io', 'c5tgyg6', 'hhj7uju', 'ju7j7u', 'jik', 'weder', 'olololo', 'vhyh', 'hjuyjuj', 'vuhuhu', 'qwsdece', ' huyjuj', 'xswxdexe', 'plmplo', 'xewded', 'gtvgtgtr', 'wedew'],
                            #predefined_values=['xxxxxxxx', '1', '2', '3', '4', '5', 'cwdcd', 'ccecece'],
                            value_sources=[ValueSource(Attributes.System.IPAddress, 'kilos', 1)],
                            category='Category X', description='X param'),
            EnterParamField('y', 'Y', ValueType.String, is_array=True, required=False,
                            geo_json=False, file_path=False, default_value='value_Y',
                            predefined_values=['1', 'xyz', 'hjk'],
                            value_sources=[ValueSource(Attributes.System.IPAddress, 'kilos', 1)],
                            category='Category Y', description='Y param'),
            EnterParamField('when', 'When', ValueType.Datetime, default_value=datetime(2007, 9, 3),
                            category='Dates', required_group='date'),
            EnterParamField('relative_zero_shift', 'Current date', ValueType.Datetime,
                            default_value=RelativeDate(ReferencePoint.Now, timedelta(0)),
                            category='Dates', required_group='date'),
            EnterParamField('week_earlier', 'Week earlier', ValueType.Datetime,
                            default_value=RelativeDate(ReferencePoint.Today, timedelta(weeks=-1)),
                            category='Dates'),

            EnterParamField('kilos', 'Weight modifier', ValueType.Integer, is_array=True, default_value=1)
        )


schema_coll = SchemaCollection(MockSchema, MockSchema2)
graph_macro_simple = Macro(name='Graph Macro simple',
                           mapping_flags=[GraphMappingFlags.Completely, GraphMappingFlags.Skeleton],
                           schemas=schema_coll)
graph_macro_reset_weight = Macro(name='Graph Macro - sets main, resets weight',
                                 mapping_flags=[GraphMappingFlags.Completely],
                                 schemas=schema_coll, switches={eps['main']: ['switched value 1', 'switched_value_2']},
                                 drops=[eps['kilos']],
                                 category='drops and switches')
graph_macro_reset = Macro(name='Graph Macro - sets main, resets other',
                          mapping_flags=[GraphMappingFlags.Completely],
                          schemas=schema_coll, switches={eps['main']: 'switched value'}, drop_except=['main'],
                          category='drops and switches')
gis_macro = Macro(name='Nothing interesting here',
                  mapping_flags=[GisMappingFlags.Instances, GisMappingFlags.Heatmap, GisMappingFlags.Path],
                  schemas=schema_coll)


ru_culture = LocalizationCulture('ru')

ru_culture.add(MockHeader, 'Тестовый заголовок')

ru_culture.add(MockHeader.StringField, 'Короткое текстовое поле')
ru_culture.add(MockHeader.StringField2, 'Короткое текстовое поле 2')
ru_culture.add(MockHeader.StringField3, 'Короткое текстовое поле 3')
ru_culture.add(MockHeader.IntField, 'Целочисленное поле')
ru_culture.add(MockHeader.FloatField, 'Поле с плавающей запятой')
ru_culture.add(MockHeader.BooleanField, 'Булево поле')
ru_culture.add(MockHeader.DatetimeField, 'Поле с датой')
ru_culture.add(MockHeader.Image, 'Поле с изображением')
ru_culture.add(MockHeader.Color, 'Поле с цветом')
ru_culture.add(MockHeader.FormattedDate, 'Отформатированная дата')
ru_culture.add(MockHeader.HiddenField, 'Скрытое поле')
ru_culture.add(MockHeader.ShortField, 'Поле с лимитированной длиной')
ru_culture.add(MockHeader.CoordinatesField, 'Поле с координатой')
ru_culture.add(MockHeader.CoordinatesField, 'Поле с координатой')
ru_culture.add(MockHeader.Latitude, 'Широта')
ru_culture.add(MockHeader.Longitude, 'Долгота')

ru_culture.add(CustomObjType, 'Кастомный объект')

ru_culture.add(CustomObjType.CustomAttr, 'Кастомный атрибут')

ru_culture.add(MockSchema, 'Тестовая схема')
ru_culture.add(MockSchema2, 'Тестовая схема 2')

ru_culture.manual_add(LocalizationScopes.Task, TaskLocalizationItems.DisplayName, 'Тестовая методика')
ru_culture.manual_add(LocalizationScopes.Task, TaskLocalizationItems.Category, 'Тестовые')
ru_culture.manual_add(LocalizationScopes.Task, TaskLocalizationItems.Description, 'Описание тестовой методики')

ru_ep_descriptions = {
    'main': 'Это пример параметра со всеми опциями',
    'when': 'Это пример параметра с датой',
    'relative_zero_shift': 'Это пример параметра снулевым сдвигом',
    'week_earlier': 'Это пример параметра со сдвигом на неделю',
    'kilos': 'Это пример параметра, учитываемого в расчёте веса'
}

for ep_name, translation in ru_ep_descriptions.items():
    ru_culture.manual_add(LocalizationScopes.EnterParamDescriptions, ep_name, translation)

ru_culture.manual_add(LocalizationScopes.EnterParamCategories, 'Category 1', 'Категория 1')
ru_culture.manual_add(LocalizationScopes.EnterParamCategories, 'Dates', 'Даты')

for m in [graph_macro_simple, graph_macro_reset_weight, graph_macro_reset]:
    ru_culture.manual_add(LocalizationScopes.MacroCategories, m.name, 'Макросы для графа')

ru_culture.manual_add(LocalizationScopes.MacroCategories, gis_macro.name, 'Макросы для ГИСа')
ru_culture.manual_add(LocalizationScopes.SchemaCategories, MockSchema.name, 'Категория схем 1')

ru_culture.add(eps['main'], 'Параметр со всеми опциями')
ru_culture.add(eps['when'], 'Когда')
ru_culture.add(eps['relative_zero_shift'], 'Нулевой сдвиг')
ru_culture.add(eps['week_earlier'], 'Неделей ранее')
ru_culture.add(eps['kilos'], 'Килограммы')

ru_culture.add(graph_macro_simple, 'Простой макрос')
ru_culture.add(graph_macro_reset, 'Макрос со сбросом всего')
ru_culture.add(graph_macro_reset_weight, 'Макрос со сбросом веса')
ru_culture.add(gis_macro, 'Гис-макрос')


class TaskLocalization(metaclass=Localization):
    RU = ru_culture


class MockTask(Task):
    def __init__(self):
        super().__init__()

    def get_id(self):
        return 'a63bd0b2-bf30-4bd0-b309-c88aa0b894d6'

    def get_display_name(self):
        return 'Mock task'

    def get_category(self):
        return 'Mock category'

    def get_description(self):
        return 'Mock description'

    def get_enter_params(self):
        return eps

    def get_headers(self):
        MockHeader.set_property(MockHeader.HiddenField.system_name, Specials.Hidden, True)
        MockHeader.set_property(MockHeader.FormattedDate.system_name, Specials.DateTimeFormat, 'dddd, dd MMMM yyyy')
        MockHeader.set_property(MockHeader.ShortField.system_name, Specials.MultilineWidth, 40)
        MockHeader.set_property(MockHeader.CoordinatesField.system_name, Specials.Coordinates, True)
        MockHeader.set_property(MockHeader.Latitude.system_name, Specials.Latitude, True)
        MockHeader.set_property(MockHeader.Longitude.system_name, Specials.Longitude, True)

        return HeaderCollection(
            MockHeader
        )

    def get_schemas(self):
        MockSchema.set_scopes(SchemaScope.Graph, SchemaScope.Document)
        return SchemaCollection(
            MockSchema, MockSchema2
        )

    def get_graph_macros(self):
        return MacroCollection(graph_macro_simple, graph_macro_reset_weight, graph_macro_reset)

    def get_gis_macros(self):
        return MacroCollection(gis_macro)

    def get_weight_function(self):
        return 'kilos'

    def get_localization(self):
        return TaskLocalization

    def execute(self, enter_params, result_writer, log_writer, temp_directory):
        for m in enter_params.main:
            line = MockHeader.create_empty()
            for field in MockHeader:
                if field.type == ValueType.Boolean:
                    line[field] = True
                elif field.type == ValueType.Datetime:
                    line[field] = str(datetime.now()).split('.')[0]
                elif field.type == ValueType.Float:
                    line[field] = 42.42
                elif field.type == ValueType.Integer:
                    line[field] = 42
                else:  # string
                    line[field] = 'The quick brown fox jumps over the lazy dog'

            line[MockHeader.StringField] = m
            line[MockHeader.StringField2] = 'test;\n string \n line "\n" test;""" quote test'
            line[MockHeader.StringField3] = 'MD5'
            line[MockHeader.Latitude] = '55.797389'
            line[MockHeader.Longitude] = '37.584569'
            line[MockHeader.Color] = 'Red'
            line[MockHeader.Image] = \
                'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACx' \
                'jwv8YQUAAANnSURBVHgBxVc9TxRRFD1vZNGAHxv8wMRm6Aw0Q6I1S20BFFhpXFtjAhTQsltrAhTasiZWUgB/QIbagi2E2DEWNmB0o4Eg' \
                'Hzve82be7AoDzK47epLdefN2ds69991733kKSeHkstjHsIwGoJQDBRs+svo3hYqMPRmUgaqLDJZRditJXqvOfcLJ2TjAmJDmI8JEUCVk' \
                'qkUxxDvzKZxOnMWhKgjpmJnK9V3E0P1LyPW2w+7OINsR/L2y66O8uY+yd4DlD3tw13/VU8xi/f1EYwZor9WKjGze5nMdmH54FfbNC0gC' \
                'b/sIhXc/8MbdjaaQ8QfjoqFiyB0hXyS5fasNi5NdcOwMmgENGSx8hbd1GBjh+yPYcMunG1DneX6wEzP5a1GYm0Vlp4qnr75jSZYGMZGw' \
                'zMBfy2cN+bCs8/yz7F+TE9lOC4tT1/FElpHv1hzMr+MGqMefCwjDPv+8C63GrEST7w6MsKYjXv0dhH6Tw83Xt89MNjX6RV/9hTuJ5uvB' \
                'Sumf2g5uMn4PlyKIQGgRsz1ppjcDp6fdLAV0bwGXQK+Hn+cNSy1tFCIOaWzCbYXtVTeZNL03IAe5BJL0GGqDsgYkArrDxcGsbbPzcTkx' \
                'dO9i0C195CQHfIeTzTabZhBGQKAc1oWtDZAEiUPSbE9SBQZhObIGbVaBbgqtaDpJweZkhhb+M2iAFg7cUv8VuD+YIRfDk4/DHSsuEdOo' \
                'AuqG4EewE/p6e/xTRKQLtuTQgnKbWLEq2Zinkhl/cPnEw2lUQbg1swpcC+1YkmGFEQiFQ6ogx+pGGAERr1agXv0S74sLP5E2CobDF07h' \
                'DsrwCHO8lETDRQmSAuh9pBOrKPJS6z59uRm5Hedmsfayu+WNiaXXP7mldaK4L0rZ1Uq51ogyYpGUBR+YmE90pmgI1IWaXDj8t9mima8Z' \
                'wFyoimCUB7gUIy++taQ50fO8EaU8PQmH6l+KPDwZ516R5RBZLhsFl2OlcKO2eTQI1jsdMZ7L1zmy3OCuaERL1KuqO5iMXklsCJON2R4l' \
                'XOg5PiU5mISgTFePvGkmppkbkCMZJTu3brZts6sxzPTS/binQx3VefCmWexIfnnxh9XzU11HA9P6cJoczKeSeD4X53VjBhjYIl47zPEc' \
                'zBMbiE7LbGZy9EKZ7VU8Xj7N4+P4DRzPfeGezl4uAAAAAElFTkSuQmCC'

            line[MockHeader.HiddenField] = 'Text in hidden field'
            result_writer.write_line(line, header_class=MockHeader)


if __name__ == '__main__':
    class EPS:
        # enter_params
        param = []


    class RW:
        # result_writer
        @staticmethod
        def write_line(line, *args, **kwargs):
            print(line)


    class LW:
        # log_writer
        @staticmethod
        def info(message, *args):
            print(message)

        @staticmethod
        def error(message, *args):
            print(message)

    temp_dir = None

    task = MockTask()

    task.execute(EPS, RW, LW, temp_dir)