import lighthouse

ONTOLOGY_ID = 'b811dc34-b029-46fb-a030-8094fc3ce096'
NAME = 'System ontology'
VERSION = '1.3.3 AS.Core.Analysis.Ontology.GeneralOntology, AS.Core.Analysis.Ontology.CdrOntologyCore, AS.Core.Analysis.Ontology.IpdrOntologyCore'


# region Constants

class Constants:
    # arrow for link names, e.g. "Domain → Email"
    RIGHTWARDS_ARROW = '\u2192'
    EN_DASH = '\u2013'

# endregion


# region Helpers

class Utils(lighthouse.Utils):
    """
    extends functionality of lighthouse.Utils
    """

    @classmethod
    def make_schema_name(cls, from_obj_name: str, to_obj_name: str):
        """
        Forms schema name, e.g. Email → Twitter account

        :param from_obj_name: start object
        :param to_obj_name: end object
        :return str:
        """
        return f'{from_obj_name} {Constants.RIGHTWARDS_ARROW} {to_obj_name}'

    # noinspection PyUnresolvedReferences
    @classmethod
    def make_link_name(cls, begin: lighthouse.Object, end: lighthouse.Object):
        if begin.name == end.name:
            return f'{begin.name} {Constants.EN_DASH} {end.name}'
        return f'{begin.name} {Constants.RIGHTWARDS_ARROW} {end.name}'

# endregion


# region Attributes

class AttributesProvider:
    def __init__(self):
        self.__attr_types = {}
        self.System = self.__SystemAttrsProvider()

    # noinspection PyPep8Naming
    class __SystemAttrsProvider:
        @property
        def AbonentContractDate(self):
            return Attributes.dt('Abonent contract date')

        @property
        def AcademicDegree(self):
            return Attributes.str('Academic degree')

        @property
        def Address(self):
            return Attributes.str('Address')

        @property
        def ApplicationLayerProtocol(self):
            return Attributes.str('Application layer protocol')

        @property
        def ASN(self):
            return Attributes.str('ASN')

        @property
        def Azimuth(self):
            return Attributes.float('Azimuth')

        @property
        def Bio(self):
            return Attributes.str('Bio')

        @property
        def BirthdayDate(self):
            return Attributes.dt('Birthday date')

        @property
        def BirthdayString(self):
            return Attributes.str('Birthday string')

        @property
        def BodyStyle(self):
            return Attributes.str('Body style')

        @property
        def Brand(self):
            return Attributes.str('Brand')

        @property
        def Carrier(self):
            return Attributes.str('Carrier')

        @property
        def Cell(self):
            return Attributes.int('Cell')

        @property
        def City(self):
            return Attributes.str('City')

        @property
        def Comment(self):
            return Attributes.str('Comment')

        @property
        def Count(self):
            return Attributes.int('Count')

        @property
        def Country(self):
            return Attributes.str('Country')

        @property
        def CountryCode(self):
            return Attributes.str('Country code')

        @property
        def Credentials(self):
            return Attributes.str('Credentials')

        @property
        def CurrentWork(self):
            return Attributes.str('Current work')

        @property
        def Data(self):
            return Attributes.str('Data')

        @property
        def DateAccessed(self):
            return Attributes.dt('Date accessed')

        @property
        def DateCreated(self):
            return Attributes.dt('Date created')

        @property
        def DateModified(self):
            return Attributes.dt('Date modified')

        @property
        def DateString(self):
            return Attributes.str('Date string')

        @property
        def DateTime(self):
            return Attributes.dt('Date time')

        @property
        def Description(self):
            return Attributes.str('Description')

        @property
        def Document(self):
            return Attributes.str('Document')

        @property
        def Domain(self):
            return Attributes.str('Domain')

        @property
        def DomainRegistrant(self):
            return Attributes.str('Domain registrant')

        @property
        def Driveline(self):
            return Attributes.str('Driveline')

        @property
        def Duration(self):
            return Attributes.int('Duration')

        @property
        def Email(self):
            return Attributes.str('Email')

        @property
        def EnginePower(self):
            return Attributes.int('Engine power')

        @property
        def EngineType(self):
            return Attributes.str('Engine type')

        @property
        def EntranceYear(self):
            return Attributes.int('Entrance year')

        @property
        def FacebookID(self):
            return Attributes.str('Facebook ID')

        @property
        def Filename(self):
            return Attributes.str('Filename')

        @property
        def FileSize(self):
            return Attributes.int('File size')

        @property
        def FileType(self):
            return Attributes.str('File type')

        @property
        def FirstAppearance(self):
            return Attributes.dt('First appearance')

        @property
        def FlickrID(self):
            return Attributes.str('Flickr ID')

        @property
        def FollowersCount(self):
            return Attributes.int('Followers count')

        @property
        def FollowingCount(self):
            return Attributes.int('Following count')

        @property
        def FoursquareID(self):
            return Attributes.str('Foursquare ID')

        @property
        def FuelType(self):
            return Attributes.str('Fuel type')

        @property
        def Geohash(self):
            return Attributes.str('Geohash')

        @property
        def GeoLineString(self):
            return Attributes.str('Geo line string')

        @property
        def GeoPoint(self):
            return Attributes.str('Geo point')

        @property
        def GeoPolygon(self):
            return Attributes.str('Geo polygon')

        @property
        def GraduationYear(self):
            return Attributes.int('Graduation year')

        @property
        def Hash(self):
            return Attributes.str('Hash')

        @property
        def HashingAlgorithm(self):
            return Attributes.str('Hashing algorithm')

        @property
        def HashInteger(self):
            return Attributes.int('Hash integer')

        @property
        def ICQID(self):
            return Attributes.str('ICQ ID')

        @property
        def IMEI(self):
            return Attributes.str('IMEI')

        @property
        def IMEIUsageBeginDate(self):
            return Attributes.dt('IMEI usage begin date')

        @property
        def IMEIUsageCount(self):
            return Attributes.int('IMEI usage count')

        @property
        def IMEIUsageEndDate(self):
            return Attributes.dt('IMEI usage end date')

        @property
        def IMSI(self):
            return Attributes.str('IMSI')

        @property
        def Info(self):
            return Attributes.str('Info')

        @property
        def IPAddress(self):
            return Attributes.str('IP address')

        @property
        def IPAddressAndPort(self):
            return Attributes.str('IP address and port')

        @property
        def IPAddressInteger(self):
            return Attributes.int('IP address integer')

        @property
        def ISP(self):
            return Attributes.str('ISP')

        @property
        def LAC(self):
            return Attributes.int('LAC')

        @property
        def LastAppearance(self):
            return Attributes.dt('Last appearance')

        @property
        def Latitude(self):
            return Attributes.float('Latitude')

        @property
        def LicensePlateNumber(self):
            return Attributes.str('License plate number')

        @property
        def LinkedInID(self):
            return Attributes.str('LinkedIn ID')

        @property
        def LocationString(self):
            return Attributes.str('Location string')

        @property
        def Login(self):
            return Attributes.str('Login')

        @property
        def Longitude(self):
            return Attributes.float('Longitude')

        @property
        def MACAddress(self):
            return Attributes.str('MAC address')

        @property
        def Manufacturer(self):
            return Attributes.str('Manufacturer')

        @property
        def MaritalStatus(self):
            return Attributes.str('Marital status')

        @property
        def Markup(self):
            return Attributes.str('Markup')

        @property
        def MCC(self):
            return Attributes.str('MCC')

        @property
        def MiddleName(self):
            return Attributes.str('Middle name')

        @property
        def MNC(self):
            return Attributes.str('MNC')

        @property
        def Model(self):
            return Attributes.str('Model')

        @property
        def Name(self):
            return Attributes.str('Name')

        @property
        def Nickname(self):
            return Attributes.str('Nickname')

        @property
        def Number(self):
            return Attributes.int('Number')

        @property
        def Occupation(self):
            return Attributes.str('Occupation')

        @property
        def OrganisationName(self):
            return Attributes.str('Organisation name')

        @property
        def OrganisationSite(self):
            return Attributes.str('Organisation site')

        @property
        def OS(self):
            return Attributes.str('OS')

        @property
        def Password(self):
            return Attributes.str('Password')

        @property
        def PhoneNumber(self):
            return Attributes.str('Phone number')

        @property
        def Port(self):
            return Attributes.int('Port')

        @property
        def Postcode(self):
            return Attributes.str('Postcode')

        @property
        def PostsCount(self):
            return Attributes.int('Posts count')

        @property
        def Product(self):
            return Attributes.str('Product')

        @property
        def ProductionYear(self):
            return Attributes.int('Production year')

        @property
        def Protocol(self):
            return Attributes.str('Protocol')

        @property
        def Radius(self):
            return Attributes.float('Radius')

        @property
        def Region(self):
            return Attributes.str('Region')

        @property
        def RegistrationID(self):
            return Attributes.str('Registration ID')

        @property
        def RelationType(self):
            return Attributes.str('Relation type')

        @property
        def ResolveDate(self):
            return Attributes.dt('Resolve date')

        @property
        def ResponseCode(self):
            return Attributes.int('Response code')

        @property
        def Role(self):
            return Attributes.str('Role')

        @property
        def School(self):
            return Attributes.str('School')

        @property
        def Sensor(self):
            return Attributes.str('Sensor')

        @property
        def Service(self):
            return Attributes.str('Service')

        @property
        def Sex(self):
            return Attributes.str('Sex')

        @property
        def SizeInBytes(self):
            return Attributes.int('Size in bytes')

        @property
        def State(self):
            return Attributes.str('State')

        @property
        def Subject(self):
            return Attributes.str('Subject')

        @property
        def Surname(self):
            return Attributes.str('Surname')

        @property
        def Tag(self):
            return Attributes.str('Tag')

        @property
        def Telco(self):
            return Attributes.str('Telco')

        @property
        def TelegramID(self):
            return Attributes.str('Telegram ID')

        @property
        def Text(self):
            return Attributes.str('Text')

        @property
        def ThreatName(self):
            return Attributes.str('Threat name')

        @property
        def Timestamp(self):
            return Attributes.int('Timestamp')

        @property
        def TimestampString(self):
            return Attributes.str('Timestamp string')

        @property
        def Title(self):
            return Attributes.str('Title')

        @property
        def Transmission(self):
            return Attributes.str('Transmission')

        @property
        def TransportLayerProtocol(self):
            return Attributes.str('Transport layer protocol')

        @property
        def TwitterID(self):
            return Attributes.str('Twitter ID')

        @property
        def UID(self):
            return Attributes.str('UID')

        @property
        def UIDInteger(self):
            return Attributes.int('UID integer')

        @property
        def University(self):
            return Attributes.str('University')

        @property
        def URL(self):
            return Attributes.str('URL')

        @property
        def Username(self):
            return Attributes.str('Username')

        @property
        def Value(self):
            return Attributes.str('Value')

        @property
        def Version(self):
            return Attributes.str('Version')

        @property
        def VIN(self):
            return Attributes.str('VIN')

        @property
        def VoIP(self):
            return Attributes.str('VoIP')

        @property
        def WebInfo(self):
            return Attributes.str('Web info')

        @property
        def Work(self):
            return Attributes.str('Work')

        @property
        def WorkEndDate(self):
            return Attributes.dt('Work end date')

        @property
        def WorkStartDate(self):
            return Attributes.dt('Work start date')


    # region Internal methods
    def generate(self, name, vtype):
        if not name:
            raise Exception('Attribute name can\'t be empty')

        if name in self.__attr_types and vtype != self.__attr_types[name]:
                raise Exception(f'Attribute {name} redeclared with different type')
        else:
            self.__attr_types[name] = vtype
        return lighthouse.Attribute(name, vtype)  # must be always new instance

    def str(self, name):
        return self.generate(name, lighthouse.ValueType.String)

    def int(self, name):
        return self.generate(name, lighthouse.ValueType.Integer)

    def float(self, name):
        return self.generate(name, lighthouse.ValueType.Float)

    def bool(self, name):
        return self.generate(name, lighthouse.ValueType.Boolean)

    def dt(self, name):
        return self.generate(name, lighthouse.ValueType.Datetime)
    # endregion


# usage:
# Attributes.System.Port
# Attributes.Comment
Attributes = AttributesProvider()

# endregion


# region Objects

class Abonent(metaclass=lighthouse.Object):
    name = 'Abonent'

    PhoneNumber = Attributes.System.PhoneNumber
    IMEI = Attributes.System.IMEI
    IMSI = Attributes.System.IMSI
    Region = Attributes.System.Region
    Credentials = Attributes.System.Credentials

    IdentAttrs = [PhoneNumber]

    CaptionAttrs = [PhoneNumber, Credentials]

class Address(metaclass=lighthouse.Object):
    name = 'Address'

    Address = Attributes.System.Address
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [Address, GeoPoint]

    CaptionAttrs = [Address]

class APT(metaclass=lighthouse.Object):
    name = 'APT'

    ThreatName = Attributes.System.ThreatName

    IdentAttrs = [ThreatName]

    CaptionAttrs = [ThreatName]

class AutonomousSystem(metaclass=lighthouse.Object):
    name = 'Autonomous system'

    ASN = Attributes.System.ASN

    IdentAttrs = [ASN]

    CaptionAttrs = [ASN]

class BaseStation(metaclass=lighthouse.Object):
    name = 'Base station'

    MCC = Attributes.System.MCC
    MNC = Attributes.System.MNC
    LAC = Attributes.System.LAC
    Cell = Attributes.System.Cell
    Telco = Attributes.System.Telco
    Address = Attributes.System.Address
    Azimuth = Attributes.System.Azimuth
    Radius = Attributes.System.Radius
    GeoPoint = Attributes.System.GeoPoint
    GeoLineString = Attributes.System.GeoLineString
    GeoPolygon = Attributes.System.GeoPolygon

    IdentAttrs = [MCC, MNC, LAC, Cell]

    CaptionAttrs = [LAC, Cell, Telco, Address, Azimuth]

class CallEvent(metaclass=lighthouse.Object):
    name = 'Call event'

    PhoneNumber = Attributes.System.PhoneNumber
    DateTime = Attributes.System.DateTime
    Duration = Attributes.System.Duration
    MCC = Attributes.System.MCC
    MNC = Attributes.System.MNC
    LAC = Attributes.System.LAC
    Cell = Attributes.System.Cell
    Telco = Attributes.System.Telco
    Address = Attributes.System.Address
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [PhoneNumber, DateTime, Duration, MCC, MNC, LAC, Cell]

    CaptionAttrs = [PhoneNumber, DateTime, Duration, LAC, Cell, Telco, Address]

class Camera(metaclass=lighthouse.Object):
    name = 'Camera'

    Sensor = Attributes.System.Sensor
    WebInfo = Attributes.System.WebInfo
    Address = Attributes.System.Address
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [Sensor]

    CaptionAttrs = [Sensor, WebInfo, Address]

class Car(metaclass=lighthouse.Object):
    name = 'Car'

    LicensePlateNumber = Attributes.System.LicensePlateNumber
    VIN = Attributes.System.VIN
    RegistrationID = Attributes.System.RegistrationID
    Manufacturer = Attributes.System.Manufacturer
    ProductionYear = Attributes.System.ProductionYear
    Brand = Attributes.System.Brand
    Model = Attributes.System.Model
    BodyStyle = Attributes.System.BodyStyle
    EngineType = Attributes.System.EngineType
    EnginePower = Attributes.System.EnginePower
    FuelType = Attributes.System.FuelType
    Driveline = Attributes.System.Driveline
    Transmission = Attributes.System.Transmission

    IdentAttrs = [LicensePlateNumber, VIN, RegistrationID]

    CaptionAttrs = [LicensePlateNumber, VIN]

class CarRecord(metaclass=lighthouse.Object):
    name = 'Car record'

    LicensePlateNumber = Attributes.System.LicensePlateNumber
    DateTime = Attributes.System.DateTime
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [LicensePlateNumber]

    CaptionAttrs = [LicensePlateNumber, DateTime]

class City(metaclass=lighthouse.Object):
    name = 'City'

    City = Attributes.System.City
    Country = Attributes.System.Country

    IdentAttrs = [City, Country]

    CaptionAttrs = [City]

class Country(metaclass=lighthouse.Object):
    name = 'Country'

    Country = Attributes.System.Country

    IdentAttrs = [Country]

    CaptionAttrs = [Country]

class Domain(metaclass=lighthouse.Object):
    name = 'Domain'

    Domain = Attributes.System.Domain

    IdentAttrs = [Domain]

    CaptionAttrs = [Domain]

class Email(metaclass=lighthouse.Object):
    name = 'Email'

    Email = Attributes.System.Email

    IdentAttrs = [Email]

    CaptionAttrs = [Email]

class Entity(metaclass=lighthouse.Object):
    name = 'Entity'

    Value = Attributes.System.Value

    IdentAttrs = [Value]

    CaptionAttrs = [Value]

class FacebookAccount(metaclass=lighthouse.Object):
    name = 'Facebook account'

    Credentials = Attributes.System.Credentials
    FacebookID = Attributes.System.FacebookID
    Username = Attributes.System.Username
    URL = Attributes.System.URL
    Country = Attributes.System.Country
    City = Attributes.System.City
    PhoneNumber = Attributes.System.PhoneNumber
    BirthdayString = Attributes.System.BirthdayString
    Sex = Attributes.System.Sex
    MaritalStatus = Attributes.System.MaritalStatus
    LastAppearance = Attributes.System.LastAppearance
    School = Attributes.System.School
    University = Attributes.System.University
    Work = Attributes.System.Work
    Occupation = Attributes.System.Occupation
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [FacebookID]

    CaptionAttrs = [Credentials, Username, URL]

class FlickrAccount(metaclass=lighthouse.Object):
    name = 'Flickr account'

    FlickrID = Attributes.System.FlickrID
    URL = Attributes.System.URL
    DateCreated = Attributes.System.DateCreated
    GeoPoint = Attributes.System.GeoPoint
    Bio = Attributes.System.Bio
    Username = Attributes.System.Username
    Credentials = Attributes.System.Credentials
    PostsCount = Attributes.System.PostsCount
    FollowersCount = Attributes.System.FollowersCount
    FollowingCount = Attributes.System.FollowingCount

    IdentAttrs = [FlickrID]

    CaptionAttrs = [URL, Username, Credentials]

class FoursquareAccount(metaclass=lighthouse.Object):
    name = 'Foursquare account'

    FoursquareID = Attributes.System.FoursquareID
    Credentials = Attributes.System.Credentials
    URL = Attributes.System.URL
    LocationString = Attributes.System.LocationString
    GeoPoint = Attributes.System.GeoPoint
    Sex = Attributes.System.Sex

    IdentAttrs = [FoursquareID, URL]

    CaptionAttrs = [Credentials, URL, LocationString, Sex]

class FTP(metaclass=lighthouse.Object):
    name = 'FTP'

    Domain = Attributes.System.Domain
    IPAddress = Attributes.System.IPAddress

    IdentAttrs = [Domain, IPAddress]

    CaptionAttrs = [Domain]

class GitHubAccount(metaclass=lighthouse.Object):
    name = 'GitHub account'

    Credentials = Attributes.System.Credentials
    Username = Attributes.System.Username
    URL = Attributes.System.URL

    IdentAttrs = [URL]

    CaptionAttrs = [Username, URL]

class Hash(metaclass=lighthouse.Object):
    name = 'Hash'

    Hash = Attributes.System.Hash
    HashingAlgorithm = Attributes.System.HashingAlgorithm

    IdentAttrs = [Hash, HashingAlgorithm]

    CaptionAttrs = [Hash, HashingAlgorithm]

class ICQAccount(metaclass=lighthouse.Object):
    name = 'ICQ account'

    Credentials = Attributes.System.Credentials
    ICQID = Attributes.System.ICQID
    URL = Attributes.System.URL
    BirthdayDate = Attributes.System.BirthdayDate

    IdentAttrs = [ICQID]

    CaptionAttrs = [Credentials, URL]

class IM(metaclass=lighthouse.Object):
    name = 'IM'

    UID = Attributes.System.UID
    Login = Attributes.System.Login
    Password = Attributes.System.Password
    IPAddress = Attributes.System.IPAddress

    IdentAttrs = [UID]

    CaptionAttrs = [UID]

class IMEI(metaclass=lighthouse.Object):
    name = 'IMEI'

    IMEI = Attributes.System.IMEI

    IdentAttrs = [IMEI]

    CaptionAttrs = [IMEI]

class IMSI(metaclass=lighthouse.Object):
    name = 'IMSI'

    IMSI = Attributes.System.IMSI

    IdentAttrs = [IMSI]

    CaptionAttrs = [IMSI]

class IPAddress(metaclass=lighthouse.Object):
    name = 'IP address'

    IPAddress = Attributes.System.IPAddress

    IdentAttrs = [IPAddress]

    CaptionAttrs = [IPAddress]

class LinkedInAccount(metaclass=lighthouse.Object):
    name = 'LinkedIn account'

    LinkedInID = Attributes.System.LinkedInID
    Credentials = Attributes.System.Credentials
    Username = Attributes.System.Username
    OrganisationName = Attributes.System.OrganisationName
    OrganisationSite = Attributes.System.OrganisationSite
    Occupation = Attributes.System.Occupation
    LocationString = Attributes.System.LocationString
    GeoPoint = Attributes.System.GeoPoint
    URL = Attributes.System.URL

    IdentAttrs = [URL]

    CaptionAttrs = [Credentials, OrganisationName, URL]

class Location(metaclass=lighthouse.Object):
    name = 'Location'

    LocationString = Attributes.System.LocationString
    Address = Attributes.System.Address
    City = Attributes.System.City
    State = Attributes.System.State
    Postcode = Attributes.System.Postcode
    Country = Attributes.System.Country
    CountryCode = Attributes.System.CountryCode
    Latitude = Attributes.System.Latitude
    Longitude = Attributes.System.Longitude
    GeoPoint = Attributes.System.GeoPoint
    GeoPolygon = Attributes.System.GeoPolygon
    Geohash = Attributes.System.Geohash

    IdentAttrs = [LocationString, Address, City, State, Postcode, Country, Latitude, Longitude, GeoPoint, Geohash]

    CaptionAttrs = [LocationString, Address]

class MyspaceAccount(metaclass=lighthouse.Object):
    name = 'Myspace account'

    Credentials = Attributes.System.Credentials
    Username = Attributes.System.Username
    GeoPoint = Attributes.System.GeoPoint
    URL = Attributes.System.URL

    IdentAttrs = [URL]

    CaptionAttrs = [Credentials, URL]

class NetworkInterface(metaclass=lighthouse.Object):
    name = 'Network interface'

    IPAddress = Attributes.System.IPAddress
    MACAddress = Attributes.System.MACAddress

    IdentAttrs = [IPAddress, MACAddress]

    CaptionAttrs = [IPAddress]

class Organisation(metaclass=lighthouse.Object):
    name = 'Organisation'

    OrganisationName = Attributes.System.OrganisationName

    IdentAttrs = [OrganisationName]

    CaptionAttrs = [OrganisationName]

class Person(metaclass=lighthouse.Object):
    name = 'Person'

    Name = Attributes.System.Name
    Surname = Attributes.System.Surname
    MiddleName = Attributes.System.MiddleName
    Credentials = Attributes.System.Credentials
    Document = Attributes.System.Document
    Sex = Attributes.System.Sex
    BirthdayDate = Attributes.System.BirthdayDate

    IdentAttrs = [Name, Surname, MiddleName, Credentials, BirthdayDate]

    CaptionAttrs = [Name, Surname, MiddleName, Credentials]

class Phone(metaclass=lighthouse.Object):
    name = 'Phone'

    PhoneNumber = Attributes.System.PhoneNumber
    IMEI = Attributes.System.IMEI
    IMSI = Attributes.System.IMSI

    IdentAttrs = [PhoneNumber, IMEI, IMSI]

    CaptionAttrs = [PhoneNumber]

class PhoneBook(metaclass=lighthouse.Object):
    name = 'Phone book'

    PhoneNumber = Attributes.System.PhoneNumber
    Credentials = Attributes.System.Credentials
    Name = Attributes.System.Name
    Surname = Attributes.System.Surname
    Country = Attributes.System.Country
    City = Attributes.System.City
    Carrier = Attributes.System.Carrier

    IdentAttrs = [PhoneNumber, Credentials]

    CaptionAttrs = [PhoneNumber, Credentials]

class PhoneNumber(metaclass=lighthouse.Object):
    name = 'Phone number'

    PhoneNumber = Attributes.System.PhoneNumber

    IdentAttrs = [PhoneNumber]

    CaptionAttrs = [PhoneNumber]

class Point(metaclass=lighthouse.Object):
    name = 'Point'

    Value = Attributes.System.Value
    Address = Attributes.System.Address
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [Value, GeoPoint]

    CaptionAttrs = [Value]

class Port(metaclass=lighthouse.Object):
    name = 'Port'

    Port = Attributes.System.Port

    IdentAttrs = [Port]

    CaptionAttrs = [Port]

class ResolvedDomain(metaclass=lighthouse.Object):
    name = 'Resolved domain'

    Domain = Attributes.System.Domain
    IPAddress = Attributes.System.IPAddress

    IdentAttrs = [Domain]

    CaptionAttrs = [Domain]

class School(metaclass=lighthouse.Object):
    name = 'School'

    School = Attributes.System.School

    IdentAttrs = [School]

    CaptionAttrs = [School]

class SkypeAccount(metaclass=lighthouse.Object):
    name = 'Skype account'

    Login = Attributes.System.Login
    Name = Attributes.System.Name
    URL = Attributes.System.URL

    IdentAttrs = [Login]

    CaptionAttrs = [Login, Name]

class TelegramAccount(metaclass=lighthouse.Object):
    name = 'Telegram account'

    TelegramID = Attributes.System.TelegramID
    Name = Attributes.System.Name
    Surname = Attributes.System.Surname
    PhoneNumber = Attributes.System.PhoneNumber
    Username = Attributes.System.Username
    Bio = Attributes.System.Bio
    LastAppearance = Attributes.System.LastAppearance

    IdentAttrs = [TelegramID]

    CaptionAttrs = [TelegramID, Name, Surname, Username]

class TrackedEmail(metaclass=lighthouse.Object):
    name = 'Tracked email'

    Email = Attributes.System.Email
    IPAddress = Attributes.System.IPAddress

    IdentAttrs = [Email]

    CaptionAttrs = [Email]

class TwitterAccount(metaclass=lighthouse.Object):
    name = 'Twitter account'

    Credentials = Attributes.System.Credentials
    Username = Attributes.System.Username
    LocationString = Attributes.System.LocationString
    DateCreated = Attributes.System.DateCreated
    TwitterID = Attributes.System.TwitterID
    URL = Attributes.System.URL
    Bio = Attributes.System.Bio
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [Username, TwitterID]

    CaptionAttrs = [Credentials, URL]

class University(metaclass=lighthouse.Object):
    name = 'University'

    University = Attributes.System.University

    IdentAttrs = [University]

    CaptionAttrs = [University]

class URL(metaclass=lighthouse.Object):
    name = 'URL'

    URL = Attributes.System.URL

    IdentAttrs = [URL]

    CaptionAttrs = [URL]

class VoIP(metaclass=lighthouse.Object):
    name = 'VoIP'

    VoIP = Attributes.System.VoIP
    IPAddress = Attributes.System.IPAddress

    IdentAttrs = [VoIP]

    CaptionAttrs = [VoIP]

class Webcam(metaclass=lighthouse.Object):
    name = 'Webcam'

    IPAddress = Attributes.System.IPAddress
    Port = Attributes.System.Port
    Address = Attributes.System.Address
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [IPAddress, Port]

    CaptionAttrs = [IPAddress, Port, Address]

class WhatsAppAccount(metaclass=lighthouse.Object):
    name = 'WhatsApp account'

    PhoneNumber = Attributes.System.PhoneNumber
    LastAppearance = Attributes.System.LastAppearance

    IdentAttrs = [PhoneNumber]

    CaptionAttrs = [PhoneNumber]

class Work(metaclass=lighthouse.Object):
    name = 'Work'

    Work = Attributes.System.Work
    LocationString = Attributes.System.LocationString
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [Work]

    CaptionAttrs = [Work]


# endregion


# region Links

class AbonentToBaseStation(metaclass=lighthouse.Link):
    name = 'Abonent → Base station'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = Abonent
    End = BaseStation

class AbonentToIMEI(metaclass=lighthouse.Link):
    name = 'Abonent → IMEI'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = Abonent
    End = IMEI

class AbonentToIMSI(metaclass=lighthouse.Link):
    name = 'Abonent → IMSI'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = Abonent
    End = IMSI

class Accordance(metaclass=lighthouse.Link):
    name = 'Accordance'

    Begin = Entity
    End = Entity

class AddressToPerson(metaclass=lighthouse.Link):
    name = 'Address → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Address
    End = Person

class AddressToSchool(metaclass=lighthouse.Link):
    name = 'Address → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Address
    End = School

class AddressToUniversity(metaclass=lighthouse.Link):
    name = 'Address → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Address
    End = University

class AddressToWork(metaclass=lighthouse.Link):
    name = 'Address → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Address
    End = Work

class AutonomousSystemToOrganisation(metaclass=lighthouse.Link):
    name = 'Autonomous system → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = AutonomousSystem
    End = Organisation

class AutonomousSystemToSchool(metaclass=lighthouse.Link):
    name = 'Autonomous system → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = AutonomousSystem
    End = School

class AutonomousSystemToUniversity(metaclass=lighthouse.Link):
    name = 'Autonomous system → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = AutonomousSystem
    End = University

class AutonomousSystemToWork(metaclass=lighthouse.Link):
    name = 'Autonomous system → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = AutonomousSystem
    End = Work

class Call(metaclass=lighthouse.Link):
    name = 'Call'
    DateTime = Attributes.System.DateTime
    Duration = Attributes.System.Duration

    CaptionAttrs = [DateTime]

    Begin = Abonent
    End = Abonent

class CallEventToAddress(metaclass=lighthouse.Link):
    name = 'Call event → Address'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = CallEvent
    End = Address

class CallEventToAPT(metaclass=lighthouse.Link):
    name = 'Call event → APT'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = CallEvent
    End = APT

class CallEventToBaseStation(metaclass=lighthouse.Link):
    name = 'Call event → Base station'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = CallEvent
    End = BaseStation

class CallEventToEmail(metaclass=lighthouse.Link):
    name = 'Call event → Email'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = CallEvent
    End = Email

class CallEventToEntity(metaclass=lighthouse.Link):
    name = 'Call event → Entity'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = CallEvent
    End = Entity

class CallEventToLocation(metaclass=lighthouse.Link):
    name = 'Call event → Location'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = CallEvent
    End = Location

class CallEventToPerson(metaclass=lighthouse.Link):
    name = 'Call event → Person'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = CallEvent
    End = Person

class CallEventToPhone(metaclass=lighthouse.Link):
    name = 'Call event → Phone'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = CallEvent
    End = Phone

class CallEventToPhoneNumber(metaclass=lighthouse.Link):
    name = 'Call event → Phone number'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = CallEvent
    End = PhoneNumber

class CarToCarRecord(metaclass=lighthouse.Link):
    name = 'Car → Car record'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Car
    End = CarRecord

class CarToOrganisation(metaclass=lighthouse.Link):
    name = 'Car → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Car
    End = Organisation

class CarToPerson(metaclass=lighthouse.Link):
    name = 'Car → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Car
    End = Person

class CityToCountry(metaclass=lighthouse.Link):
    name = 'City → Country'

    Begin = City
    End = Country

class Contact(metaclass=lighthouse.Link):
    name = 'Contact'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = Entity
    End = Entity

class DomainToDomain(metaclass=lighthouse.Link):
    name = 'Domain – Domain'
    RelationType = Attributes.System.RelationType

    CaptionAttrs = [RelationType]

    Begin = Domain
    End = Domain

class EmailToAPT(metaclass=lighthouse.Link):
    name = 'Email → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = APT

class EmailToDomain(metaclass=lighthouse.Link):
    name = 'Email → Domain'

    Begin = Email
    End = Domain

class EmailToEmail(metaclass=lighthouse.Link):
    name = 'Email – Email'

    Begin = Email
    End = Email

class EmailToEntity(metaclass=lighthouse.Link):
    name = 'Email → Entity'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = Entity

class EmailToFacebookAccount(metaclass=lighthouse.Link):
    name = 'Email → Facebook account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = FacebookAccount

class EmailToFlickrAccount(metaclass=lighthouse.Link):
    name = 'Email → Flickr account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = FlickrAccount

class EmailToFoursquareAccount(metaclass=lighthouse.Link):
    name = 'Email → Foursquare account'

    Begin = Email
    End = FoursquareAccount

class EmailToGitHubAccount(metaclass=lighthouse.Link):
    name = 'Email → GitHub account'

    Begin = Email
    End = GitHubAccount

class EmailToICQAccount(metaclass=lighthouse.Link):
    name = 'Email → ICQ account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = ICQAccount

class EmailToLinkedInAccount(metaclass=lighthouse.Link):
    name = 'Email → LinkedIn account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = LinkedInAccount

class EmailToMyspaceAccount(metaclass=lighthouse.Link):
    name = 'Email → Myspace account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = MyspaceAccount

class EmailToOrganisation(metaclass=lighthouse.Link):
    name = 'Email → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = Organisation

class EmailToPerson(metaclass=lighthouse.Link):
    name = 'Email → Person'

    Begin = Email
    End = Person

class EmailToPhoneLink(metaclass=lighthouse.Link):
    name = 'Email → Phone'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = Email
    End = Phone

class EmailToSchool(metaclass=lighthouse.Link):
    name = 'Email → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = School

class EmailToSkypeAccount(metaclass=lighthouse.Link):
    name = 'Email → Skype account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = SkypeAccount

class EmailToTelegramAccount(metaclass=lighthouse.Link):
    name = 'Email → Telegram account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = TelegramAccount

class EmailToTwitterAccount(metaclass=lighthouse.Link):
    name = 'Email → Twitter account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = TwitterAccount

class EmailToUniversity(metaclass=lighthouse.Link):
    name = 'Email → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = University

class EmailToWhatsAppAccount(metaclass=lighthouse.Link):
    name = 'Email → WhatsApp account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = WhatsAppAccount

class EmailToWork(metaclass=lighthouse.Link):
    name = 'Email → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Email
    End = Work

class EntityToEntity(metaclass=lighthouse.Link):
    name = 'Entity – Entity'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Entity
    End = Entity

class FacebookAccountToAPT(metaclass=lighthouse.Link):
    name = 'Facebook account → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FacebookAccount
    End = APT

class FacebookAccountToCountry(metaclass=lighthouse.Link):
    name = 'Facebook account → Country'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FacebookAccount
    End = Country

class FacebookAccountToFacebookAccount(metaclass=lighthouse.Link):
    name = 'Facebook account – Facebook account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FacebookAccount
    End = FacebookAccount

class FacebookAccountToLocation(metaclass=lighthouse.Link):
    name = 'Facebook account → Location'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FacebookAccount
    End = Location

class FacebookAccountToOrganisation(metaclass=lighthouse.Link):
    name = 'Facebook account → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FacebookAccount
    End = Organisation

class FacebookAccountToPerson(metaclass=lighthouse.Link):
    name = 'Facebook account → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FacebookAccount
    End = Person

class FacebookAccountToSchool(metaclass=lighthouse.Link):
    name = 'Facebook account → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FacebookAccount
    End = School

class FacebookAccountToUniversity(metaclass=lighthouse.Link):
    name = 'Facebook account → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FacebookAccount
    End = University

class FacebookAccountToWork(metaclass=lighthouse.Link):
    name = 'Facebook account → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FacebookAccount
    End = Work

class FlickrAccountToAPT(metaclass=lighthouse.Link):
    name = 'Flickr account → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FlickrAccount
    End = APT

class FlickrAccountToLocation(metaclass=lighthouse.Link):
    name = 'Flickr account → Location'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FlickrAccount
    End = Location

class FlickrAccountToOrganisation(metaclass=lighthouse.Link):
    name = 'Flickr account → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FlickrAccount
    End = Organisation

class FlickrAccountToPerson(metaclass=lighthouse.Link):
    name = 'Flickr account → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FlickrAccount
    End = Person

class FlickrAccountToSchool(metaclass=lighthouse.Link):
    name = 'Flickr account → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FlickrAccount
    End = School

class FlickrAccountToUniversity(metaclass=lighthouse.Link):
    name = 'Flickr account → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FlickrAccount
    End = University

class FlickrAccountToWork(metaclass=lighthouse.Link):
    name = 'Flickr account → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = FlickrAccount
    End = Work

class GitHubAccountToAPT(metaclass=lighthouse.Link):
    name = 'GitHub account → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = GitHubAccount
    End = APT

class GitHubAccountToLocation(metaclass=lighthouse.Link):
    name = 'GitHub account → Location'

    Begin = GitHubAccount
    End = Location

class GitHubAccountToOrganisation(metaclass=lighthouse.Link):
    name = 'GitHub account → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = GitHubAccount
    End = Organisation

class GitHubAccountToPerson(metaclass=lighthouse.Link):
    name = 'GitHub account → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = GitHubAccount
    End = Person

class GitHubAccountToSchool(metaclass=lighthouse.Link):
    name = 'GitHub account → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = GitHubAccount
    End = School

class GitHubAccountToUniversity(metaclass=lighthouse.Link):
    name = 'GitHub account → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = GitHubAccount
    End = University

class GitHubAccountToWork(metaclass=lighthouse.Link):
    name = 'GitHub account → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = GitHubAccount
    End = Work

class HashToAPT(metaclass=lighthouse.Link):
    name = 'Hash → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Hash
    End = APT

class HashToEmail(metaclass=lighthouse.Link):
    name = 'Hash → Email'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Hash
    End = Email

class HashToIPAddress(metaclass=lighthouse.Link):
    name = 'Hash → IP address'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = Hash
    End = IPAddress

class ICQAccountToAPT(metaclass=lighthouse.Link):
    name = 'ICQ account → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = ICQAccount
    End = APT

class ICQAccountToLocation(metaclass=lighthouse.Link):
    name = 'ICQ account → Location'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = ICQAccount
    End = Location

class ICQAccountToOrganisation(metaclass=lighthouse.Link):
    name = 'ICQ account → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = ICQAccount
    End = Organisation

class ICQAccountToPerson(metaclass=lighthouse.Link):
    name = 'ICQ account → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = ICQAccount
    End = Person

class ICQAccountToSchool(metaclass=lighthouse.Link):
    name = 'ICQ account → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = ICQAccount
    End = School

class ICQAccountToUniversity(metaclass=lighthouse.Link):
    name = 'ICQ account → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = ICQAccount
    End = University

class ICQAccountToWork(metaclass=lighthouse.Link):
    name = 'ICQ account → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = ICQAccount
    End = Work

class IMEIToAbonent(metaclass=lighthouse.Link):
    name = 'IMEI → Abonent'
    IMSI = Attributes.System.IMSI
    IMEIUsageBeginDate = Attributes.System.IMEIUsageBeginDate
    IMEIUsageEndDate = Attributes.System.IMEIUsageEndDate
    IMEIUsageCount = Attributes.System.IMEIUsageCount

    CaptionAttrs = [IMSI, IMEIUsageBeginDate, IMEIUsageEndDate, IMEIUsageCount]

    Begin = IMEI
    End = Abonent

class IMToIM(metaclass=lighthouse.Link):
    name = 'IM – IM'
    DateTime = Attributes.System.DateTime
    Protocol = Attributes.System.Protocol
    SizeInBytes = Attributes.System.SizeInBytes

    CaptionAttrs = [DateTime]

    Begin = IM
    End = IM

class IPAddressToAPT(metaclass=lighthouse.Link):
    name = 'IP address → APT'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = IPAddress
    End = APT

class IPAddressToAutonomousSystem(metaclass=lighthouse.Link):
    name = 'IP address → Autonomous system'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = AutonomousSystem

class IPAddressToCity(metaclass=lighthouse.Link):
    name = 'IP address → City'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = City

class IPAddressToCountry(metaclass=lighthouse.Link):
    name = 'IP address → Country'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = Country

class IPAddressToDomain(metaclass=lighthouse.Link):
    name = 'IP address → Domain'
    ResolveDate = Attributes.System.ResolveDate

    CaptionAttrs = [ResolveDate]

    Begin = IPAddress
    End = Domain

class IPAddressToEmail(metaclass=lighthouse.Link):
    name = 'IP address → Email'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = IPAddress
    End = Email

class IPAddressToEntity(metaclass=lighthouse.Link):
    name = 'IP address → Entity'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = Entity

class IPAddressToFacebookAccount(metaclass=lighthouse.Link):
    name = 'IP address → Facebook account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = FacebookAccount

class IPAddressToFlickrAccount(metaclass=lighthouse.Link):
    name = 'IP address → Flickr account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = FlickrAccount

class IPAddressToGitHubAccount(metaclass=lighthouse.Link):
    name = 'IP address → GitHub account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = GitHubAccount

class IPAddressToICQAccount(metaclass=lighthouse.Link):
    name = 'IP address → ICQ account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = ICQAccount

class IPAddressToIPAddress(metaclass=lighthouse.Link):
    name = 'IP address – IP address'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = IPAddress

class IPAddressToLinkedInAccount(metaclass=lighthouse.Link):
    name = 'IP address → LinkedIn account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = LinkedInAccount

class IPAddressToLocation(metaclass=lighthouse.Link):
    name = 'IP address → Location'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = IPAddress
    End = Location

class IPAddressToMyspaceAccount(metaclass=lighthouse.Link):
    name = 'IP address → Myspace account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = MyspaceAccount

class IPAddressToOrganisation(metaclass=lighthouse.Link):
    name = 'IP address → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = Organisation

class IPAddressToPerson(metaclass=lighthouse.Link):
    name = 'IP address → Person'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = IPAddress
    End = Person

class IPAddressToPhone(metaclass=lighthouse.Link):
    name = 'IP address → Phone'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = Phone

class IPAddressToSchool(metaclass=lighthouse.Link):
    name = 'IP address → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = School

class IPAddressToSkypeAccount(metaclass=lighthouse.Link):
    name = 'IP address → Skype account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = SkypeAccount

class IPAddressToTelegramAccount(metaclass=lighthouse.Link):
    name = 'IP address → Telegram account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = TelegramAccount

class IPAddressToTwitterAccount(metaclass=lighthouse.Link):
    name = 'IP address → Twitter account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = TwitterAccount

class IPAddressToUniversity(metaclass=lighthouse.Link):
    name = 'IP address → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = University

class IPAddressToURL(metaclass=lighthouse.Link):
    name = 'IP address → URL'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = URL

class IPAddressToWhatsAppAccount(metaclass=lighthouse.Link):
    name = 'IP address → WhatsApp account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = WhatsAppAccount

class IPAddressToWork(metaclass=lighthouse.Link):
    name = 'IP address → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = IPAddress
    End = Work

class LinkedInAccountToAPT(metaclass=lighthouse.Link):
    name = 'LinkedIn account → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = LinkedInAccount
    End = APT

class LinkedInAccountToLocation(metaclass=lighthouse.Link):
    name = 'LinkedIn account → Location'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = LinkedInAccount
    End = Location

class LinkedInAccountToOrganisation(metaclass=lighthouse.Link):
    name = 'LinkedIn account → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = LinkedInAccount
    End = Organisation

class LinkedInAccountToPerson(metaclass=lighthouse.Link):
    name = 'LinkedIn account → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = LinkedInAccount
    End = Person

class LinkedInAccountToSchool(metaclass=lighthouse.Link):
    name = 'LinkedIn account → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = LinkedInAccount
    End = School

class LinkedInAccountToUniversity(metaclass=lighthouse.Link):
    name = 'LinkedIn account → University'
    EntranceYear = Attributes.System.EntranceYear
    GraduationYear = Attributes.System.GraduationYear
    AcademicDegree = Attributes.System.AcademicDegree

    CaptionAttrs = [EntranceYear]

    Begin = LinkedInAccount
    End = University

class LinkedInAccountToWork(metaclass=lighthouse.Link):
    name = 'LinkedIn account → Work'
    WorkStartDate = Attributes.System.WorkStartDate
    WorkEndDate = Attributes.System.WorkEndDate

    CaptionAttrs = [WorkStartDate, WorkEndDate]

    Begin = LinkedInAccount
    End = Work

class MyspaceAccountToAPT(metaclass=lighthouse.Link):
    name = 'Myspace account → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = MyspaceAccount
    End = APT

class MyspaceAccountToLocation(metaclass=lighthouse.Link):
    name = 'Myspace account → Location'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = MyspaceAccount
    End = Location

class MyspaceAccountToOrganisation(metaclass=lighthouse.Link):
    name = 'Myspace account → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = MyspaceAccount
    End = Organisation

class MyspaceAccountToPerson(metaclass=lighthouse.Link):
    name = 'Myspace account → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = MyspaceAccount
    End = Person

class MyspaceAccountToSchool(metaclass=lighthouse.Link):
    name = 'Myspace account → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = MyspaceAccount
    End = School

class MyspaceAccountToUniversity(metaclass=lighthouse.Link):
    name = 'Myspace account → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = MyspaceAccount
    End = University

class MyspaceAccountToWork(metaclass=lighthouse.Link):
    name = 'Myspace account → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = MyspaceAccount
    End = Work

class NetworkInterfaceToAPT(metaclass=lighthouse.Link):
    name = 'Network interface → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = NetworkInterface
    End = APT

class NetworkInterfaceToFTP(metaclass=lighthouse.Link):
    name = 'Network interface → FTP'
    DateTime = Attributes.System.DateTime
    Protocol = Attributes.System.Protocol
    SizeInBytes = Attributes.System.SizeInBytes

    CaptionAttrs = [DateTime]

    Begin = NetworkInterface
    End = FTP

class NetworkInterfaceToIM(metaclass=lighthouse.Link):
    name = 'Network interface → IM'
    DateTime = Attributes.System.DateTime
    Protocol = Attributes.System.Protocol
    Port = Attributes.System.Port
    SizeInBytes = Attributes.System.SizeInBytes

    CaptionAttrs = [DateTime]

    Begin = NetworkInterface
    End = IM

class NetworkInterfaceToIPAddress(metaclass=lighthouse.Link):
    name = 'Network interface → IP address'
    DateTime = Attributes.System.DateTime
    Service = Attributes.System.Service
    SizeInBytes = Attributes.System.SizeInBytes

    CaptionAttrs = [DateTime]

    Begin = NetworkInterface
    End = IPAddress

class NetworkInterfaceToNetworkInterface(metaclass=lighthouse.Link):
    name = 'Network interface – Network interface'
    DateTime = Attributes.System.DateTime
    Service = Attributes.System.Service
    SizeInBytes = Attributes.System.SizeInBytes

    CaptionAttrs = [DateTime]

    Begin = NetworkInterface
    End = NetworkInterface

class NetworkInterfaceToOrganisation(metaclass=lighthouse.Link):
    name = 'Network interface → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = NetworkInterface
    End = Organisation

class NetworkInterfaceToPerson(metaclass=lighthouse.Link):
    name = 'Network interface → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = NetworkInterface
    End = Person

class NetworkInterfaceToResolvedDomain(metaclass=lighthouse.Link):
    name = 'Network interface → Resolved domain'
    DateTime = Attributes.System.DateTime
    Port = Attributes.System.Port
    URL = Attributes.System.URL

    CaptionAttrs = [DateTime]

    Begin = NetworkInterface
    End = ResolvedDomain

class NetworkInterfaceToSchool(metaclass=lighthouse.Link):
    name = 'Network interface → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = NetworkInterface
    End = School

class NetworkInterfaceToTrackedEmail(metaclass=lighthouse.Link):
    name = 'Network interface → Tracked email'
    DateTime = Attributes.System.DateTime
    Protocol = Attributes.System.Protocol
    Port = Attributes.System.Port
    SizeInBytes = Attributes.System.SizeInBytes

    CaptionAttrs = [DateTime]

    Begin = NetworkInterface
    End = TrackedEmail

class NetworkInterfaceToUniversity(metaclass=lighthouse.Link):
    name = 'Network interface → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = NetworkInterface
    End = University

class NetworkInterfaceToVoIP(metaclass=lighthouse.Link):
    name = 'Network interface → VoIP'
    DateTime = Attributes.System.DateTime
    Protocol = Attributes.System.Protocol
    Port = Attributes.System.Port

    CaptionAttrs = [DateTime]

    Begin = NetworkInterface
    End = VoIP

class NetworkInterfaceToWork(metaclass=lighthouse.Link):
    name = 'Network interface → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = NetworkInterface
    End = Work

class PersonToAbonent(metaclass=lighthouse.Link):
    name = 'Person → Abonent'
    AbonentContractDate = Attributes.System.AbonentContractDate

    CaptionAttrs = [AbonentContractDate]

    Begin = Person
    End = Abonent

class PersonToCity(metaclass=lighthouse.Link):
    name = 'Person → City'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Person
    End = City

class PersonToCountry(metaclass=lighthouse.Link):
    name = 'Person → Country'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Person
    End = Country

class PersonToLocation(metaclass=lighthouse.Link):
    name = 'Person → Location'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Person
    End = Location

class PhoneBookToEmail(metaclass=lighthouse.Link):
    name = 'Phone book → Email'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = Email

class PhoneBookToFacebookAccount(metaclass=lighthouse.Link):
    name = 'Phone book → Facebook account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = FacebookAccount

class PhoneBookToFlickrAccount(metaclass=lighthouse.Link):
    name = 'Phone book → Flickr account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = FlickrAccount

class PhoneBookToGitHubAccount(metaclass=lighthouse.Link):
    name = 'Phone book → GitHub account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = GitHubAccount

class PhoneBookToICQAccount(metaclass=lighthouse.Link):
    name = 'Phone book → ICQ account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = ICQAccount

class PhoneBookToLinkedInAccount(metaclass=lighthouse.Link):
    name = 'Phone book → LinkedIn account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = LinkedInAccount

class PhoneBookToMyspaceAccount(metaclass=lighthouse.Link):
    name = 'Phone book → Myspace account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = MyspaceAccount

class PhoneBookToOrganisation(metaclass=lighthouse.Link):
    name = 'Phone book → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = Organisation

class PhoneBookToPerson(metaclass=lighthouse.Link):
    name = 'Phone book → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = Person

class PhoneBookToPhone(metaclass=lighthouse.Link):
    name = 'Phone book → Phone'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = Phone

class PhoneBookToPhoneNumber(metaclass=lighthouse.Link):
    name = 'Phone book → Phone number'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = PhoneNumber

class PhoneBookToSkypeAccount(metaclass=lighthouse.Link):
    name = 'Phone book → Skype account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = SkypeAccount

class PhoneBookToTelegramAccount(metaclass=lighthouse.Link):
    name = 'Phone book → Telegram account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = TelegramAccount

class PhoneBookToTwitterAccount(metaclass=lighthouse.Link):
    name = 'Phone book → Twitter account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = TwitterAccount

class PhoneBookToWhatsAppAccount(metaclass=lighthouse.Link):
    name = 'Phone book → WhatsApp account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneBook
    End = WhatsAppAccount

class PhoneNumberToFacebookAccount(metaclass=lighthouse.Link):
    name = 'Phone number → Facebook account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = FacebookAccount

class PhoneNumberToFlickrAccount(metaclass=lighthouse.Link):
    name = 'Phone number → Flickr account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = FlickrAccount

class PhoneNumberToFoursquareAccount(metaclass=lighthouse.Link):
    name = 'Phone number → Foursquare account'

    Begin = PhoneNumber
    End = FoursquareAccount

class PhoneNumberToGitHubAccount(metaclass=lighthouse.Link):
    name = 'Phone number → GitHub account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = GitHubAccount

class PhoneNumberToICQAccount(metaclass=lighthouse.Link):
    name = 'Phone number → ICQ account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = ICQAccount

class PhoneNumberToIMEI(metaclass=lighthouse.Link):
    name = 'Phone number → IMEI'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = PhoneNumber
    End = IMEI

class PhoneNumberToIMSI(metaclass=lighthouse.Link):
    name = 'Phone number → IMSI'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = PhoneNumber
    End = IMSI

class PhoneNumberToLinkedInAccount(metaclass=lighthouse.Link):
    name = 'Phone number → LinkedIn account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = LinkedInAccount

class PhoneNumberToMyspaceAccount(metaclass=lighthouse.Link):
    name = 'Phone number → Myspace account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = MyspaceAccount

class PhoneNumberToOrganisation(metaclass=lighthouse.Link):
    name = 'Phone number → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = Organisation

class PhoneNumberToPerson(metaclass=lighthouse.Link):
    name = 'Phone number → Person'

    Begin = PhoneNumber
    End = Person

class PhoneNumberToPhoneNumber(metaclass=lighthouse.Link):
    name = 'Phone number – Phone number'

    Begin = PhoneNumber
    End = PhoneNumber

class PhoneNumberToSchool(metaclass=lighthouse.Link):
    name = 'Phone number → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = School

class PhoneNumberToSkypeAccount(metaclass=lighthouse.Link):
    name = 'Phone number → Skype account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = SkypeAccount

class PhoneNumberToTelegramAccount(metaclass=lighthouse.Link):
    name = 'Phone number → Telegram account'

    Begin = PhoneNumber
    End = TelegramAccount

class PhoneNumberToTwitterAccount(metaclass=lighthouse.Link):
    name = 'Phone number → Twitter account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = TwitterAccount

class PhoneNumberToUniversity(metaclass=lighthouse.Link):
    name = 'Phone number → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = University

class PhoneNumberToWhatsAppAccount(metaclass=lighthouse.Link):
    name = 'Phone number → WhatsApp account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = WhatsAppAccount

class PhoneNumberToWork(metaclass=lighthouse.Link):
    name = 'Phone number → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = PhoneNumber
    End = Work

class PhoneToBaseStation(metaclass=lighthouse.Link):
    name = 'Phone → Base station'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = Phone
    End = BaseStation

class PhoneToFacebookAccount(metaclass=lighthouse.Link):
    name = 'Phone → Facebook account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Phone
    End = FacebookAccount

class PhoneToFlickrAccount(metaclass=lighthouse.Link):
    name = 'Phone → Flickr account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Phone
    End = FlickrAccount

class PhoneToGitHubAccount(metaclass=lighthouse.Link):
    name = 'Phone → GitHub account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Phone
    End = GitHubAccount

class PhoneToICQAccount(metaclass=lighthouse.Link):
    name = 'Phone → ICQ account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Phone
    End = ICQAccount

class PhoneToIMEI(metaclass=lighthouse.Link):
    name = 'Phone → IMEI'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = Phone
    End = IMEI

class PhoneToIMSI(metaclass=lighthouse.Link):
    name = 'Phone → IMSI'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = Phone
    End = IMSI

class PhoneToLinkedInAccount(metaclass=lighthouse.Link):
    name = 'Phone → LinkedIn account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Phone
    End = LinkedInAccount

class PhoneToMyspaceAccount(metaclass=lighthouse.Link):
    name = 'Phone → Myspace account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Phone
    End = MyspaceAccount

class PhoneToPerson(metaclass=lighthouse.Link):
    name = 'Phone → Person'
    DateTime = Attributes.System.DateTime

    CaptionAttrs = [DateTime]

    Begin = Phone
    End = Person

class PhoneToPhone(metaclass=lighthouse.Link):
    name = 'Phone – Phone'
    DateTime = Attributes.System.DateTime
    Duration = Attributes.System.Duration

    CaptionAttrs = [DateTime]

    Begin = Phone
    End = Phone

class PhoneToSkypeAccount(metaclass=lighthouse.Link):
    name = 'Phone → Skype account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Phone
    End = SkypeAccount

class PhoneToTelegramAccount(metaclass=lighthouse.Link):
    name = 'Phone → Telegram account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Phone
    End = TelegramAccount

class PhoneToTwitterAccount(metaclass=lighthouse.Link):
    name = 'Phone → Twitter account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Phone
    End = TwitterAccount

class PhoneToWhatsAppAccount(metaclass=lighthouse.Link):
    name = 'Phone → WhatsApp account'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Phone
    End = WhatsAppAccount

class PortToIPAddress(metaclass=lighthouse.Link):
    name = 'Port → IP address'
    TransportLayerProtocol = Attributes.System.TransportLayerProtocol
    Product = Attributes.System.Product

    CaptionAttrs = [TransportLayerProtocol]

    Begin = Port
    End = IPAddress

class Relation(metaclass=lighthouse.Link):
    name = 'Relation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Entity
    End = Entity

class SkypeAccountToAPT(metaclass=lighthouse.Link):
    name = 'Skype account → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = SkypeAccount
    End = APT

class SkypeAccountToLocation(metaclass=lighthouse.Link):
    name = 'Skype account → Location'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = SkypeAccount
    End = Location

class SkypeAccountToOrganisation(metaclass=lighthouse.Link):
    name = 'Skype account → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = SkypeAccount
    End = Organisation

class SkypeAccountToPerson(metaclass=lighthouse.Link):
    name = 'Skype account → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = SkypeAccount
    End = Person

class SkypeAccountToSchool(metaclass=lighthouse.Link):
    name = 'Skype account → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = SkypeAccount
    End = School

class SkypeAccountToUniversity(metaclass=lighthouse.Link):
    name = 'Skype account → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = SkypeAccount
    End = University

class SkypeAccountToWork(metaclass=lighthouse.Link):
    name = 'Skype account → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = SkypeAccount
    End = Work

class TelegramAccountToAPT(metaclass=lighthouse.Link):
    name = 'Telegram account → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TelegramAccount
    End = APT

class TelegramAccountToLocation(metaclass=lighthouse.Link):
    name = 'Telegram account → Location'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TelegramAccount
    End = Location

class TelegramAccountToOrganisation(metaclass=lighthouse.Link):
    name = 'Telegram account → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TelegramAccount
    End = Organisation

class TelegramAccountToPerson(metaclass=lighthouse.Link):
    name = 'Telegram account → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TelegramAccount
    End = Person

class TelegramAccountToSchool(metaclass=lighthouse.Link):
    name = 'Telegram account → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TelegramAccount
    End = School

class TelegramAccountToUniversity(metaclass=lighthouse.Link):
    name = 'Telegram account → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TelegramAccount
    End = University

class TelegramAccountToWork(metaclass=lighthouse.Link):
    name = 'Telegram account → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TelegramAccount
    End = Work

class TrackedEmailToTrackedEmail(metaclass=lighthouse.Link):
    name = 'Tracked email – Tracked email'
    DateTime = Attributes.System.DateTime
    Subject = Attributes.System.Subject
    SizeInBytes = Attributes.System.SizeInBytes
    Protocol = Attributes.System.Protocol

    CaptionAttrs = [DateTime]

    Begin = TrackedEmail
    End = TrackedEmail

class TwitterAccountToAPT(metaclass=lighthouse.Link):
    name = 'Twitter account → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TwitterAccount
    End = APT

class TwitterAccountToLocation(metaclass=lighthouse.Link):
    name = 'Twitter account → Location'

    Begin = TwitterAccount
    End = Location

class TwitterAccountToOrganisation(metaclass=lighthouse.Link):
    name = 'Twitter account → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TwitterAccount
    End = Organisation

class TwitterAccountToPerson(metaclass=lighthouse.Link):
    name = 'Twitter account → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TwitterAccount
    End = Person

class TwitterAccountToSchool(metaclass=lighthouse.Link):
    name = 'Twitter account → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TwitterAccount
    End = School

class TwitterAccountToUniversity(metaclass=lighthouse.Link):
    name = 'Twitter account → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TwitterAccount
    End = University

class TwitterAccountToWork(metaclass=lighthouse.Link):
    name = 'Twitter account → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = TwitterAccount
    End = Work

class UniversityToLocation(metaclass=lighthouse.Link):
    name = 'University → Location'

    Begin = University
    End = Location

class URLToAPT(metaclass=lighthouse.Link):
    name = 'URL → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = URL
    End = APT

class URLToDomain(metaclass=lighthouse.Link):
    name = 'URL → Domain'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = URL
    End = Domain

class URLToOrganisation(metaclass=lighthouse.Link):
    name = 'URL → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = URL
    End = Organisation

class URLToPerson(metaclass=lighthouse.Link):
    name = 'URL → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = URL
    End = Person

class URLToSchool(metaclass=lighthouse.Link):
    name = 'URL → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = URL
    End = School

class URLToUniversity(metaclass=lighthouse.Link):
    name = 'URL → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = URL
    End = University

class URLToWork(metaclass=lighthouse.Link):
    name = 'URL → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = URL
    End = Work

class VoIPToVoIP(metaclass=lighthouse.Link):
    name = 'VoIP – VoIP'
    DateTime = Attributes.System.DateTime
    Duration = Attributes.System.Duration
    Protocol = Attributes.System.Protocol

    CaptionAttrs = [DateTime]

    Begin = VoIP
    End = VoIP

class WebcamToIPAddress(metaclass=lighthouse.Link):
    name = 'Webcam → IP address'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Webcam
    End = IPAddress

class WebcamToOrganisation(metaclass=lighthouse.Link):
    name = 'Webcam → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Webcam
    End = Organisation

class WebcamToPerson(metaclass=lighthouse.Link):
    name = 'Webcam → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Webcam
    End = Person

class WebcamToSchool(metaclass=lighthouse.Link):
    name = 'Webcam → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Webcam
    End = School

class WebcamToUniversity(metaclass=lighthouse.Link):
    name = 'Webcam → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Webcam
    End = University

class WebcamToWork(metaclass=lighthouse.Link):
    name = 'Webcam → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = Webcam
    End = Work

class WhatsAppAccountToAPT(metaclass=lighthouse.Link):
    name = 'WhatsApp account → APT'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = WhatsAppAccount
    End = APT

class WhatsAppAccountToLocation(metaclass=lighthouse.Link):
    name = 'WhatsApp account → Location'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = WhatsAppAccount
    End = Location

class WhatsAppAccountToOrganisation(metaclass=lighthouse.Link):
    name = 'WhatsApp account → Organisation'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = WhatsAppAccount
    End = Organisation

class WhatsAppAccountToPerson(metaclass=lighthouse.Link):
    name = 'WhatsApp account → Person'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = WhatsAppAccount
    End = Person

class WhatsAppAccountToSchool(metaclass=lighthouse.Link):
    name = 'WhatsApp account → School'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = WhatsAppAccount
    End = School

class WhatsAppAccountToUniversity(metaclass=lighthouse.Link):
    name = 'WhatsApp account → University'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = WhatsAppAccount
    End = University

class WhatsAppAccountToWork(metaclass=lighthouse.Link):
    name = 'WhatsApp account → Work'
    Value = Attributes.System.Value

    CaptionAttrs = [Value]

    Begin = WhatsAppAccount
    End = Work

class WorkToLocation(metaclass=lighthouse.Link):
    name = 'Work → Location'

    Begin = Work
    End = Location


# endregion
