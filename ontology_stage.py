from os.path import join as join_path


from lighthouse import *

ONTOLOGY_ID = '5f49b746-d8d0-4eb3-8793-57f3f3e902fa'
NAME = 'Stage ontology'


# region Constants
class Constants:
    # arrow for link names, e.g. "Domain → Email"
    RIGHTWARDS_ARROW = '\u2192'
    EN_DASH = '\u2013'

    class Methods:
        class Categories:
            INFO = 'Info'
            OSINT = 'OSINT'
            CYBER = 'Cyber Security'
            NET = 'Network Tools'
            MESSENGER = 'Messenger'
            SOCIAL_MEDIA = 'Social media'
            SERVICE = 'Service'
            GEO = 'Geographical'

        class LinksValues:
            VALUE = 'Value'

        # this is required for tasks to have coomon directory for any purpose for both desktop and remote execution
        # e.g., shodan images for nodes, caching vk avatars, dumping some debug logs, etc.
        CommonDirVariants = [r'D:\UserTasksFiles']

    class VitokInfo:
        REST_URL = 'http://10.50.3.52:8999/search'
        REST_TOKEN = 'bb7c153caf89fa7026120606add7480c'
        MAX_WORKERS = 4

    class Cyber:
        class Keys:
            SHODAN = '3kXU3QIhw13nhujR9ddxYaQDyqyMeOA7'
            VIRUSTOTAL = '0db35b5b44658b06832cc31063c78a9036b7719f7d5f9d7841093ead6484f2c6'
            CYMON = '63062e3129cf60f2a7dcb8797761e4b4a5bf2591'
            HYBRID_KEY = '0c4g0ow8g8cs80g4ksgg0wwokk8cckoo040csk8gkk4cc0wwcggcgs4gcg04ww04'
            HYBRID_SECRET = 'f9f08baf1658871966865e2e656a6d81302fae1c044635c7'
            AIPDB = '3pMjPjRaRMpX46b1DhN5sfvgn4Ni1pWPzhngaYlM'
            Google_Places_API = 'AIzaSyD1Uv_ufrqxwWhmQ2vuMlLesxsLn6P85X8'
            URLSCAN_API_KEY = 'eb29037e-fc87-434d-ae68-d13fd59db2fa'


# endregion


# region Helpers
class Utils(Utils):
    """
    extends functionality of user_task_base.Utils
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

    @classmethod
    def make_link_name(cls, begin: Object, end: Object):
        if begin.name == end.name:
            return f'{begin.name} {Constants.EN_DASH} {end.name}'
        return f'{begin.name} {Constants.RIGHTWARDS_ARROW} {end.name}'


# endregion


# region Attributes
class AttributesProvider:
    def __init__(self):
        self.__attr_types = {}
        self.System = self.__SystemAttrsProvider()

    # region Net & Cyber

    # region databases and software
    @property
    def DBName(self):
        return self.str('DB Name')

    @property
    def CollectionName(self):
        return self.str('Collection Name')

    # region Elasticsearch DB

    @property
    def StorageSizeTotal(self):
        return Attributes.int('Storage size total')

    @property
    def StorageSizeUsed(self):
        return Attributes.int('Storage size used')

    @property
    def StorageSizeAvail(self):
        return Attributes.int('Storage size available')

    @property
    def HostRAMCurrent(self):
        return Attributes.int('Host RAM size (current)')

    @property
    def HostRAMAvail(self):
        return Attributes.int('Host RAM size (available)')

    @property
    def HostRAMMax(self):
        return Attributes.int('Host RAM size (max)')

    @property
    def HostCPUusage(self):
        return Attributes.int('Host CPU usage')

    @property
    def HostUptime(self):
        return Attributes.int('Host uptime')

    @property
    def HostUptimeStr(self):
        return Attributes.str('Host uptime (days)')

    @property
    def HostUptimeHours(self):
        return Attributes.int('Host uptime (hours)')

    @property
    def HostRole(self):
        return Attributes.str('Host role')

    @property
    def MasterNodeName(self):
        return self.str('Master node Name')

    @property
    def NodeName(self):
        return self.str('Node Name')

    @property
    def MasterNodeID(self):
        return self.str('Master node ID')

    @property
    def NodeID(self):
        return self.str('Node ID')

    @property
    def MasterNodeValue(self):
        return self.str('Node *master*')

    @property
    def IndexHealth(self):
        return self.str('Index health')

    @property
    def IndexStatus(self):
        return self.str('Index status')

    @property
    def IndexName(self):
        return self.str('Index Name')

    @property
    def IndexCountDocuments(self):
        return self.int('count documents')

    @property
    def IndexCountDeletedDocuments(self):
        return self.int('deleted documents')

    # endregion

    @property
    def Netblock(self):
        return self.str('Netblock')

    @property
    def Opts(self):
        return self.str('Opts')

    @property
    def SearchEngine(self):
        return self.str('Search engine')

    @property
    def Compromised(self):
        return self.bool('Compromised')

    @property
    def CPE(self):
        return self.str('CPE')

    @property
    def VTScanId(self):
        return self.str('VT scan id')

    @property
    def SectigoCertificateID(self):
        return self.str('Sectigo certificate ID')

    @property
    def Resource(self):
        return self.str('Resource')

    @property
    def Permalink(self):
        return self.str('Permalink')

    @property
    def VerboseMsg(self):
        return self.str('Verbose msg')

    @property
    def FilescanId(self):
        return self.str('Filescan id')

    @property
    def ParentUID(self):
        return self.str('Parent UID')

    @property
    def Owner(self):
        return self.str('Owner')

    @property
    def Issuer(self):
        return self.str('Issuer')

    @property
    def SerialNumber(self):
        return self.str('Serial number')

    @property
    def SSLSerialNumber(self):
        return self.str('SSL serial number')

    @property
    def ValidFrom(self):
        return self.dt('Valid from')

    @property
    def ValidUntil(self):
        return self.dt('Valid until')

    @property
    def PID(self):
        return self.int('PID')

    @property
    def Icon(self):
        return self.str('Icon')

    @property
    def AVPositives(self):
        return self.int('AV Positives')

    @property
    def AVTotal(self):
        return self.int('AV Total')

    @property
    def VTScanBy(self):
        return self.str('VT scanner')

    @property
    def VTScanDetected(self):
        return self.bool('VT Detected')

    @property
    def VTScanResult(self):
        return self.str('VT Scan result')

    @property
    def VTScanDetail(self):
        return self.str('VT Scan detail')

    @property
    def AbuseTypeID(self):
        return self.int('Abuse type id')

    @property
    def AbuseType(self):
        return self.str('Abuse type')

    @property
    def AbuseDescription(self):
        return self.str('Abuse description')

    @property
    def CymonSourceName(self):
        return self.str('Cymon source name')

    @property
    def HybridVerdict(self):
        return self.str('Hybrid verdict')

    @property
    def HybrydAVDetect(self):
        return self.int('Hybrid AV detect')

    @property
    def HybridThreatScore(self):
        return self.int('Hybrid threat score')

    @property
    def HybridThreatScoreStr(self):
        return self.str('Hybrid threat score str')

    @property
    def HybridVXFamily(self):
        return self.str('Hybrid VX family')

    @property
    def HybridEnvironmentId(self):
        return self.str('Hybrid environment Id')

    @property
    def HybridJobID(self):
        return self.str('Hybrid job Id')

    @property
    def HybridStartTime(self):
        return self.dt('Start time')

    @property
    def HybridSubmitName(self):
        return self.str('Hybrid submit name')

    @property
    def HybridEnvDesc(self):
        return self.str('Hybrid environment description')

    @property
    def HybridTypeShort(self):
        return self.str('Hybrid type short')

    @property
    def AVLabel(self):
        return self.str('AV Label')

    @property
    def DownloadAvailable(self):
        return self.bool('Download available')

    @property
    def MitreTactic(self):
        return self.str('Mitre tactic')

    @property
    def MitreTechnique(self):
        return self.str('Mitre technique')

    @property
    def MitreAttckId(self):
        return self.str('Mitre attck Id')

    @property
    def MitreAttckIdWiki(self):
        return self.str('Mitre attck Id Wiki')

    @property
    def MaliciousIdentifiersCount(self):
        return self.int('Malicious identifiers count')

    @property
    def MaliciousIdentifiers(self):
        return self.str('Malicious identifiers')

    @property
    def SuspiciousIdentifiersCount(self):
        return self.int('Suspicious identifiers count')

    @property
    def SuspiciousIdentifiers(self):
        return self.str('Suspicious identifiers')

    @property
    def InformativeIdentifiersCount(self):
        return self.int('Informative identifiers count')

    @property
    def InformativeIdentifiers(self):
        return self.str('Informative identifiers')

    @property
    def NormalizedPath(self):
        return self.str('Normalized path')

    @property
    def CommandLine(self):
        return self.str('Command line')

    @property
    def HIBPBreachName(self):
        return self.str('Breach name')

    @property
    def HIBPBreachedDomain(self):
        return self.str('Breached domain')

    @property
    def HIBPBreachDate(self):
        return self.dt('Breach date')

    @property
    def HIBPPwnCount(self):
        return self.int('Breach pwn count')

    @property
    def HIBPDescription(self):
        return self.str('Breach description')

    @property
    def HIBPDataClass(self):
        return self.str('Breach data class')

    @property
    def HIBPIsVerified(self):
        return self.bool('Breach verified')

    @property
    def HIBPIsFabricated(self):
        return self.bool('Breach fabricated')

    @property
    def HIBPIsSensitive(self):
        return self.bool('Breach sensitive')

    @property
    def HIBPIsActive(self):
        return self.bool('Breach active')

    @property
    def HIBPIsRetired(self):
        return self.bool('Breach retired')

    @property
    def HIBPIsSpamList(self):
        return self.bool('Breach spamlist')

    @property
    def HIBPLogoType(self):
        return self.str('Breach logo type')

    @property
    def PasteSource(self):
        return self.str('Paste Source')

    @property
    def PasteID(self):
        return self.str('Paste ID')

    @property
    def PasteEmailCount(self):
        return self.str('Paste email count')

    @property
    def FilePath(self):
        return self.str('File path')

    @property
    def SHA1(self):
        return self.str('SHA1')

    @property
    def SHA256(self):
        return self.str('SHA256')

    @property
    def MD5(self):
        return self.str('MD5')

    @property
    def RuntimeProcess(self):
        return self.str('Runtime process')

    # endregion

    @property
    def DateAndType(self):
        return self.str('Date and type')

    @property
    def Hidden(self):
        return self.bool('Hidden')

    @property
    def ExitPolicy(self):
        return self.str('Exit policy')

    @property
    def AutonomousSystemName(self):
        return self.str('Autonomous system name')

    @property
    def Contact(self):
        return self.str('Contact')

    @property
    def OSFingerprint(self):
        return self.str('OS fingerprint')

    @property
    def Running(self):
        return self.bool('Running')

    @property
    def NotBefore(self):
        return self.dt('Not before')

    @property
    def NotAfter(self):
        return self.dt('Not after')

    @property
    def Vendor(self):
        return self.str('Vendor')

    @property
    def CVE(self):
        return self.str('CVE')

    @property
    def CVSS(self):
        return self.float('CVSS')

    @property
    def Vector(self):
        return self.str('Vector')

    @property
    def References(self):
        return self.str('References')

    @property
    def SignatureAlgorithm(self):
        return self.str('Signature algorithm')

    @property
    def SubjectCN(self):
        return self.str('Subject common name')

    @property
    def SubjectOU(self):
        return self.str('Subject organisational unit')

    @property
    def SubjectO(self):
        return self.str('Subject organisation')

    @property
    def SubjectL(self):
        return self.str('Subject location')

    @property
    def SubjectC(self):
        return self.str('Subject country code')

    @property
    def Issued(self):
        return self.dt('Issued')

    @property
    def Expires(self):
        return self.dt('Expires')

    @property
    def Expired(self):
        return self.bool('Expired')

    @property
    def FingerprintSHA1(self):
        return self.str('Fingerprint SHA1')

    @property
    def FingerprintSHA256(self):
        return self.str('Fingerprint SHA256')

    @property
    def IssuerCN(self):
        return self.str('Issuer common name')

    @property
    def IssuerC(self):
        return self.str('Issuer country code')

    @property
    def IssuerO(self):
        return self.str('Issuer organisation')

    @property
    def IssuerOU(self):
        return self.str('Issuer organisational unit')

    @property
    def IssuerST(self):
        return self.str('Issuer state')

    @property
    def IssuerL(self):
        return self.str('Issuer location')
    # endregion

    # region OSINT commons
    @property
    def CardNumber(self):
        return self.str('Card number')

    @property
    def CardLevel(self):
        return self.str('Card level')

    @property
    def Bank(self):
        return self.str('Bank')

    @property
    def BIN(self):
        return self.int('BIN')

    @property
    def VKID(self):
        return self.str('VK ID')

    @property
    def StravaID(self):
        return self.str('Strava ID')

    @property
    def StravaActivityID(self):
        return self.str('Strava activity ID')

    @property
    def OdnoklassnikiID(self):
        return self.str('Odnoklassniki ID')

    @property
    def CompanyName(self):
        return self.str('Company name')

    @property
    def CompanyStatus(self):
        return self.str('Company status')

    @property
    def CompanyNumber(self):
        return self.str('Company number')

    @property
    def Bio(self):
        return self.str('Bio')

    @property
    def PostsCount(self):
        return self.int('Posts count')

    @property
    def FollowersCount(self):
        return self.int('Followers count')

    @property
    def FollowingCount(self):
        return self.int('Following count')

    @property
    def InstagramID(self):
        return self.str('Instagram ID')

    @property
    def DeezerID(self):
        return self.str('Deezer ID')

    # endregion

    @property
    def Verified(self):
        return self.bool('Verified')

    @property
    def ResidenceCountry(self):
        return self.str('Country of residence')

    @property
    def Nationality(self):
        return self.str('Nationality')

    @property
    def BirthYear(self):
        return self.int('Birth year')

    @property
    def AppointedOn(self):
        return self.dt('Appointed on')

    @property
    def CompanieshouseID(self):
        return self.str('Companieshouse ID')

    @property
    def CompanyID(self):
        return self.str('Company ID')

    @property
    def OfficerID(self):
        return self.str('Officer ID')

    @property
    def WalletAddress(self):
        return self.str('Wallet address')

    @property
    def TotalCoinsReceived(self):
        return self.float('Total coins received')

    @property
    def TotalCoinsSent(self):
        return self.float('Total coins sent')

    @property
    def Balance(self):
        return self.float('Balance')

    @property
    def TransactionCount(self):
        return self.int('Transaction count')

    @property
    def TransactionHash(self):
        return self.str('Transaction hash')

    @property
    def TransactionAmount(self):
        return self.float('Transaction amount')

    @property
    def InputScript(self):
        return self.str('Input script')

    @property
    def OutScript(self):
        return self.str('Out script')

    @property
    def BitbucketTeam(self):
        return self.bool('Bitbucket team')

    @property
    def Subdomain(self):
        return self.str('Subdomain')

    @property
    def WikipediaUserID(self):
        return self.str('Wikipedia user Id')

    @property
    def BytesChanged(self):
        return self.str('Bytes changed')

    @property
    def DateOfCompletion(self):
        return self.str('Date of completion')

    @property
    def HTTPMethod(self):
        return self.str('HTTP Method')

    @property
    def StatusCode(self):
        return self.int('Status code')

    @property
    def QueryString(self):
        return self.str('Query string')

    @property
    def WebDataType(self):
        return self.str('Web data type')

    @property
    def DataType(self):
        return self.str('Data type')

    @property
    def Confidence(self):
        return self.int('Confidence')

    @property
    def Category(self):
        return self.str('Category')

    @property
    def ProjectName(self):
        return self.str('Project name')

    @property
    def ProjectURL(self):
        return self.str('Project URL')

    @property
    def LearningLanguage(self):
        return self.str('Learning language')

    @property
    def LinkedinCompanyId(self):
        return self.str('Linkedin company id')

    @property
    def LinkedinCompanyUrl(self):
        return self.str('Linkedin company URL')

    @property
    def LinkedinCompanyName(self):
        return self.str('Linkedin company name')

    class __SystemAttrsProvider:
        @property
        def Emptiness(self):
            return Attributes.str('Emptiness')

        @property
        def UID(self):
            return Attributes.str('UID')

        @property
        def UIDInt(self):
            return Attributes.int('UID integer')

        @property
        def Comment(self):
            return Attributes.str('Comment')

        @property
        def Title(self):
            return Attributes.str('Title')

        @property
        def Description(self):
            return Attributes.str('Description')

        @property
        def Tag(self):
            return Attributes.str('Tag')

        @property
        def Info(self):
            return Attributes.str('Info')

        @property
        def Data(self):
            return Attributes.str('Data')

        @property
        def Text(self):
            return Attributes.str('Text')

        @property
        def RelationType(self):
            return Attributes.str('Relation type')  # universal - how one entity related to another

        @property
        def Datetime(self):
            return Attributes.dt('Datetime')  # system datetime attr

        @property
        def DateString(self):
            return Attributes.str('Date string')

        @property
        def Timestamp(self):
            return Attributes.int('Timestamp')

        @property
        def TimestampStr(self):
            return Attributes.str('Timestamp string')

        @property
        def Birthday(self):
            return Attributes.dt('Birthday date')

        @property
        def BirthdayStr(self):
            return Attributes.str('Birthday string')

        @property
        def Duration(self):
            return Attributes.int('Duration')

        @property
        def Value(self):
            return Attributes.str('Value')  # system value attr

        @property
        def Count(self):
            return Attributes.int('Count')  # count of something

        @property
        def Number(self):
            return Attributes.int('Number')  # ordinal number of something

        @property
        def DateCreated(self):
            return Attributes.dt('Date created')

        @property
        def Product(self):
            return Attributes.str('Product')

        @property
        def Version(self):
            return Attributes.str('Version')

        @property
        def LastAppearance(self):
            return Attributes.dt('Last appearance')  # common attr

        @property
        def FirstAppearance(self):
            return Attributes.dt('First appearance')  # common attr

        @property
        def OS(self):
            return Attributes.str('OS')  # operating system

        @property
        def TransportLayerProto(self):
            return Attributes.str('Transport layer protocol')  # tcp/udp

        @property
        def AppLayerProto(self):
            return Attributes.str('Application layer protocol')  # http, ftp, etc.

        @property
        def IPAddress(self):
            return Attributes.str('IP address')

        @property
        def IPAndPort(self):
            return Attributes.str('IP and port')

        @property
        def IPInteger(self):
            return Attributes.int('IP integer')

        @property
        def ISP(self):
            return Attributes.str('ISP')  # internet service provider

        @property
        def Port(self):
            return Attributes.int('Port')

        @property
        def MacAddress(self):
            return Attributes.str('MAC address')

        @property
        def ResponseCode(self):
            return Attributes.int('Response code')

        @property
        def Domain(self):
            return Attributes.str('Domain')

        @property
        def Resolved(self):
            return Attributes.dt('Resolve date')  # when domain resolved

        @property
        def ASN(self):
            return Attributes.str('ASN')  # autonomous system number

        @property
        def DomainRegistrant(self):
            return Attributes.str('Domain registrant')

        @property
        def GeoPoint(self):
            return Attributes.str('Geo point')

        @property
        def GeoPolygon(self):
            return Attributes.str('Geo polygon')

        @property
        def GeoLineString(self):
            return Attributes.str('Geo line string')

        @property
        def Latitude(self):
            return Attributes.float('Latitude')

        @property
        def Longitude(self):
            return Attributes.float('Longitude')

        @property
        def Location(self):
            return Attributes.str('Location string')

        @property
        def Region(self):
            return Attributes.str('Region')

        @property
        def Country(self):
            return Attributes.str('Country')

        @property
        def CountryCode(self):
            return Attributes.str('Country code')

        @property
        def Geohash(self):
            return Attributes.str('Geohash')

        @property
        def City(self):
            return Attributes.str('City')

        @property
        def Address(self):
            return Attributes.str('Address')

        @property
        def URL(self):
            return Attributes.str('URL')

        @property
        def Email(self):
            return Attributes.str('Email')

        @property
        def PhoneNumber(self):
            return Attributes.str('Phone number')

        @property
        def IMEI(self):
            return Attributes.str('IMEI')

        @property
        def IMSI(self):
            return Attributes.str('IMSI')

        @property
        def Lac(self):
            return Attributes.int('LAC')

        @property
        def Cell(self):
            return Attributes.int('CELL')

        @property
        def Telco(self):
            return Attributes.str('TELCO')

        @property
        def Azimuth(self):
            return Attributes.float('Azimuth')

        @property
        def Carrier(self):
            return Attributes.str('Carrier')

        @property
        def Credentials(self):
            return Attributes.str('Credentials')  # surname, name, middlename

        @property
        def Name(self):
            return Attributes.str('Name')

        @property
        def Surname(self):
            return Attributes.str('Surname')

        @property
        def MiddleName(self):
            return Attributes.str('Middle name')

        @property
        def Login(self):
            return Attributes.str('Login')

        @property
        def Nickname(self):
            return Attributes.str('Nickname')

        @property
        def Sex(self):
            return Attributes.str('Sex')

        @property
        def University(self):
            return Attributes.str('University')

        @property
        def School(self):
            return Attributes.str('School')

        @property
        def Work(self):
            return Attributes.str('Work')

        @property
        def Occupation(self):
            return Attributes.str('Occupation')

        @property
        def Role(self):
            return Attributes.str('Role')

        @property
        def MaritalStatus(self):
            return Attributes.str('Marital status')

        @property
        def OrgName(self):
            return Attributes.str('Organisation name')

        @property
        def VIN(self):
            return Attributes.str('VIN')

        @property
        def LicensePlate(self):
            return Attributes.str('License plate number')

        @property
        def Manufacturer(self):
            return Attributes.str('Manufacturer')

        @property
        def Hash(self):
            return Attributes.str('Hash')

        @property
        def HashDigest(self):
            return Attributes.int('Hash integer')

        @property
        def HashAlgo(self):
            return Attributes.str('Hashing algorithm')

        @property
        def DateAccessed(self):
            return Attributes.dt('Date accessed')

        @property
        def DateModified(self):
            return Attributes.dt('Date modified')

        @property
        def Filename(self):
            return Attributes.str('Filename')

        @property
        def FileType(self):
            return Attributes.str('File type')

        @property
        def FileSize(self):
            return Attributes.int('File size')

        @property
        def ThreatName(self):
            return Attributes.str('Threat name')

        @property
        def FacebookID(self):
            return Attributes.str('Facebook id')

        @property
        def ICQID(self):
            return Attributes.str('Icq id')

        @property
        def TwitterID(self):
            return Attributes.str('Twitter id')

        @property
        def FlickrId(self):
            return Attributes.str('Flickr id')

        @property
        def TelegramId(self):
            return Attributes.str('Telegram id')

        @property
        def LinkedinId(self):
            return Attributes.str('Linkedin id')

        @property
        def CurrentWork(self):
            return Attributes.str('Current work')

        @property
        def OrganisationSite(self):
            return Attributes.str('Organisation site')

        @property
        def AcademicDegree(self):
            return Attributes.str('Academic degree')

        @property
        def EntranceYear(self):
            return Attributes.int('Entrance year')

        @property
        def GraduationYear(self):
            return Attributes.int('Graduation year')

        @property
        def WorkStartDate(self):
            return Attributes.dt('Work start date')

        @property
        def WorkEndDate(self):
            return Attributes.dt('Work end date')

        @property
        def Brand(self):
            return Attributes.str('Brand')

        @property
        def Model(self):
            return Attributes.str('Model')

        @property
        def BodyStyle(self):
            return Attributes.str('Body style')

        @property
        def EngineType(self):
            return Attributes.str('Engine type')

        @property
        def FuelType(self):
            return Attributes.str('Fuel type')

        @property
        def Driveline(self):
            return Attributes.str('Driveline')

        @property
        def Transmission(self):
            return Attributes.str('Transmission')

        @property
        def ProductionYear(self):
            return Attributes.int('Production year')

        @property
        def EnginePower(self):
            return Attributes.int('Engine power')

    # region Internal methods
    def generate(self, name, vtype):
        if not name:
            raise Exception('Attribute name can\'t be empty')

        if name in self.__attr_types and vtype != self.__attr_types[name]:
            raise Exception(f'Attribute {name} redeclared with different type')
        else:
            self.__attr_types[name] = vtype
        return Attribute(name, vtype)  # must be always new instance

    def str(self, name):
        return self.generate(name, ValueType.String)

    def int(self, name):
        return self.generate(name, ValueType.Integer)

    def float(self, name):
        return self.generate(name, ValueType.Float)

    def bool(self, name):
        return self.generate(name, ValueType.Boolean)

    def dt(self, name):
        return self.generate(name, ValueType.Datetime)
    # endregion


# usage:
# Attributes.System.Port
# Attributes.Comment
Attributes = AttributesProvider()


# endregion


# region Objects
# region System objects
class Entity(metaclass=Object):
    Value = Attributes.System.Value

    IdentAttrs = CaptionAttrs = [Value]


class Email(metaclass=Object):
    Email = Attributes.System.Email
    # IP = Attributes.System.IPAddress

    IdentAttrs = CaptionAttrs = [Email]


class Phone(metaclass=Object):
    Number = Attributes.System.PhoneNumber
    IMEI = Attributes.System.IMEI
    IMSI = Attributes.System.IMSI

    IdentAttrs = CaptionAttrs = [Number]


class Address(metaclass=Object):
    Address = Attributes.System.Address
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [Address, GeoPoint]
    CaptionAttrs = [Address]


class Location(metaclass=Object):
    Name = Attributes.System.Location
    City = Attributes.System.City
    Country = Attributes.System.Country
    CountryCode = Attributes.System.CountryCode
    Address = Attributes.System.Address
    Latitude = Attributes.System.Latitude
    Longitude = Attributes.System.Longitude
    GeoPoint = Attributes.System.GeoPoint
    Geohash = Attributes.System.Geohash

    IdentAttrs = [Name, City, Country, Latitude, Longitude, Geohash, GeoPoint]
    CaptionAttrs = [Name, Address]


class BaseStation(metaclass=Object):
    name = 'Base station'

    Lac = Attributes.System.Lac
    Cell = Attributes.System.Cell
    Telco = Attributes.System.Telco
    Address = Attributes.System.Address
    Azimuth = Attributes.System.Azimuth
    GeoPoint = Attributes.System.GeoPoint
    GeoPolygon = Attributes.System.GeoPolygon

    IdentAttrs = [Lac, Cell]
    CaptionAttrs = IdentAttrs + [Telco, Address, Azimuth]


class PhoneNumber(metaclass=Object):
    name = 'Phone number'

    Number = Attributes.System.PhoneNumber

    IdentAttrs = CaptionAttrs = [Number]


class IMEI(metaclass=Object):
    IMEI = Attributes.System.IMEI

    IdentAttrs = CaptionAttrs = [IMEI]


class IMSI(metaclass=Object):
    IMSI = Attributes.System.IMSI

    IdentAttrs = CaptionAttrs = [IMSI]


class CallEvent(metaclass=Object):
    name = 'Call event'

    PhoneNumber = Attributes.System.PhoneNumber
    DateTime = Attributes.System.Datetime
    Duration = Attributes.System.Duration
    Lac = Attributes.System.Lac
    Cell = Attributes.System.Cell
    Telco = Attributes.System.Telco
    Address = Attributes.System.Address
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [PhoneNumber, DateTime, Duration, Lac, Cell]
    CaptionAttrs = IdentAttrs + [Telco]


class Webcam(metaclass=Object):
    IPAddress = Attributes.System.IPAddress
    Port = Attributes.System.Port
    Address = Attributes.System.Address
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [IPAddress, Port]
    CaptionAttrs = IdentAttrs + [Address]


class Domain(metaclass=Object):
    Domain = Attributes.System.Domain
    # IP = Attributes.System.IPAddress

    IdentAttrs = CaptionAttrs = [Domain]


class Car(metaclass=Object):
    Plate = Attributes.System.LicensePlate
    VIN = Attributes.System.VIN
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

    IdentAttrs = CaptionAttrs = [VIN]


class CarRecord(metaclass=Object):
    name = 'Car record'

    Plate = Attributes.System.LicensePlate
    DateTime = Attributes.System.Datetime
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = CaptionAttrs = [Plate]


class Point(metaclass=Object):
    Value = Attributes.System.Value
    Address = Attributes.System.Address
    Point = Attributes.System.GeoPoint

    IdentAttrs = [Value, Point]
    CaptionAttrs = [Value]


class IP(metaclass=Object):
    name = 'IP'

    IP = Attributes.System.IPAddress

    IdentAttrs = CaptionAttrs = [IP]


class NetworkInterface(metaclass=Object):
    name = 'Network interface'

    IP = Attributes.System.IPAddress
    Mac = Attributes.System.MacAddress

    IdentAttrs = CaptionAttrs = [IP, Mac]


class URL(metaclass=Object):
    URL = Attributes.System.URL

    IdentAttrs = CaptionAttrs = [URL]


class Hash(metaclass=Object):
    Hash = Attributes.System.Hash
    Algo = Attributes.System.HashAlgo

    IdentAttrs = CaptionAttrs = [Hash, Algo]


class AutonomousSystem(metaclass=Object):
    name = 'Autonomous system'
    ASN = Attributes.System.ASN

    IdentAttrs = CaptionAttrs = [ASN]


class Port(metaclass=Object):
    Port = Attributes.System.Port

    IdentAttrs = CaptionAttrs = [Port]


class APT(metaclass=Object):
    ThreatName = Attributes.System.ThreatName

    IdentAttrs = CaptionAttrs = [ThreatName]


class Organisation(metaclass=Object):
    OrgName = Attributes.System.OrgName

    IdentAttrs = CaptionAttrs = [OrgName]


class City(metaclass=Object):
    City = Attributes.System.City
    Country = Attributes.System.Country

    IdentAttrs = [City, Country]
    CaptionAttrs = [City]


class School(metaclass=Object):
    School = Attributes.System.School

    IdentAttrs = [School]
    CaptionAttrs = [School]


class Country(metaclass=Object):
    Country = Attributes.System.Country

    IdentAttrs = CaptionAttrs = [Country]


class University(metaclass=Object):
    University = Attributes.System.University

    IdentAttrs = CaptionAttrs = [University]


class Work(metaclass=Object):
    Work = Attributes.System.Work
    Location = Attributes.System.Location
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = CaptionAttrs = [Work]


class Person(metaclass=Object):
    Name = Attributes.System.Name
    Surname = Attributes.System.Surname
    Middlename = Attributes.System.MiddleName
    Credentials = Attributes.System.Credentials

    IdentAttrs = CaptionAttrs = [Name, Surname, Middlename]


class SkypeAccount(metaclass=Object):
    name = 'Skype account'

    Login = Attributes.System.Login
    Fullname = Attributes.System.Name

    IdentAttrs = [Login]
    CaptionAttrs = [Login, Fullname]


class FacebookAccount(metaclass=Object):
    name = 'Facebook account'

    Credentials = Attributes.System.Credentials
    UID = Attributes.System.FacebookID
    Nickname = Attributes.System.Nickname
    URL = Attributes.System.URL
    Country = Attributes.System.Country
    City = Attributes.System.City
    Phone = Attributes.System.PhoneNumber
    BirthdayStr = Attributes.System.BirthdayStr
    Sex = Attributes.System.Sex
    MaritalStatus = Attributes.System.MaritalStatus
    LastAppearance = Attributes.System.LastAppearance
    School = Attributes.System.School
    University = Attributes.System.University
    Work = Attributes.System.Work
    Occupation = Attributes.System.Occupation
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [UID]
    CaptionAttrs = [Credentials, Nickname, URL]


class TelegramAccount(metaclass=Object):
    name = 'Telegram account'

    TelegramId = Attributes.System.TelegramId
    PhoneNumber = Attributes.System.PhoneNumber
    Credentials = Attributes.System.Credentials
    Nickname = Attributes.System.Nickname

    IdentAttrs = [PhoneNumber]
    CaptionAttrs = [Nickname, Credentials]


class WhatsappAccount(metaclass=Object):
    name = 'Whatsapp account'

    PhoneNumber = Attributes.System.PhoneNumber
    LastAppearance = Attributes.System.LastAppearance

    IdentAttrs = CaptionAttrs = [PhoneNumber]


class LinkedinAccount(metaclass=Object):
    name = 'Linkedin account'

    LinkedinId = Attributes.System.LinkedinId
    Credentials = Attributes.System.Credentials
    Organization = Attributes.System.OrgName
    OrganisationSite = Attributes.System.OrganisationSite
    Occupation = Attributes.System.Occupation
    Location = Attributes.System.Location
    Geopoint = Attributes.System.GeoPoint
    URL = Attributes.System.URL

    IdentAttrs = [URL]
    CaptionAttrs = [Credentials, Organization, URL]


class IcqAccount(metaclass=Object):
    name = 'Icq account'

    Credentials = Attributes.System.Credentials
    UID = Attributes.System.ICQID
    URL = Attributes.System.URL
    Birthday = Attributes.System.Birthday

    IdentAttrs = [UID]
    CaptionAttrs = [Credentials, URL]


class GooglePlusAccount(metaclass=Object):
    name = 'Googleplus account'

    Credentials = Attributes.System.Credentials
    Nickname = Attributes.System.Nickname
    URL = Attributes.System.URL

    IdentAttrs = [URL]
    CaptionAttrs = [Credentials, URL]


class FlickrAccount(metaclass=Object):
    name = 'Flickr account'

    FlickrId = Attributes.System.FlickrId
    Nickname = Attributes.System.Nickname
    URL = Attributes.System.URL
    DateCreated = Attributes.System.DateCreated

    IdentAttrs = CaptionAttrs = [Nickname, URL]


class FoursquareAccount(metaclass=Object):
    name = 'Foursquare account'

    Credentials = Attributes.System.Credentials
    URL = Attributes.System.URL
    Location = Attributes.System.Location
    Sex = Attributes.System.Sex

    IdentAttrs = [URL]
    CaptionAttrs = [Credentials, Location, Sex, URL]


class GithubAccount(metaclass=Object):
    name = 'Github account'

    Credentials = Attributes.System.Credentials
    Nickname = Attributes.System.Nickname
    URL = Attributes.System.URL

    IdentAttrs = [URL]
    CaptionAttrs = [Nickname, URL]


class TwitterAccount(metaclass=Object):
    name = 'Twitter account'

    Credentials = Attributes.System.Credentials
    Location = Attributes.System.Location
    Created = Attributes.System.DateCreated
    UID = Attributes.System.TwitterID
    URL = Attributes.System.URL

    IdentAttrs = [UID]
    CaptionAttrs = [Credentials, URL]


class MyspaceAccount(metaclass=Object):
    name = 'Myspace account'

    Credentials = Attributes.System.Credentials
    Nickname = Attributes.System.Nickname
    GeoPoint = Attributes.System.GeoPoint
    URL = Attributes.System.URL

    IdentAttrs = [URL]
    CaptionAttrs = [Credentials, URL]


class PhoneBook(metaclass=Object):
    name = 'Phone book'
    Firstname = Attributes.System.Name
    Lastname = Attributes.System.Surname
    Credentials = Attributes.System.Credentials
    Country = Attributes.System.Country
    City = Attributes.System.City
    Carrier = Attributes.System.Carrier

    IdentAttrs = []
    CaptionAttrs = [Credentials]


# endregion


# region OSINT

class GithubOrganization(metaclass=Object):
    name = 'Github organization'

    URL = Attributes.System.URL

    IdentAttrs = [URL]
    CaptionAttrs = [URL]
    Image = Utils.base64string(join_path('static/icons', 'github_organization.png'))

class EngCompany(metaclass=Object):
    name = 'British company'

    number = Attributes.CompanyNumber
    company_name = Attributes.CompanyName
    date_of_creation = Attributes.System.DateCreated
    status = Attributes.CompanyStatus
    address = Attributes.System.Address
    latitude = Attributes.System.Latitude
    longitude = Attributes.System.Longitude
    point = Attributes.System.GeoPoint

    IdentAttrs = [number]
    CaptionAttrs = [company_name]

    Image = Utils.base64string(join_path('static/icons', 'engcompany.png'))


class EngCompanyPerson(metaclass=Object):
    name = 'Person in british company'

    person_name = Attributes.System.Name
    number = Attributes.CompanyNumber
    appointed_on = Attributes.AppointedOn
    officer_role = Attributes.System.Role
    occupation = Attributes.System.Occupation
    country_of_residence = Attributes.ResidenceCountry
    nationality = Attributes.Nationality
    birthyear = Attributes.BirthYear
    address = Attributes.System.Address
    latitude = Attributes.System.Latitude
    longitude = Attributes.System.Longitude
    person_id = Attributes.CompanieshouseID
    point = Attributes.System.GeoPoint

    IdentAttrs = [person_id]
    CaptionAttrs = [person_name]

    Image = Utils.base64string(join_path('static/icons', 'engcompanyperson.png'))


class Company(metaclass=Object):
    name = 'Company'

    CompanyID = Attributes.CompanyID
    CompanyName = Attributes.CompanyName
    DateCreated = Attributes.System.DateCreated
    CompanyStatus = Attributes.CompanyStatus
    Address = Attributes.System.Address
    Country = Attributes.System.Country
    Latitude = Attributes.System.Latitude
    Longitude = Attributes.System.Longitude
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [CompanyID]
    CaptionAttrs = [CompanyName]

    Image = Utils.base64string(join_path('static/icons', 'company.png'))


class CompanyOfficer(metaclass=Object):
    name = 'Company officer'

    OfficerID = Attributes.OfficerID
    CompanyName = Attributes.CompanyName
    Role = Attributes.System.Role
    Address = Attributes.System.Address
    Latitude = Attributes.System.Latitude
    Longitude = Attributes.System.Longitude
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [OfficerID]
    CaptionAttrs = [CompanyName]

    Image = Utils.base64string(join_path('static/icons', 'company_officer.png'))

class AbstractUser(metaclass=Object):
    name = 'Abstract user'

    Nickname = Attributes.System.Nickname
    IdentAttrs = CaptionAttrs = [Nickname]

    Image = Utils.base64string(join_path('static/icons', 'abstract_person.png'))

class ViberAccount(metaclass=Object):
    name = 'Viber account'

    Credentials = Attributes.System.Credentials
    PhoneNumber = Attributes.System.PhoneNumber

    IdentAttrs = [PhoneNumber]
    CaptionAttrs = [Credentials]

    Image = Utils.base64string(join_path('static/icons', 'viber.png'))


class DeezerAccount(metaclass=Object):
    name = 'Deezer account'

    DeezerId = Attributes.DeezerID
    URL = Attributes.System.URL

    Nickname = Attributes.System.Nickname
    Sex = Attributes.System.Sex
    Birthday = Attributes.System.Birthday

    IdentAttrs = [DeezerId]
    CaptionAttrs = [Nickname, Sex, Birthday, URL]

    Image = Utils.base64string(join_path('static/icons', 'deezer.png'))


class FullcontactPersonInfo(metaclass=Object):
    name = 'Fullcontact person info'

    Name = Attributes.System.Name
    Surname = Attributes.System.Surname
    Credentials = Attributes.System.Credentials
    Bio = Attributes.Bio
    Sex = Attributes.System.Sex
    CompanyName = Attributes.CompanyName
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [Credentials]
    CaptionAttrs = [Credentials, Sex]

    Image = Utils.base64string(join_path('static/icons', 'fullcontact.png'))


class VivinoAccount(metaclass=Object):
    name = 'Vivino account'

    Credentials = Attributes.System.Credentials
    UID = Attributes.System.UID
    URL = Attributes.System.URL

    IdentAttrs = [UID]
    CaptionAttrs = [Credentials, URL]

    Image = Utils.base64string(join_path('static/icons', 'vivino.png'))


class DuolingoAccount(metaclass=Object):
    name = 'Duolingo account'

    Credentials = Attributes.System.Credentials
    URL = Attributes.System.URL
    LearningLanguage = Attributes.LearningLanguage

    IdentAttrs = [URL]
    CaptionAttrs = [Credentials, URL]

    Image = Utils.base64string(join_path('static/icons', 'duolingo.png'))


class TorNode(metaclass=Object):
    name = 'Tor node'

    IP = Attributes.System.IPAddress
    Port = Attributes.System.Port
    IPAndPort = Attributes.System.IPAndPort
    Domain = Attributes.System.Domain
    DateAndType = Attributes.DateAndType
    ASN = Attributes.System.ASN
    AutonomousSystemName = Attributes.AutonomousSystemName
    Region = Attributes.System.Region
    CountryCode = Attributes.System.CountryCode
    ExitPolicy = Attributes.ExitPolicy
    HostUptimeHours = Attributes.HostUptimeHours
    Contact = Attributes.Contact
    Hidden = Attributes.Hidden
    Tag = Attributes.System.Tag
    Datetime = Attributes.System.Datetime
    Nickname = Attributes.System.Nickname
    Fingerprint = Attributes.OSFingerprint
    Product = Attributes.System.Product
    Version = Attributes.System.Version
    Running = Attributes.Running
    Geopoint = Attributes.System.GeoPoint
    LastAppearance = Attributes.System.LastAppearance
    FirstAppearance = Attributes.System.FirstAppearance

    IdentAttrs = [IP, Port, DateAndType]
    CaptionAttrs = [IPAndPort, Domain, DateAndType]
    Image = Utils.base64string(join_path('static/icons', 'tor_node.png'))


class NikePlusAccount(metaclass=Object):
    name = 'NikePlus account'

    Nickname = Attributes.System.Nickname
    Firstname = Attributes.System.Name
    Lastname = Attributes.System.Surname

    IdentAttrs = [Nickname]
    CaptionAttrs = [Nickname, Firstname, Lastname]
    Image = Utils.base64string(join_path('static/icons', 'nikeplus.png'))


class RunkeeperAccount(metaclass=Object):
    name = 'Runkeeper account'

    UID = Attributes.System.UID
    URL = Attributes.System.URL
    Credentials = Attributes.System.Credentials
    Nickname = Attributes.System.Nickname

    IdentAttrs = [UID]
    CaptionAttrs = [UID, URL, Credentials]
    Image = Utils.base64string(join_path('static/icons', 'runkeeper.png'))


class RunkeeperActivity(metaclass=Object):
    name = 'Runkeeper activity'

    UID = Attributes.System.UID
    Datetime = Attributes.System.Datetime
    GeoPoint = Attributes.System.GeoPoint
    Email = Attributes.System.Email

    IdentAttrs = [UID, Datetime]
    CaptionAttrs = []
    Image = Utils.base64string(join_path('static/icons', 'runkeeper.png'))

class StravaAccount(metaclass=Object):
    name = 'Strava account'

    StravaID = Attributes.StravaID
    Firstname = Attributes.System.Name
    Lastname = Attributes.System.Surname
    URL = Attributes.System.URL

    IdentAttrs = [StravaID]
    CaptionAttrs = [StravaID, Firstname, Lastname, URL]
    Image = Utils.base64string(join_path('static/icons', 'strava.png'))

class StravaActivity(metaclass=Object):
    name = 'Strava activity'
    StravaActivityID = Attributes.StravaActivityID
    Datetime = Attributes.System.Datetime
    GeoPoint = Attributes.System.GeoPoint

    IdentAttrs = [StravaActivityID, Datetime]
    CaptionAttrs = []
    Image = Utils.base64string(join_path('static/icons', 'strava.png'))

class BookmateAccount(metaclass=Object):
    name = 'Bookmate account'

    Nickname = Attributes.System.Nickname
    URL = Attributes.System.URL
    Credentials = Attributes.System.Credentials

    IdentAttrs = [URL]
    CaptionAttrs = [Nickname, Credentials, URL]
    Image = Utils.base64string(join_path('static/icons', 'bookmate.png'))


class TumblrAccount(metaclass=Object):
    name = 'Tumblr account'

    URL = Attributes.System.URL
    Nickname = Attributes.System.Nickname

    IdentAttrs = CaptionAttrs = [URL]
    Image = Utils.base64string(join_path('static/icons', 'tumblr.png'))


class GoodreadsAccount(metaclass=Object):
    name = 'Goodreads account'

    Nickname = Attributes.System.Nickname
    URL = Attributes.System.URL

    IdentAttrs = [URL]
    CaptionAttrs = [Nickname, URL]
    Image = Utils.base64string(join_path('static/icons', 'goodreads.png'))


class GravatarAccount(metaclass=Object):
    name = 'Gravatar account'

    URL = Attributes.System.URL
    Nickname = Attributes.System.Nickname
    Firstname = Attributes.System.Name
    Lastname = Attributes.System.Surname
    Address = Attributes.System.Address
    GeoPoint = Attributes.System.GeoPoint
    Bio = Attributes.Bio

    IdentAttrs = [URL]
    CaptionAttrs = [Nickname, URL, Firstname, Lastname]
    Image = Utils.base64string(join_path('static/icons', 'gravatar.png'))


class PeriscopeAccount(metaclass=Object):
    name = 'Periscope account'
    Nickname = Attributes.System.Nickname
    URL = Attributes.System.URL

    IdentAttrs = [URL]
    CaptionAttrs = [Nickname]

    Image = Utils.base64string(join_path('static/icons', 'periscope.png'))


class InstagramAccount(metaclass=Object):
    name = 'Instagram account'
    URL = Attributes.System.URL
    UID = Attributes.InstagramID

    Bio = Attributes.Bio
    Nickname = Attributes.System.Nickname
    Fullname = Attributes.System.Credentials

    PostsCount = Attributes.PostsCount
    FollowersCount = Attributes.FollowersCount
    FollowingCount = Attributes.FollowingCount

    IdentAttrs = [UID]
    CaptionAttrs = [Fullname, Nickname, URL]

    Image = Utils.base64string(join_path('static/icons', 'instagram.png'))


class VKAccount(metaclass=Object):
    name = 'VK account'

    URL = Attributes.System.URL
    VKID = Attributes.VKID
    Email = Attributes.System.Email
    City = Attributes.System.City
    Firstname = Attributes.System.Name
    Lastname = Attributes.System.Surname
    PhoneNumber = Attributes.System.PhoneNumber
    Birthday = Attributes.System.Birthday
    BirthdayStr = Attributes.System.BirthdayStr
    GeoPoint = Attributes.System.GeoPoint
    Sex = Attributes.System.Sex
    Nickname = Attributes.System.Nickname
    MaritalStatus = Attributes.System.MaritalStatus
    LastAppearance = Attributes.System.LastAppearance
    School = Attributes.System.School
    University = Attributes.System.University
    Work = Attributes.System.Work
    Occupation = Attributes.System.Occupation
    Country = Attributes.System.Country

    IdentAttrs = [VKID]
    CaptionAttrs = [Firstname, Lastname, URL]

    Image = Utils.base64string(join_path('static/icons', 'vk.png'))


class BitcoinWallet(metaclass=Object):
    name = 'Bitcoin wallet'

    WalletAddress = Attributes.WalletAddress
    TotalCoinsReceived = Attributes.TotalCoinsReceived
    TotalCoinsSent = Attributes.TotalCoinsSent
    Balance = Attributes.Balance
    TransactionCount = Attributes.TransactionCount

    IdentAttrs = [WalletAddress]
    CaptionAttrs = [WalletAddress, Balance]
    Image = Utils.base64string(join_path('static/icons', 'bitcoin_wallet.png'))

class BitbucketAccount(metaclass=Object):
    name = 'Bitbucket account'
    Nickname = Attributes.System.Nickname
    Firstname = Attributes.System.Name
    Lastname = Attributes.System.Surname
    Credentials = Attributes.System.Credentials
    URL = Attributes.System.URL
    BitbucketTeam = Attributes.Compromised

    IdentAttrs = [Credentials]
    CaptionAttrs = [Credentials]
    Image = Utils.base64string(join_path('static/icons', 'bitbucket.png'))


class TransactionMix(metaclass=Object):
    name = 'Transaction mix'

    TransactionHash = Attributes.TransactionHash
    Datetime = Attributes.System.Datetime
    InputScript = Attributes.InputScript
    OutScript = Attributes.OutScript

    IdentAttrs = [TransactionHash]
    Image = Utils.base64string(join_path('static/icons', 'bitcoin_transaction.png'))


class WikipediaArticle(metaclass=Object):
    name = 'Wikipedia article'

    Subdomain = Attributes.Subdomain
    Title = Attributes.System.Title
    URL = Attributes.System.URL

    IdentAttrs = [URL]
    CaptionAttrs = [Title]
    Image = Utils.base64string(join_path('static/icons', 'wiki_article.png'))


class WikipediaUser(metaclass=Object):
    name = 'Wikipedia user'

    Nickname = Attributes.System.Nickname
    UID = Attributes.WikipediaUserID
    URL = Attributes.System.URL

    IdentAttrs = [UID]
    CaptionAttrs = [Nickname]
    Image = Utils.base64string(join_path('static/icons', 'head_silhouette.png'))


class Photo(metaclass=Object):
    GeoPoint = Attributes.System.GeoPoint
    DateCreated = Attributes.System.DateCreated
    URL = Attributes.System.URL

    IdentAttrs = [URL]
    CaptionAttrs = [GeoPoint, DateCreated]
    Image = Utils.base64string(join_path('static/icons', 'photo.png'))


class InstagramPost(metaclass=Object):
    GeoPoint = Attributes.System.GeoPoint
    DateCreated = Attributes.System.DateCreated
    URL = Attributes.System.URL
    Text = Attributes.System.Text

    IdentAttrs = [URL]
    CaptionAttrs = [URL, DateCreated]
    Image = Utils.base64string(join_path('static/icons', 'photo.png'))


class Tweet(metaclass=Object):
    GeoPoint = Attributes.System.GeoPoint
    Text = Attributes.System.Text
    URL = Attributes.System.URL

    IdentAttrs = [URL]
    CaptionAttrs = [URL]
    Image = Utils.base64string(join_path('static/icons', 'tweet.png'))


class Stream(metaclass=Object):
    URL = Attributes.System.URL
    GeoPoint = Attributes.System.GeoPoint
    DateCreated = Attributes.System.DateCreated
    DateOfCompletion = Attributes.DateOfCompletion

    IdentAttrs = [URL]
    CaptionAttrs = [URL, DateCreated, DateOfCompletion]
    Image = Utils.base64string(join_path('static/icons', 'stream.png'))


class LinkedinCompany(metaclass=Object):
    name = 'Linkedin company'

    LinkedinCompanyName = Attributes.LinkedinCompanyName
    LinkedinCompanyId = Attributes.LinkedinCompanyId
    LinkedinCompanyUrl = Attributes.LinkedinCompanyUrl

    IdentAttrs = [LinkedinCompanyUrl]
    CaptionAttrs = [LinkedinCompanyName, LinkedinCompanyUrl]
    Image = Utils.base64string(join_path('static/icons', 'linkedin_company.png')) #from icons8.com


# endregion


# region Torrent
class TorrentService(metaclass=Object):
    name = 'Torrent service'
    UID = Attributes.System.UID
    Title = Attributes.System.Title
    Description = Attributes.System.Description
    SizeTorrent = Attributes.System.FileSize

    IdentAttrs = [UID]
    CaptionAttrs = [Title, Description, SizeTorrent]
    Image = Utils.base64string(join_path('static/icons/common', 'torrent_strike.png'))


# endregion


# region HTTPS
class SectigoSertificateEntry(metaclass=Object):
    name = 'Sectigo certificate entry'

    SectigoCertificateID = Attributes.SectigoCertificateID

    IdentAttrs = CaptionAttrs = [SectigoCertificateID]
    Image = Utils.base64string(join_path('static/icons/common', 'sectigo_logo.png'))


class SSLCertificateSerialNumber(metaclass=Object):
    name = 'SSL certificate serial number'

    SerialNumber = Attributes.System.UID
    SSLSerialNumber = Attributes.SSLSerialNumber
    IdentAttrs = [SSLSerialNumber]
    CaptionAttrs = [SSLSerialNumber, SerialNumber]
    Image = Utils.base64string(join_path('static/icons', 'lock-ssl.png'))


class SSLCertificate(metaclass=Object):
    name = 'SSL certificate'

    SerialNumber = Attributes.SerialNumber
    SSLSerialNumber = Attributes.SSLSerialNumber
    Hash = Attributes.System.Hash
    CommonName = Attributes.System.Domain
    CountryName = Attributes.System.CountryCode
    StateOrProvinceName = Attributes.System.Region
    LocalityName = Attributes.System.City
    OrganizationName = Attributes.System.OrgName
    Version = Attributes.System.Version
    NotBefore = Attributes.NotBefore
    NotAfter = Attributes.NotAfter

    IdentAttrs = [SSLSerialNumber]
    CaptionAttrs = [CommonName, SSLSerialNumber, SerialNumber, Hash]
    Image = Utils.base64string(join_path('static/icons', 'ssl-https.png'))


# endregion


# region Shodan
class ShodanService(metaclass=Object):
    name = 'Shodan service'

    Hash = Attributes.System.HashDigest
    Tags = Attributes.System.Tag
    IP = Attributes.System.IPAddress
    IPInteger = Attributes.System.IPInteger
    IPAndPort = Attributes.System.IPAndPort
    Port = Attributes.System.Port
    Transport = Attributes.System.TransportLayerProto
    Product = Attributes.System.Product
    Version = Attributes.System.Version
    OS = Attributes.System.OS
    ISP = Attributes.System.ISP
    Timestamp = Attributes.System.Datetime
    Org = Attributes.System.OrgName
    Opts = Attributes.Opts
    Data = Attributes.System.Data
    ASN = Attributes.System.ASN
    Info = Attributes.System.Info
    CPE = Attributes.CPE
    Geo = Attributes.System.GeoPoint

    IdentAttrs = [IPAndPort]
    CaptionAttrs = [IPAndPort, Product, Version]

    Image = Utils.base64string(join_path('static/icons/shodan', 'gear.png'))


class NetworkService(metaclass=Object):  # network service software piece
    name = 'Network service'

    Product = Attributes.System.Product
    Version = Attributes.System.Version
    CPE = Attributes.CPE
    Info = Attributes.System.Info
    Transport = Attributes.System.TransportLayerProto

    IdentAttrs = CaptionAttrs = [Product, Version]

    Image = Utils.base64string(join_path('static/icons/shodan', 'gear2.png'))


class Vulnerability(metaclass=Object):
    CVE = Attributes.CVE
    CVSS = Attributes.CVSS
    References = Attributes.References
    Description = Attributes.System.Description

    IdentAttrs = CaptionAttrs = [CVE]

    Image = Utils.base64string(join_path('static/icons/shodan', 'cve.png'))


class Certificate(metaclass=Object):
    Serial = Attributes.SerialNumber
    SignatureAlgorithm = Attributes.SignatureAlgorithm
    SubjectCN = Attributes.SubjectCN
    SubjectOU = Attributes.SubjectOU
    SubjectO = Attributes.SubjectO
    SubjectL = Attributes.SubjectL
    SubjectC = Attributes.SubjectC
    Issued = Attributes.Issued
    Expires = Attributes.Expires
    Expired = Attributes.Expired
    Version = Attributes.System.Version
    FingerprintSHA1 = Attributes.FingerprintSHA1
    FingerprintSHA256 = Attributes.FingerprintSHA256

    IdentAttrs = [Serial]
    CaptionAttrs = [SubjectCN, SubjectO]
    Image = Utils.base64string(join_path('static/icons/shodan', 'ssl.png'))


class CertificateIssuer(metaclass=Object):
    name = 'Certificate issuer'

    IssuerCN = Attributes.IssuerCN
    IssuerO = Attributes.IssuerO
    IssuerC = Attributes.IssuerC
    IssuerOU = Attributes.IssuerOU
    IssuerST = Attributes.IssuerST
    IssuerL = Attributes.IssuerL
    Email = Attributes.System.Email

    IdentAttrs = [IssuerCN]
    CaptionAttrs = [IssuerO, IssuerC]
    Image = Utils.base64string(join_path('static/icons/shodan', 'cert_issuer.png'))
# endregion


# region VT
class VTSample(metaclass=Object):
    name = 'Virustotal sample'

    Date = Attributes.System.Datetime
    Positives = Attributes.AVPositives
    Total = Attributes.AVTotal
    Sha256 = Attributes.System.Hash

    IdentAttrs = [Sha256]
    CaptionAttrs = [Positives, Total]

    Image = Utils.base64string(join_path('static/icons/virustotal', 'virus.png'))


class VTURL(metaclass=Object):
    name = 'VT scanned URL'

    Url = Attributes.System.URL
    ScanDate = Attributes.System.Datetime
    Positives = Attributes.AVPositives
    UrlTotal = Attributes.AVTotal
    Hash = Attributes.System.Hash

    IdentAttrs = [Url]
    CaptionAttrs = [Positives, Url]

    Image = Utils.base64string(join_path('static/icons/virustotal', 'chain.png'))


class VTScanResult(metaclass=Object):
    name = 'Virustotal scan'

    ScanId = Attributes.VTScanId
    Resource = Attributes.Resource
    Url = Attributes.System.URL
    ResponseCode = Attributes.System.ResponseCode
    ScanDate = Attributes.System.Datetime
    FileName = Attributes.System.Filename
    Permalink = Attributes.Permalink
    VerboseMsg = Attributes.VerboseMsg
    FilescanId = Attributes.FilescanId
    Positives = Attributes.AVPositives
    Total = Attributes.AVTotal

    IdentAttrs = [ScanId]
    CaptionAttrs = [FileName, Positives]

    Image = Utils.base64string(join_path('static/icons/virustotal', 'vt.png'))


class VTScannerReport(metaclass=Object):
    name = 'Virustotal scanner report'

    ScanBy = Attributes.VTScanBy
    ScanDetected = Attributes.VTScanDetected
    ScanResult = Attributes.VTScanResult
    ScanDetail = Attributes.VTScanDetail
    ScanDate = Attributes.System.Datetime

    IdentAttrs = [ScanBy, ScanDate]
    CaptionAttrs = [ScanBy, ScanResult]

    Image = Utils.base64string(join_path('static/icons/virustotal', 'paper.png'))


# endregion


# region AIPDB
class Abuse(metaclass=Object):
    ID = Attributes.AbuseTypeID
    Type = Attributes.AbuseType
    Date = Attributes.System.Datetime
    Description = Attributes.AbuseDescription

    IdentAttrs = [ID]
    CaptionAttrs = [Type]

    Image = Utils.base64string(join_path('static/icons/abuses', 'report.png'))


# endregion


# region Cymon
class CymonEvent(metaclass=Object):
    name = 'Cymon report'

    Title = Attributes.System.Title
    Description = Attributes.System.Description
    DetailsUrl = Attributes.System.URL
    Created = Attributes.System.DateCreated
    Updated = Attributes.System.DateModified
    Tag = Attributes.System.Tag

    IdentAttrs = CaptionAttrs = [Title]

    Image = Utils.base64string(join_path('static/icons/cymon', 'announcement.png'))


class CymonSource(metaclass=Object):
    name = 'Cymon source'
    Name = Attributes.CymonSourceName

    IdentAttrs = CaptionAttrs = [Name]

    Image = Utils.base64string(join_path('static/icons/cymon', 'badge.png'))


# endregion


# region HybridSearch
class HybridExtraFile(metaclass=Object):
    name = 'Hybrid extracted file'

    Filename = Attributes.System.Filename
    FilePath = Attributes.FilePath
    FileSize = Attributes.System.FileSize
    SHA1 = Attributes.SHA1
    SHA256 = Attributes.SHA256
    MD5 = Attributes.MD5
    Tag = Attributes.System.Tag
    Description = Attributes.System.Description
    RuntimeProcess = Attributes.RuntimeProcess
    ThreatScore = Attributes.HybridThreatScore
    ThreatScoreStr = Attributes.HybridThreatScoreStr
    AVLabel = Attributes.AVLabel
    AVPositives = Attributes.AVPositives
    AVTotal = Attributes.AVTotal
    DownloadAvailable = Attributes.DownloadAvailable

    IdentAttrs = [SHA256]
    CaptionAttrs = [Filename, AVPositives]
    Image = Utils.base64string(join_path('static/icons/hybrid', 'file.png'))


class HybridProcess(metaclass=Object):
    name = 'Hybrid process'

    UID = Attributes.System.UID
    Parentuid = Attributes.ParentUID
    Name = Attributes.System.Name
    NormalizedPath = Attributes.NormalizedPath
    CommandLine = Attributes.CommandLine
    Sha256 = Attributes.SHA256
    AVLlabel = Attributes.AVLabel
    AVPositives = Attributes.AVPositives
    AVTotal = Attributes.AVTotal
    PID = Attributes.PID
    Icon = Attributes.Icon

    IdentAttrs = [UID, Sha256]
    CaptionAttrs = [Name, AVPositives]
    Image = Utils.base64string(join_path('static/icons/hybrid', 'running_process.png'))


class HybridCertificate(metaclass=Object):
    name = 'Hybrid certificate'

    Owner = Attributes.Owner
    Issuer = Attributes.Issuer
    SerialNumber = Attributes.SerialNumber
    MD5 = Attributes.MD5
    SHA1 = Attributes.SHA1
    ValidFrom = Attributes.ValidFrom
    ValidUntil = Attributes.ValidUntil

    IdentAttrs = [SerialNumber, SHA1]
    CaptionAttrs = [Owner, Issuer]
    Image = Utils.base64string(join_path('static/icons/hybrid', 'encrypt.png'))


class HybridReport(metaclass=Object):
    name = 'Hybrid report'

    HybridJobID = Attributes.HybridJobID
    Verdict = Attributes.HybridVerdict
    AVDetect = Attributes.HybrydAVDetect
    ThreatScore = Attributes.HybridThreatScore
    VXFamily = Attributes.HybridVXFamily
    Hash = Attributes.System.Hash
    EnvironmentId = Attributes.HybridEnvironmentId
    StartTime = Attributes.HybridStartTime
    SubmitName = Attributes.HybridSubmitName
    EnvDesc = Attributes.HybridEnvDesc
    Size = Attributes.System.FileSize
    Type = Attributes.System.FileType
    TypeShort = Attributes.HybridTypeShort

    IdentAttrs = [HybridJobID]
    CaptionAttrs = [SubmitName, AVDetect, Verdict]

    Image = Utils.base64string(join_path('static/icons/hybrid', 'hybrid1.png'))


class MitreAttck(metaclass=Object):  # Adversarial Tactics, Techniques & Common Knowledge
    name = 'Mitre attck'

    Tactic = Attributes.MitreTactic
    Technique = Attributes.MitreTechnique
    AttckId = Attributes.MitreAttckId
    AttckIdWiki = Attributes.MitreAttckIdWiki
    MaliciousIdentifiersCount = Attributes.MaliciousIdentifiersCount
    MaliciousIdentifiers = Attributes.MaliciousIdentifiers
    SuspiciousIdentifiersCount = Attributes.SuspiciousIdentifiersCount
    SuspiciousIdentifiers = Attributes.SuspiciousIdentifiers
    InformativeIdentifiersCount = Attributes.InformativeIdentifiersCount
    InformativeIdentifiers = Attributes.InformativeIdentifiers

    IdentAttrs = [AttckId]
    CaptionAttrs = [Tactic, Technique]
    Image = Utils.base64string(join_path('static/icons/hybrid', 'mitre_attck.png'))


# endregion


# region HIBP
class HIBPBreach(metaclass=Object):
    name = 'Data breach'

    Title = Attributes.System.Title
    BreachName = Attributes.HIBPBreachName
    BreachedDomain = Attributes.HIBPBreachedDomain
    AddedDate = Attributes.System.DateCreated
    ModifiedDate = Attributes.System.DateModified
    BreachDate = Attributes.HIBPBreachDate
    PwnCount = Attributes.HIBPPwnCount
    Description = Attributes.HIBPDescription
    DataClass = Attributes.HIBPDataClass
    IsVerified = Attributes.HIBPIsVerified
    IsFabricated = Attributes.HIBPIsFabricated
    IsSensitive = Attributes.HIBPIsSensitive
    IsActive = Attributes.HIBPIsActive
    IsRetired = Attributes.HIBPIsRetired
    IsSpamList = Attributes.HIBPIsSpamList
    LogoType = Attributes.HIBPLogoType

    IdentAttrs = [BreachedDomain, BreachName]
    CaptionAttrs = [BreachName]

    Image = Utils.base64string(join_path('static/icons/hibp', 'leak.png'))


class HIBPPaste(metaclass=Object):
    name = 'Paste'

    PasteSource = Attributes.PasteSource
    PasteId = Attributes.PasteID
    PasteTitle = Attributes.System.Title
    PasteDate = Attributes.System.DateString
    PasteEmailCount = Attributes.PasteEmailCount

    IdentAttrs = CaptionAttrs = [PasteSource, PasteId]

    Image = Utils.base64string(join_path('static/icons/hibp', 'paste.png'))


# endregion


# region MongoDB and Collection
class MongoDatabase(metaclass=Object):
    name = "MongoDB: Database"
    DBName = Attributes.DBName
    ip_and_port = Attributes.System.IPAndPort
    product = Attributes.System.Product
    ip = Attributes.System.IPAddress
    version = Attributes.System.Version

    size = Attributes.System.FileSize

    IdentAttrs = [DBName, ip_and_port]
    CaptionAttrs = [DBName, ip_and_port, product, version, size]
    Image = Utils.base64string(join_path('static/icons/shodan/colored/db', 'mongo.png'))


class MongoDBCollection(metaclass=Object):
    name = "MongoDB:Collection"
    CollectionName = Attributes.CollectionName
    DBName = Attributes.DBName
    ip_and_port = Attributes.System.IPAndPort
    product = Attributes.System.Product
    ip = Attributes.System.IPAddress
    version = Attributes.System.Version
    Count = Attributes.System.Count
    IdentAttrs = [CollectionName, DBName, ip_and_port]
    CaptionAttrs = [CollectionName, DBName, ip_and_port, Count]
    Image = Utils.base64string(join_path('static/icons/shodan', 'storage.png'))


# endregion


# region Elasticsearch
class ElasticNodeM(metaclass=Object):
    name = "Elasticsearch: Master Node"
    MasterNodeName = Attributes.MasterNodeName
    MasterNodeID = Attributes.MasterNodeID
    IPAddress = Attributes.System.IPAddress
    IPAndPort = Attributes.System.IPAndPort
    IdentAttrs = [MasterNodeName, MasterNodeID, IPAndPort]
    CaptionAttrs = IdentAttrs
    Image = Utils.base64string(join_path('static/icons/shodan/colored/db', 'elasticM.png'))


class ElasticNode(metaclass=Object):
    name = "Elasticsearch: Node"
    MasterNodeName = Attributes.MasterNodeName
    MasterNodeID = Attributes.MasterNodeID
    NodeName = Attributes.NodeName
    NodeID = Attributes.NodeID
    IPAddress = Attributes.System.IPAddress
    MasterNodeValue = Attributes.MasterNodeValue
    StorageSizeTotal = Attributes.StorageSizeTotal
    StorageSizeUsed = Attributes.StorageSizeUsed
    StorageSizeAvail = Attributes.StorageSizeAvail
    HostRAMCurrent = Attributes.HostRAMCurrent
    HostRAMMax = Attributes.HostRAMMax
    HostCPUusage = Attributes.HostCPUusage
    HostUptimeStr = Attributes.HostUptimeStr
    HostRole = Attributes.HostRole
    IPAndPort = Attributes.System.IPAndPort

    IdentAttrs = [NodeID, NodeName, IPAddress, MasterNodeID, IPAndPort]
    CaptionAttrs = [NodeName, IPAddress, IPAndPort]
    Image = Utils.base64string(join_path('static/icons/shodan/colored/db', 'elastic.png'))


class ElasticIndex(metaclass=Object):
    name = "Elasticsearch: Index"
    MasterNodeName = Attributes.MasterNodeName
    MasterNodeID = Attributes.MasterNodeID
    IPAddress = Attributes.System.IPAddress
    IPAndPort = Attributes.System.IPAndPort
    IndexHealth = Attributes.IndexHealth
    IndexStatus = Attributes.IndexStatus
    IndexName = Attributes.IndexName
    IndexURL = Attributes.System.URL
    IndexUID = Attributes.System.UID
    IndexCountDocuments = Attributes.IndexCountDocuments
    IndexCountDeletedDocuments = Attributes.IndexCountDeletedDocuments
    IndexStoreSize = Attributes.System.FileSize
    IdentAttrs = [IndexUID, IndexName, IPAddress, MasterNodeID, MasterNodeName, IPAndPort]
    CaptionAttrs = [IndexName, IndexCountDocuments, IPAndPort, MasterNodeName]
    Image = Utils.base64string(join_path('static/icons/shodan', 'storage.png'))


# endregion


# region Miscellanous
class Netblock(metaclass=Object):
    Netblock = Attributes.Netblock

    IdentAttrs = CaptionAttrs = [Netblock]
    Image = Utils.base64string(join_path('static/icons/common', 'netblock.png'))


class SearchTerm(metaclass=Object):
    name = 'Search term'

    Text = Attributes.System.Text

    IdentAttrs = CaptionAttrs = [Text]
    Image = Utils.base64string(join_path('static/icons/common', 'text.png'))


class BankCard(metaclass=Object):
    Number = Attributes.CardNumber
    BIN = Attributes.BIN
    Country = Attributes.System.Country
    Vendor = Attributes.Vendor
    CardLevel = Attributes.CardLevel
    Bank = Attributes.Bank
    URL = Attributes.System.URL

    IdentAttrs = [Number]
    CaptionAttrs = [Number, Country, Bank]
    Image = Utils.base64string(join_path('static/icons/common', 'bank_card.png'))


class Directory(metaclass=Object):
    FilePath = Attributes.FilePath
    Filename = Attributes.System.Filename
    DateCreated = Attributes.System.DateCreated
    DateAccessed = Attributes.System.DateAccessed
    DateModified = Attributes.System.DateModified

    IdentAttrs = [FilePath]
    CaptionAttrs = [Filename]
    Image = Utils.base64string(join_path('static/icons/common', 'directory.png'))


class File(metaclass=Object):
    FilePath = Attributes.FilePath
    Filename = Attributes.System.Filename
    DateCreated = Attributes.System.DateCreated
    DateAccessed = Attributes.System.DateAccessed
    DateModified = Attributes.System.DateModified
    FileType = Attributes.System.FileType
    FileSize = Attributes.System.FileSize

    IdentAttrs = [FilePath]
    CaptionAttrs = [Filename]
    Image = Utils.base64string(join_path('static/icons/common', 'file.png'))


# endregion


# region Urlscan.io
class ElasticsearchQueryString(metaclass=Object):
    name = 'Elasticsearch query string'

    QueryString = Attributes.QueryString

    IdentAttrs = CaptionAttrs = [QueryString]
    Image = Utils.base64string(join_path('static/icons', 'query_string.png'))


class UrlScanReport(metaclass=Object):
    name = 'Urlscan report'

    UUID = Attributes.System.UID
    Datetime = Attributes.System.Datetime

    IdentAttrs = [UUID]
    CaptionAttrs = [UUID]
    Image = Utils.base64string(join_path('static/icons', 'report.png'))


class WebRequest(metaclass=Object):
    name = 'Web request'

    URL = Attributes.System.URL
    WebDataType = Attributes.WebDataType

    IdentAttrs = [URL]
    CaptionAttrs = [URL, WebDataType]
    Image = Utils.base64string(join_path('static/icons', 'web_request.png'))


class HyperLink(metaclass=Object):
    name = 'Hyperlink'

    URL = Attributes.System.URL
    Text = Attributes.System.Text

    IdentAttrs = [URL]
    CaptionAttrs = [URL, Text]
    Image = Utils.base64string(join_path('static/icons', 'hyperlink.png'))


class GlobalVariable(metaclass=Object):
    name = 'Global variable'

    Name = Attributes.System.Name
    DataType = Attributes.DataType

    IdentAttrs = CaptionAttrs = [Name, DataType]
    Image = Utils.base64string(join_path('static/icons', 'js_global_var.png'))


class WebTechnology(metaclass=Object):
    name = 'Web technology'

    Name = Attributes.System.Name
    Version = Attributes.System.Version
    Confidence = Attributes.Confidence
    URL = Attributes.System.URL
    Category = Attributes.Category

    IdentAttrs = CaptionAttrs = [Name, Version]
    Image = Utils.base64string(join_path('static/icons', 'web_technology.png'))


class HashMatch(metaclass=Object):
    name = 'Hash match'

    Resource = Attributes.Resource
    URL = Attributes.System.URL
    ProjectName = Attributes.ProjectName
    ProjectURL = Attributes.ProjectURL
    Filename = Attributes.System.Filename

    IdentAttrs = [URL]
    CaptionAttrs = [Filename]
    Image = Utils.base64string(join_path('static/icons', 'hash_match.png'))


# endregion


# endregion


# region Links
# region System links
class Call(metaclass=Link):
    name = 'Call'

    CallTime = Attributes.System.Datetime
    Duration = Attributes.System.Duration

    Begin = Phone
    End = Phone


class IPToDomain(metaclass=Link):
    name = Utils.make_link_name(IP, Domain)

    Resolved = Attributes.System.Resolved

    Begin = IP
    End = Domain


class IPToEmail(metaclass=Link):
    name = Utils.make_link_name(IP, Email)

    DateTime = Attributes.System.Datetime

    Begin = IP
    End = Email


class IPToPerson(metaclass=Link):
    name = Utils.make_link_name(IP, Person)

    DateTime = Attributes.System.Datetime

    Begin = IP
    End = Person


class IPToAPT(metaclass=Link):
    name = Utils.make_link_name(IP, APT)

    DateTime = Attributes.System.Datetime

    Begin = IP
    End = APT


class IPToAutonomousSystem(metaclass=Link):
    name = Utils.make_link_name(IP, AutonomousSystem)

    Value = Attributes.System.Value

    Begin = IP
    End = AutonomousSystem


class IPToCity(metaclass=Link):
    name = Utils.make_link_name(IP, City)

    Value = Attributes.System.Value

    Begin = IP
    End = City


class IPToCountry(metaclass=Link):
    name = Utils.make_link_name(IP, Country)

    Value = Attributes.System.Value

    Begin = IP
    End = Country


class IPToEntity(metaclass=Link):
    name = Utils.make_link_name(IP, Entity)

    Value = Attributes.System.Value

    Begin = IP
    End = Entity


class IPToIP(metaclass=Link):
    name = Utils.make_link_name(IP, IP)

    Value = Attributes.System.Value

    Begin = IP
    End = IP


class IPToLocation(metaclass=Link):
    name = Utils.make_link_name(IP, Location)

    DateTime = Attributes.System.Datetime

    Begin = IP
    End = Location


class IPToOrganisation(metaclass=Link):
    name = Utils.make_link_name(IP, Organisation)

    Value = Attributes.System.Value

    Begin = IP
    End = Organisation


class IPToPhone(metaclass=Link):
    name = Utils.make_link_name(IP, Phone)

    Value = Attributes.System.Value

    Begin = IP
    End = Phone


class IPToSchool(metaclass=Link):
    name = Utils.make_link_name(IP, School)

    Value = Attributes.System.Value

    Begin = IP
    End = School


class IPToTelegramAccount(metaclass=Link):
    name = Utils.make_link_name(IP, TelegramAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = TelegramAccount


class IPToURL(metaclass=Link):
    name = Utils.make_link_name(IP, URL)

    Value = Attributes.System.Value

    Begin = IP
    End = URL


class IPToUniversity(metaclass=Link):
    name = Utils.make_link_name(IP, University)

    Value = Attributes.System.Value

    Begin = IP
    End = University


class DomainToDomain(metaclass=Link):
    name = Utils.make_link_name(Domain, Domain)

    RelationType = Attributes.System.RelationType

    Begin = Domain
    End = Domain


class EntityToEntity(metaclass=Link):
    name = Utils.make_link_name(Entity, Entity)

    Value = Attributes.System.Value

    Begin = Entity
    End = Entity


class PortToIP(metaclass=Link):
    name = Utils.make_link_name(Port, IP)

    Transport = Attributes.System.TransportLayerProto
    Product = Attributes.System.Product

    Begin = Port
    End = IP


class CallEventToAPT(metaclass=Link):
    name = Utils.make_link_name(CallEvent, APT)

    DateTime = Attributes.System.Datetime

    Begin = CallEvent
    End = APT


class CallEventToAddress(metaclass=Link):
    name = Utils.make_link_name(CallEvent, Address)

    DateTime = Attributes.System.Datetime

    Begin = CallEvent
    End = Address


class CallEventToBaseStation(metaclass=Link):
    name = Utils.make_link_name(CallEvent, BaseStation)

    DateTime = Attributes.System.Datetime

    Begin = CallEvent
    End = BaseStation


class CallEventToEmail(metaclass=Link):
    name = Utils.make_link_name(CallEvent, Email)

    DateTime = Attributes.System.Datetime

    Begin = CallEvent
    End = Email


class CallEventToEntity(metaclass=Link):
    name = Utils.make_link_name(CallEvent, Entity)

    DateTime = Attributes.System.Datetime

    Begin = CallEvent
    End = Entity


class CallEventToLocation(metaclass=Link):
    name = Utils.make_link_name(CallEvent, Location)

    DateTime = Attributes.System.Datetime

    Begin = CallEvent
    End = Location


class CallEventToPerson(metaclass=Link):
    name = Utils.make_link_name(CallEvent, Person)

    DateTime = Attributes.System.Datetime

    Begin = CallEvent
    End = Person


class CallEventToPhone(metaclass=Link):
    name = Utils.make_link_name(CallEvent, Phone)

    DateTime = Attributes.System.Datetime

    Begin = CallEvent
    End = Phone


class CallEventToPhoneNumber(metaclass=Link):
    name = Utils.make_link_name(CallEvent, PhoneNumber)

    DateTime = Attributes.System.Datetime

    Begin = CallEvent
    End = PhoneNumber


class PhoneToIMEI(metaclass=Link):
    name = Utils.make_link_name(Phone, IMEI)

    DateTime = Attributes.System.Datetime

    Begin = Phone
    End = IMEI


class PhoneToIMSI(metaclass=Link):
    name = Utils.make_link_name(Phone, IMSI)

    DateTime = Attributes.System.Datetime

    Begin = Phone
    End = IMSI


class PhoneToBaseStation(metaclass=Link):
    name = Utils.make_link_name(Phone, BaseStation)

    DateTime = Attributes.System.Datetime

    Begin = Phone
    End = BaseStation


class PhoneToPerson(metaclass=Link):
    name = Utils.make_link_name(Phone, Person)

    DateTime = Attributes.System.Datetime

    Begin = Phone
    End = Person


class PhoneNumberToIMEI(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, IMEI)

    DateTime = Attributes.System.Datetime

    Begin = PhoneNumber
    End = IMEI


class PhoneNumberToIMSI(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, IMSI)

    DateTime = Attributes.System.Datetime

    Begin = PhoneNumber
    End = IMSI


class PhoneNumberToPerson(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, Person)

    DateTime = Attributes.System.Datetime

    Begin = PhoneNumber
    End = Person


class HashToEmail(metaclass=Link):
    name = Utils.make_link_name(Hash, Email)

    Value = Attributes.System.Value

    Begin = Hash
    End = Email


class HashToIP(metaclass=Link):
    name = Utils.make_link_name(Hash, IP)

    DateTime = Attributes.System.Datetime

    Begin = Hash
    End = IP


class EmailToPerson(metaclass=Link):
    name = Utils.make_link_name(Email, Person)

    DateTime = Attributes.System.Datetime

    Begin = Email
    End = Person


class EmailToDomain(metaclass=Link):
    name = Utils.make_link_name(Email, Domain)

    DateTime = Attributes.System.Datetime

    Begin = Email
    End = Domain


class EmailToPhoneLink(metaclass=Link):
    name = Utils.make_link_name(Email, Phone)

    DateTime = Attributes.System.Datetime

    Begin = Email
    End = Phone


class EmailToSkypeAccount(metaclass=Link):
    name = Utils.make_link_name(Email, SkypeAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = SkypeAccount


class EmailToFacebookAccount(metaclass=Link):
    name = Utils.make_link_name(Email, FacebookAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = FacebookAccount


class EmailToTelegramAccount(metaclass=Link):
    name = Utils.make_link_name(Email, TelegramAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = TelegramAccount


class EmailToWhatsappAccount(metaclass=Link):
    name = Utils.make_link_name(Email, WhatsappAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = WhatsappAccount


class EmailToLinkedinAccount(metaclass=Link):
    name = Utils.make_link_name(Email, LinkedinAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = LinkedinAccount


class EmailToIcqAccount(metaclass=Link):
    name = Utils.make_link_name(Email, IcqAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = IcqAccount


class EmailToGooglePlusAccount(metaclass=Link):
    name = Utils.make_link_name(Email, GooglePlusAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = GooglePlusAccount


class EmailToFlickrAccount(metaclass=Link):
    name = Utils.make_link_name(Email, FlickrAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = FlickrAccount


class EmailToFoursquareAccount(metaclass=Link):
    name = Utils.make_link_name(Email, FoursquareAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = FoursquareAccount


class EmailToGithubAccount(metaclass=Link):
    name = Utils.make_link_name(Email, GithubAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = GithubAccount


class EmailToTwitterAccount(metaclass=Link):
    name = Utils.make_link_name(Email, TwitterAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = TwitterAccount


class EmailToMyspaceAccount(metaclass=Link):
    name = Utils.make_link_name(Email, MyspaceAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = MyspaceAccount


class EmailToAPT(metaclass=Link):
    name = Utils.make_link_name(Email, APT)

    Value = Attributes.System.Value

    Begin = Email
    End = APT


class EmailToEmail(metaclass=Link):
    name = Utils.make_link_name(Email, Email)

    Value = Attributes.System.Value

    Begin = Email
    End = Email


class EmailToEntity(metaclass=Link):
    name = Utils.make_link_name(Email, Entity)

    Value = Attributes.System.Value

    Begin = Email
    End = Entity


class EmailToOrganisation(metaclass=Link):
    name = Utils.make_link_name(Email, Organisation)

    Value = Attributes.System.Value

    Begin = Email
    End = Organisation


class EmailToSchool(metaclass=Link):
    name = Utils.make_link_name(Email, School)

    Value = Attributes.System.Value

    Begin = Email
    End = School


class EmailToUniversity(metaclass=Link):
    name = Utils.make_link_name(Email, University)

    Value = Attributes.System.Value

    Begin = Email
    End = University


class EmailToWork(metaclass=Link):
    name = Utils.make_link_name(Email, Work)

    Value = Attributes.System.Value

    Begin = Email
    End = Work


class CityToCountry(metaclass=Link):
    name = Utils.make_link_name(City, Country)

    Emptiness = Attributes.System.Emptiness

    Begin = City
    End = Country


class PhoneToSkypeAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, SkypeAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = SkypeAccount


class PhoneToFacebookAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, FacebookAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = FacebookAccount


class PhoneToTelegramAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, TelegramAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = TelegramAccount


class PhoneToWhatsappAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, WhatsappAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = WhatsappAccount


class PhoneToLinkedinAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, LinkedinAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = LinkedinAccount


class PhoneToIcqAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, IcqAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = IcqAccount


class PhoneToGooglePlusAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, GooglePlusAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = GooglePlusAccount


class PhoneToFlickrAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, FlickrAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = FlickrAccount


class PhoneToFoursquareAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, FoursquareAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = FoursquareAccount


class PhoneToGithubAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, GithubAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = GithubAccount


class PhoneToTwitterAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, TwitterAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = TwitterAccount


class PhoneToMyspaceAccount(metaclass=Link):
    name = Utils.make_link_name(Phone, MyspaceAccount)

    Value = Attributes.System.Value

    Begin = Phone
    End = MyspaceAccount


class SkypeAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(SkypeAccount, Person)

    Value = Attributes.System.Value

    Begin = SkypeAccount
    End = Person


class FacebookAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, Person)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = Person


class FacebookAccountToFacebookAccount(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, FacebookAccount)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = FacebookAccount


class FacebookAccountToCountry(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, Country)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = Country


class FacebookAccountToCity(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, City)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = City


class FacebookAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, Organisation)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = Organisation


class FacebookAccountToWork(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, Work)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = Work


class FacebookAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, School)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = School


class FacebookAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, University)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = University


class TelegramAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(TelegramAccount, Person)

    Value = Attributes.System.Value

    Begin = TelegramAccount
    End = Person


class WhatsappAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(WhatsappAccount, Person)

    Value = Attributes.System.Value

    Begin = WhatsappAccount
    End = Person


class LinkedinAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(LinkedinAccount, Person)

    Value = Attributes.System.Value

    Begin = LinkedinAccount
    End = Person


class IcqAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(IcqAccount, Person)

    Value = Attributes.System.Value

    Begin = IcqAccount
    End = Person


class GooglePlusAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(GooglePlusAccount, Person)

    Value = Attributes.System.Value

    Begin = GooglePlusAccount
    End = Person


class FlickrAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(FlickrAccount, Person)

    Value = Attributes.System.Value

    Begin = FlickrAccount
    End = Person


class FoursquareAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(FoursquareAccount, Person)

    Value = Attributes.System.Value

    Begin = FoursquareAccount
    End = Person


class GithubAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(GithubAccount, Person)

    Value = Attributes.System.Value

    Begin = GithubAccount
    End = Person


class TwitterAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(TwitterAccount, Person)

    Value = Attributes.System.Value

    Begin = TwitterAccount
    End = Person


class MyspaceAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(MyspaceAccount, Person)

    Value = Attributes.System.Value

    Begin = MyspaceAccount
    End = Person


class UniversityToLocation(metaclass=Link):
    name = Utils.make_link_name(University, Location)

    Value = Attributes.System.Value

    Begin = University
    End = Location


class WorkToLocation(metaclass=Link):
    name = Utils.make_link_name(Work, Location)

    Value = Attributes.System.Value

    Begin = Work
    End = Location


class PersonToLocation(metaclass=Link):
    name = Utils.make_link_name(Person, Location)

    Value = Attributes.System.Value

    Begin = Person
    End = Location


class PhoneNumberToLocation(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, Location)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = Location


class PersonToCountry(metaclass=Link):
    name = Utils.make_link_name(Person, Country)

    Value = Attributes.System.Value

    Begin = Person
    End = Country


class PersonToCity(metaclass=Link):
    name = Utils.make_link_name(Person, City)

    Value = Attributes.System.Value

    Begin = Person
    End = City


class SkypeAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(SkypeAccount, Location)

    Value = Attributes.System.Value

    Begin = SkypeAccount
    End = Location


class FacebookAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, Location)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = Location


class TelegramAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(TelegramAccount, Location)

    Value = Attributes.System.Value

    Begin = TelegramAccount
    End = Location


class WhatsappAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(WhatsappAccount, Location)

    Value = Attributes.System.Value

    Begin = WhatsappAccount
    End = Location


class LinkedinAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(LinkedinAccount, Location)

    Value = Attributes.System.Value

    Begin = LinkedinAccount
    End = Location


class IcqAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(IcqAccount, Location)

    Value = Attributes.System.Value

    Begin = IcqAccount
    End = Location


class GooglePlusAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(GooglePlusAccount, Location)

    Value = Attributes.System.Value

    Begin = GooglePlusAccount
    End = Location


class FlickrAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(FlickrAccount, Location)

    Value = Attributes.System.Value

    Begin = FlickrAccount
    End = Location


class FoursquareAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(FoursquareAccount, Location)

    Value = Attributes.System.Value

    Begin = FoursquareAccount
    End = Location


class GithubAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(GithubAccount, Location)

    Value = Attributes.System.Value

    Begin = GithubAccount
    End = Location


class TwitterAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(TwitterAccount, Location)

    Value = Attributes.System.Value

    Begin = TwitterAccount
    End = Location


class MyspaceAccountToLocation(metaclass=Link):
    name = Utils.make_link_name(MyspaceAccount, Location)

    Value = Attributes.System.Value

    Begin = MyspaceAccount
    End = Location


class WebcamToIP(metaclass=Link):
    name = Utils.make_link_name(Webcam, IP)

    Value = Attributes.System.Value

    Begin = Webcam
    End = IP


class AddressToPerson(metaclass=Link):
    name = Utils.make_link_name(Address, Person)

    Value = Attributes.System.Value

    Begin = Address
    End = Person


class AddressToSchool(metaclass=Link):
    name = Utils.make_link_name(Address, School)

    Value = Attributes.System.Value

    Begin = Address
    End = School


class AddressToUniversity(metaclass=Link):
    name = Utils.make_link_name(Address, University)

    Value = Attributes.System.Value

    Begin = Address
    End = University


class AddressToWork(metaclass=Link):
    name = Utils.make_link_name(Address, Work)

    Value = Attributes.System.Value

    Begin = Address
    End = Work


class CarToCarRecord(metaclass=Link):
    name = Utils.make_link_name(Car, CarRecord)

    Value = Attributes.System.Value

    Begin = Car
    End = CarRecord


class CarToOrganisation(metaclass=Link):
    name = Utils.make_link_name(Car, Organisation)

    Value = Attributes.System.Value

    Begin = Car
    End = Organisation


class CarToPerson(metaclass=Link):
    name = Utils.make_link_name(Car, Person)

    Value = Attributes.System.Value

    Begin = Car
    End = Person


class PhoneNumberToOrganisation(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, Organisation)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = Organisation


class PhoneNumberToWork(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, Work)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = Work


class PhoneNumberToSchool(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, School)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = School


class PhoneNumberToUniversity(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, University)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = University


class IPToWork(metaclass=Link):
    name = Utils.make_link_name(IP, Work)

    Value = Attributes.System.Value

    Begin = IP
    End = Work


class IPToSkypeAccount(metaclass=Link):
    name = Utils.make_link_name(IP, SkypeAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = SkypeAccount


class IPToFacebookAccount(metaclass=Link):
    name = Utils.make_link_name(IP, FacebookAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = FacebookAccount


class IPToWhatsappAccount(metaclass=Link):
    name = Utils.make_link_name(IP, WhatsappAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = WhatsappAccount


class IPToLinkedinAccount(metaclass=Link):
    name = Utils.make_link_name(IP, LinkedinAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = LinkedinAccount


class IPToIcqAccount(metaclass=Link):
    name = Utils.make_link_name(IP, IcqAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = IcqAccount


class IPToGooglePlusAccount(metaclass=Link):
    name = Utils.make_link_name(IP, GooglePlusAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = GooglePlusAccount


class IPToFlickrAccount(metaclass=Link):
    name = Utils.make_link_name(IP, FlickrAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = FlickrAccount


class IPToFoursquareAccount(metaclass=Link):
    name = Utils.make_link_name(IP, FoursquareAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = FoursquareAccount


class IPToGithubAccount(metaclass=Link):
    name = Utils.make_link_name(IP, GithubAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = GithubAccount


class IPToTwitterAccount(metaclass=Link):
    name = Utils.make_link_name(IP, TwitterAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = TwitterAccount


class IPToMyspaceAccount(metaclass=Link):
    name = Utils.make_link_name(IP, MyspaceAccount)

    Value = Attributes.System.Value

    Begin = IP
    End = MyspaceAccount


class PhoneNumberToSkypeAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, SkypeAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = SkypeAccount


class PhoneNumberToFacebookAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, FacebookAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = FacebookAccount


class PhoneNumberToTelegramAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, TelegramAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = TelegramAccount


class PhoneNumberToWhatsappAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, WhatsappAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = WhatsappAccount


class PhoneNumberToLinkedinAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, LinkedinAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = LinkedinAccount


class PhoneNumberToIcqAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, IcqAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = IcqAccount


class PhoneNumberToGooglePlusAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, GooglePlusAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = GooglePlusAccount


class PhoneNumberToFlickrAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, FlickrAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = FlickrAccount


class PhoneNumberToFoursquareAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, FoursquareAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = FoursquareAccount


class PhoneNumberToGithubAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, GithubAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = GithubAccount


class PhoneNumberToTwitterAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, TwitterAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = TwitterAccount


class PhoneNumberToMyspaceAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, MyspaceAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = MyspaceAccount


class WebcamToPerson(metaclass=Link):
    name = Utils.make_link_name(Webcam, Person)

    Value = Attributes.System.Value

    Begin = Webcam
    End = Person


class WebcamToOrganisation(metaclass=Link):
    name = Utils.make_link_name(Webcam, Organisation)

    Value = Attributes.System.Value

    Begin = Webcam
    End = Organisation


class WebcamToWork(metaclass=Link):
    name = Utils.make_link_name(Webcam, Work)

    Value = Attributes.System.Value

    Begin = Webcam
    End = Work


class WebcamToSchool(metaclass=Link):
    name = Utils.make_link_name(Webcam, School)

    Value = Attributes.System.Value

    Begin = Webcam
    End = School


class WebcamToUniversity(metaclass=Link):
    name = Utils.make_link_name(Webcam, University)

    Value = Attributes.System.Value

    Begin = Webcam
    End = University


class NetworkInterfaceToPerson(metaclass=Link):
    name = Utils.make_link_name(NetworkInterface, Person)

    Value = Attributes.System.Value

    Begin = NetworkInterface
    End = Person


class NetworkInterfaceToOrganisation(metaclass=Link):
    name = Utils.make_link_name(NetworkInterface, Organisation)

    Value = Attributes.System.Value

    Begin = NetworkInterface
    End = Organisation


class NetworkInterfaceToWork(metaclass=Link):
    name = Utils.make_link_name(NetworkInterface, Work)

    Value = Attributes.System.Value

    Begin = NetworkInterface
    End = Work


class NetworkInterfaceToSchool(metaclass=Link):
    name = Utils.make_link_name(NetworkInterface, School)

    Value = Attributes.System.Value

    Begin = NetworkInterface
    End = School


class NetworkInterfaceToUniversity(metaclass=Link):
    name = Utils.make_link_name(NetworkInterface, University)

    Value = Attributes.System.Value

    Begin = NetworkInterface
    End = University


class NetworkInterfaceToAPT(metaclass=Link):
    name = Utils.make_link_name(NetworkInterface, APT)

    Value = Attributes.System.Value

    Begin = NetworkInterface
    End = APT


class URLToPerson(metaclass=Link):
    name = Utils.make_link_name(URL, Person)

    Value = Attributes.System.Value

    Begin = URL
    End = Person


class URLToOrganisation(metaclass=Link):
    name = Utils.make_link_name(URL, Organisation)

    Value = Attributes.System.Value

    Begin = URL
    End = Organisation


class URLToWork(metaclass=Link):
    name = Utils.make_link_name(URL, Work)

    Value = Attributes.System.Value

    Begin = URL
    End = Work


class URLToSchool(metaclass=Link):
    name = Utils.make_link_name(URL, School)

    Value = Attributes.System.Value

    Begin = URL
    End = School


class URLToUniversity(metaclass=Link):
    name = Utils.make_link_name(URL, University)

    Value = Attributes.System.Value

    Begin = URL
    End = University


class URLToAPT(metaclass=Link):
    name = Utils.make_link_name(URL, APT)

    Value = Attributes.System.Value

    Begin = URL
    End = APT


class URLToDomain(metaclass=Link):
    name = Utils.make_link_name(URL, Domain)

    Value = Attributes.System.Value

    Begin = URL
    End = Domain


class HashToAPT(metaclass=Link):
    name = Utils.make_link_name(Hash, APT)

    Value = Attributes.System.Value

    Begin = Hash
    End = APT


class AutonomousSystemToOrganisation(metaclass=Link):
    name = Utils.make_link_name(AutonomousSystem, Organisation)

    Value = Attributes.System.Value

    Begin = AutonomousSystem
    End = Organisation


class AutonomousSystemToWork(metaclass=Link):
    name = Utils.make_link_name(AutonomousSystem, Work)

    Value = Attributes.System.Value

    Begin = AutonomousSystem
    End = Work


class AutonomousSystemToSchool(metaclass=Link):
    name = Utils.make_link_name(AutonomousSystem, School)

    Value = Attributes.System.Value

    Begin = AutonomousSystem
    End = School


class AutonomousSystemToUniversity(metaclass=Link):
    name = Utils.make_link_name(AutonomousSystem, University)

    Value = Attributes.System.Value

    Begin = AutonomousSystem
    End = University


class PhoneBookToPerson(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, Person)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = Person


class PhoneBookToPhone(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, Phone)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = Phone


class PhoneBookToPhoneNumber(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, PhoneNumber)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = PhoneNumber


class PhoneBookToEmail(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, Email)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = Email


class PhoneBookToOrganisation(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, Organisation)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = Organisation


class PhoneBookToSkypeAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, SkypeAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = SkypeAccount


class PhoneBookToFacebookAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, FacebookAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = FacebookAccount


class PhoneBookToTelegramAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, TelegramAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = TelegramAccount


class PhoneBookToWhatsappAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, WhatsappAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = WhatsappAccount


class PhoneBookToLinkedinAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, LinkedinAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = LinkedinAccount


class PhoneBookToIcqAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, IcqAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = IcqAccount


class PhoneBookToGooglePlusAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, GooglePlusAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = GooglePlusAccount


class PhoneBookToFlickrAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, FlickrAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = FlickrAccount


class PhoneBookToFoursquareAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, FoursquareAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = FoursquareAccount


class PhoneBookToGithubAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, GithubAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = GithubAccount


class PhoneBookToTwitterAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, TwitterAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = TwitterAccount


class PhoneBookToMyspaceAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneBook, MyspaceAccount)

    Value = Attributes.System.Value

    Begin = PhoneBook
    End = MyspaceAccount


class SkypeAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(SkypeAccount, Organisation)

    Value = Attributes.System.Value

    Begin = SkypeAccount
    End = Organisation


class SkypeAccountToWork(metaclass=Link):
    name = Utils.make_link_name(SkypeAccount, Work)

    Value = Attributes.System.Value

    Begin = SkypeAccount
    End = Work


class SkypeAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(SkypeAccount, School)

    Value = Attributes.System.Value

    Begin = SkypeAccount
    End = School


class SkypeAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(SkypeAccount, University)

    Value = Attributes.System.Value

    Begin = SkypeAccount
    End = University


class SkypeAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(SkypeAccount, APT)

    Value = Attributes.System.Value

    Begin = SkypeAccount
    End = APT


class FacebookAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, APT)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = APT


class TelegramAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(TelegramAccount, Organisation)

    Value = Attributes.System.Value

    Begin = TelegramAccount
    End = Organisation


class TelegramAccountToWork(metaclass=Link):
    name = Utils.make_link_name(TelegramAccount, Work)

    Value = Attributes.System.Value

    Begin = TelegramAccount
    End = Work


class TelegramAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(TelegramAccount, School)

    Value = Attributes.System.Value

    Begin = TelegramAccount
    End = School


class TelegramAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(TelegramAccount, University)

    Value = Attributes.System.Value

    Begin = TelegramAccount
    End = University


class TelegramAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(TelegramAccount, APT)

    Value = Attributes.System.Value

    Begin = TelegramAccount
    End = APT


class WhatsappAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(WhatsappAccount, Organisation)

    Value = Attributes.System.Value

    Begin = WhatsappAccount
    End = Organisation


class WhatsappAccountToWork(metaclass=Link):
    name = Utils.make_link_name(WhatsappAccount, Work)

    Value = Attributes.System.Value

    Begin = WhatsappAccount
    End = Work


class WhatsappAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(WhatsappAccount, School)

    Value = Attributes.System.Value

    Begin = WhatsappAccount
    End = School


class WhatsappAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(WhatsappAccount, University)

    Value = Attributes.System.Value

    Begin = WhatsappAccount
    End = University


class WhatsappAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(WhatsappAccount, APT)

    Value = Attributes.System.Value

    Begin = WhatsappAccount
    End = APT


class LinkedinAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(LinkedinAccount, Organisation)

    Value = Attributes.System.Value

    Begin = LinkedinAccount
    End = Organisation


class LinkedinAccountToWork(metaclass=Link):
    name = Utils.make_link_name(LinkedinAccount, Work)

    WorkStartDate = Attributes.System.WorkStartDate
    WorkEndDate = Attributes.System.WorkEndDate

    Begin = LinkedinAccount
    End = Work


class LinkedinAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(LinkedinAccount, School)

    Value = Attributes.System.Value

    Begin = LinkedinAccount
    End = School


class LinkedinAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(LinkedinAccount, University)

    EntranceYear = Attributes.System.EntranceYear
    GraduationYear = Attributes.System.GraduationYear
    AcademicDegree = Attributes.System.AcademicDegree

    Begin = LinkedinAccount
    End = University


class LinkedinAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(LinkedinAccount, APT)

    Value = Attributes.System.Value

    Begin = LinkedinAccount
    End = APT


class IcqAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(IcqAccount, Organisation)

    Value = Attributes.System.Value

    Begin = IcqAccount
    End = Organisation


class IcqAccountToWork(metaclass=Link):
    name = Utils.make_link_name(IcqAccount, Work)

    Value = Attributes.System.Value

    Begin = IcqAccount
    End = Work


class IcqAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(IcqAccount, School)

    Value = Attributes.System.Value

    Begin = IcqAccount
    End = School


class IcqAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(IcqAccount, University)

    Value = Attributes.System.Value

    Begin = IcqAccount
    End = University


class IcqAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(IcqAccount, APT)

    Value = Attributes.System.Value

    Begin = IcqAccount
    End = APT


class GooglePlusAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(GooglePlusAccount, Organisation)

    Value = Attributes.System.Value

    Begin = GooglePlusAccount
    End = Organisation


class GooglePlusAccountToWork(metaclass=Link):
    name = Utils.make_link_name(GooglePlusAccount, Work)

    Value = Attributes.System.Value

    Begin = GooglePlusAccount
    End = Work


class GooglePlusAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(GooglePlusAccount, School)

    Value = Attributes.System.Value

    Begin = GooglePlusAccount
    End = School


class GooglePlusAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(GooglePlusAccount, University)

    Value = Attributes.System.Value

    Begin = GooglePlusAccount
    End = University


class GooglePlusAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(GooglePlusAccount, APT)

    Value = Attributes.System.Value

    Begin = GooglePlusAccount
    End = APT


class GooglePlusAccountToURL(metaclass=Link):
    name = Utils.make_link_name(GooglePlusAccount, URL)

    Value = Attributes.System.Value

    Begin = GooglePlusAccount
    End = URL


class GooglePlusAccountToFacebookAccount(metaclass=Link):
    name = Utils.make_link_name(GooglePlusAccount, FacebookAccount)

    Value = Attributes.System.Value

    Begin = GooglePlusAccount
    End = FacebookAccount


class AbstractUserToTumblrAccount(metaclass=Link):
    name = Utils.make_link_name(AbstractUser, TumblrAccount)

    Value = Attributes.System.Value

    Begin = AbstractUser
    End = TumblrAccount


class AbstractUserToFlickrAccount(metaclass=Link):
    name = Utils.make_link_name(AbstractUser, FlickrAccount)

    Value = Attributes.System.Value

    Begin = AbstractUser
    End = FlickrAccount


class AbstractUserToPeriscopeAccount(metaclass=Link):
    name = Utils.make_link_name(AbstractUser, PeriscopeAccount)

    Value = Attributes.System.Value

    Begin = AbstractUser
    End = PeriscopeAccount


class AbstractUserToGithubAccount(metaclass=Link):
    name = Utils.make_link_name(AbstractUser, GithubAccount)

    Value = Attributes.System.Value

    Begin = AbstractUser
    End = GithubAccount


class AbstractUserToTwitterAccount(metaclass=Link):
    name = Utils.make_link_name(AbstractUser, TwitterAccount)

    Value = Attributes.System.Value

    Begin = AbstractUser
    End = TwitterAccount


class AbstractUserToBitbucketAccount(metaclass=Link):
    name = Utils.make_link_name(AbstractUser, BitbucketAccount)

    Value = Attributes.System.Value

    Begin = AbstractUser
    End = BitbucketAccount


class BitbucketAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(BitbucketAccount, Person)

    Value = Attributes.System.Value

    Begin = BitbucketAccount
    End = Person


class GooglePlusAccountToLinkedinAccount(metaclass=Link):
    name = Utils.make_link_name(GooglePlusAccount, LinkedinAccount)

    Value = Attributes.System.Value

    Begin = GooglePlusAccount
    End = LinkedinAccount


class GooglePlusAccountToTwitterAccount(metaclass=Link):
    name = Utils.make_link_name(GooglePlusAccount, TwitterAccount)

    Value = Attributes.System.Value

    Begin = GooglePlusAccount
    End = TwitterAccount


class FlickrAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(FlickrAccount, Organisation)

    Value = Attributes.System.Value

    Begin = FlickrAccount
    End = Organisation


class FlickrAccountToWork(metaclass=Link):
    name = Utils.make_link_name(FlickrAccount, Work)

    Value = Attributes.System.Value

    Begin = FlickrAccount
    End = Work


class FlickrAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(FlickrAccount, School)

    Value = Attributes.System.Value

    Begin = FlickrAccount
    End = School


class FlickrAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(FlickrAccount, University)

    Value = Attributes.System.Value

    Begin = FlickrAccount
    End = University


class FlickrAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(FlickrAccount, APT)

    Value = Attributes.System.Value

    Begin = FlickrAccount
    End = APT


class FoursquareAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(FoursquareAccount, Organisation)

    Value = Attributes.System.Value

    Begin = FoursquareAccount
    End = Organisation


class FoursquareAccountToWork(metaclass=Link):
    name = Utils.make_link_name(FoursquareAccount, Work)

    Value = Attributes.System.Value

    Begin = FoursquareAccount
    End = Work


class FoursquareAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(FoursquareAccount, School)

    Value = Attributes.System.Value

    Begin = FoursquareAccount
    End = School


class FoursquareAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(FoursquareAccount, University)

    Value = Attributes.System.Value

    Begin = FoursquareAccount
    End = University


class FoursquareAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(FoursquareAccount, APT)

    Value = Attributes.System.Value

    Begin = FoursquareAccount
    End = APT


class GithubAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(GithubAccount, Organisation)

    Value = Attributes.System.Value

    Begin = GithubAccount
    End = Organisation


class GithubAccountToWork(metaclass=Link):
    name = Utils.make_link_name(GithubAccount, Work)

    Value = Attributes.System.Value

    Begin = GithubAccount
    End = Work


class GithubAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(GithubAccount, School)

    Value = Attributes.System.Value

    Begin = GithubAccount
    End = School


class GithubAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(GithubAccount, University)

    Value = Attributes.System.Value

    Begin = GithubAccount
    End = University


class GithubAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(GithubAccount, APT)

    Value = Attributes.System.Value

    Begin = GithubAccount
    End = APT


class TwitterAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(TwitterAccount, Organisation)

    Value = Attributes.System.Value

    Begin = TwitterAccount
    End = Organisation


class TwitterAccountToWork(metaclass=Link):
    name = Utils.make_link_name(TwitterAccount, Work)

    Value = Attributes.System.Value

    Begin = TwitterAccount
    End = Work


class TwitterAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(TwitterAccount, School)

    Value = Attributes.System.Value

    Begin = TwitterAccount
    End = School


class TwitterAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(TwitterAccount, University)

    Value = Attributes.System.Value

    Begin = TwitterAccount
    End = University


class TwitterAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(TwitterAccount, APT)

    Value = Attributes.System.Value

    Begin = TwitterAccount
    End = APT


class MyspaceAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(MyspaceAccount, Organisation)

    Value = Attributes.System.Value

    Begin = MyspaceAccount
    End = Organisation


class MyspaceAccountToWork(metaclass=Link):
    name = Utils.make_link_name(MyspaceAccount, Work)

    Value = Attributes.System.Value

    Begin = MyspaceAccount
    End = Work


class MyspaceAccountToSchool(metaclass=Link):
    name = Utils.make_link_name(MyspaceAccount, School)

    Value = Attributes.System.Value

    Begin = MyspaceAccount
    End = School


class MyspaceAccountToUniversity(metaclass=Link):
    name = Utils.make_link_name(MyspaceAccount, University)

    Value = Attributes.System.Value

    Begin = MyspaceAccount
    End = University


class MyspaceAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(MyspaceAccount, APT)

    Value = Attributes.System.Value

    Begin = MyspaceAccount
    End = APT


# endregion


# region OSINT
class LocationToCountry(metaclass=Link):
    name = Utils.make_link_name(Location, Country)

    Value = Attributes.System.Value

    Begin = Location
    End = Country


class LocationToCity(metaclass=Link):
    name = Utils.make_link_name(Location, City)

    Value = Attributes.System.Value

    Begin = Location
    End = City


class CountryToCity(metaclass=Link):
    name = Utils.make_link_name(Country, City)

    Value = Attributes.System.Value

    Begin = Country
    End = City


class SchoolToLocation(metaclass=Link):
    name = Utils.make_link_name(School, Location)

    Value = Attributes.System.Value

    Begin = School
    End = Location


class SchoolToCountry(metaclass=Link):
    name = Utils.make_link_name(School, Country)

    Value = Attributes.System.Value

    Begin = School
    End = Country


class SchoolToCity(metaclass=Link):
    name = Utils.make_link_name(School, City)

    Value = Attributes.System.Value

    Begin = School
    End = City


class UniversityToCountry(metaclass=Link):
    name = Utils.make_link_name(University, Country)

    Value = Attributes.System.Value

    Begin = University
    End = Country


class UniversityToCity(metaclass=Link):
    name = Utils.make_link_name(University, City)

    Value = Attributes.System.Value

    Begin = University
    End = City


class WorkToCountry(metaclass=Link):
    name = Utils.make_link_name(Work, Country)

    Value = Attributes.System.Value

    Begin = Work
    End = Country


class WorkToCity(metaclass=Link):
    name = Utils.make_link_name(Work, City)

    Value = Attributes.System.Value

    Begin = Work
    End = City


class FacebookAccountToUrl(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, URL)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = URL


class FacebookAccountToEmail(metaclass=Link):
    name = Utils.make_link_name(FacebookAccount, Email)

    Value = Attributes.System.Value

    Begin = FacebookAccount
    End = Email


class GithubAccountToGithubOrganization(metaclass=Link):
    name = Utils.make_link_name(GithubAccount, GithubOrganization)

    Value = Attributes.System.Value

    Begin = GithubAccount
    End = GithubOrganization


class InstagramAccountToUrl(metaclass=Link):
    name = Utils.make_link_name(InstagramAccount, URL)

    Value = Attributes.System.Value

    Begin = InstagramAccount
    End = URL


class PersonToBritishCompany(metaclass=Link):
    name = Utils.make_link_name(Person, EngCompany)

    Value = Attributes.System.Value
    AppointedOn = Attributes.AppointedOn
    OfficerRole = Attributes.System.Role

    Begin = EngCompanyPerson
    End = EngCompany

    CaptionAttrs = [OfficerRole]


class EngCompanyToPerson(metaclass=Link):
    name = Utils.make_link_name(EngCompany, Person)

    Value = Attributes.System.Value

    Begin = EngCompany
    End = EngCompanyPerson


class ViberAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(ViberAccount, Person)

    Value = Attributes.System.Value

    Begin = ViberAccount
    End = Person


class PhoneNumberToViberAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, ViberAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = ViberAccount


class EmailToDeezerAccount(metaclass=Link):
    name = Utils.make_link_name(Email, DeezerAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = DeezerAccount


class EmailToVivinoAccount(metaclass=Link):
    name = Utils.make_link_name(Email, VivinoAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = VivinoAccount


class EmailToDuolingoAccount(metaclass=Link):
    name = Utils.make_link_name(Email, DuolingoAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = DuolingoAccount


class DeezerAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(DeezerAccount, Person)

    Value = Attributes.System.Value

    Begin = DeezerAccount
    End = Person


class DeezerAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(DeezerAccount, Organisation)

    Value = Attributes.System.Value

    Begin = DeezerAccount
    End = Organisation


class DeezerAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(DeezerAccount, APT)

    Value = Attributes.System.Value

    Begin = DeezerAccount
    End = APT


class VivinoAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(VivinoAccount, Person)

    Value = Attributes.System.Value

    Begin = VivinoAccount
    End = Person


class VivinoAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(VivinoAccount, Organisation)

    Value = Attributes.System.Value

    Begin = VivinoAccount
    End = Organisation


class VivinoAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(VivinoAccount, APT)

    Value = Attributes.System.Value

    Begin = VivinoAccount
    End = APT


class DuolingoAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(DuolingoAccount, Person)

    Value = Attributes.System.Value

    Begin = DuolingoAccount
    End = Person


class DuolingoAccountToOrganisation(metaclass=Link):
    name = Utils.make_link_name(DuolingoAccount, Organisation)

    Value = Attributes.System.Value

    Begin = DuolingoAccount
    End = Organisation


class DuolingoAccountToAPT(metaclass=Link):
    name = Utils.make_link_name(DuolingoAccount, APT)

    Value = Attributes.System.Value

    Begin = DuolingoAccount
    End = APT


class FoursquareAccountToFacebookAccount(metaclass=Link):
    name = Utils.make_link_name(FoursquareAccount, FacebookAccount)

    Value = Attributes.System.Value

    Begin = FoursquareAccount
    End = FacebookAccount


class FoursquareAccountToTwitterAccount(metaclass=Link):
    name = Utils.make_link_name(FoursquareAccount, TwitterAccount)

    Value = Attributes.System.Value

    Begin = FoursquareAccount
    End = TwitterAccount


class FoursquareAccountToURL(metaclass=Link):
    name = Utils.make_link_name(FoursquareAccount, URL)

    Value = Attributes.System.Value

    Begin = FoursquareAccount
    End = URL


class TorNodeToCountry(metaclass=Link):
    name = Utils.make_link_name(TorNode, Country)

    Value = Attributes.System.Value

    Begin = TorNode
    End = Country


class TorNodeToCity(metaclass=Link):
    name = Utils.make_link_name(TorNode, City)

    Value = Attributes.System.Value

    Begin = TorNode
    End = City


class IPToTorNode(metaclass=Link):
    name = Utils.make_link_name(IP, TorNode)

    Datetime = Attributes.System.Datetime

    Begin = IP
    End = TorNode


class EmailToNikePlusAccount(metaclass=Link):
    name = Utils.make_link_name(Email, NikePlusAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = NikePlusAccount


class NikePlusAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(NikePlusAccount, Person)

    Value = Attributes.System.Value

    Begin = NikePlusAccount
    End = Person


class EmailToRunkeeperAccount(metaclass=Link):
    name = Utils.make_link_name(Email, RunkeeperAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = RunkeeperAccount


class RunkeeperAccountToFacebookAccount(metaclass=Link):
    name = Utils.make_link_name(RunkeeperAccount, FacebookAccount)

    Value = Attributes.System.Value

    Begin = RunkeeperAccount
    End = FacebookAccount


class RunkeeperAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(RunkeeperAccount, Person)

    Value = Attributes.System.Value

    Begin = RunkeeperAccount
    End = Person


class EmailToStravaAccount(metaclass=Link):
    name = Utils.make_link_name(Email, StravaAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = StravaAccount

class StravaAccountToURL(metaclass=Link):
    name = Utils.make_link_name(StravaAccount, URL)

    Value = Attributes.System.Value

    Begin = StravaAccount
    End = URL

class StravaAccountToFacebookAccount(metaclass=Link):
    name = Utils.make_link_name(StravaAccount, FacebookAccount)

    Value = Attributes.System.Value

    Begin = StravaAccount
    End = FacebookAccount

class StravaAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(StravaAccount, Person)

    Value = Attributes.System.Value

    Begin = StravaAccount
    End = Person


class EmailToBookmateAccount(metaclass=Link):
    name = Utils.make_link_name(Email, BookmateAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = BookmateAccount


class PhoneNumberToBookmateAccount(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, BookmateAccount)

    Value = Attributes.System.Value

    Begin = PhoneNumber
    End = BookmateAccount


class BookmateAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(BookmateAccount, Person)

    Value = Attributes.System.Value

    Begin = BookmateAccount
    End = Person


class EmailToTumblrAccount(metaclass=Link):
    name = Utils.make_link_name(Email, TumblrAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = TumblrAccount


class TumblrAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(TumblrAccount, Person)

    Value = Attributes.System.Value

    Begin = TumblrAccount
    End = Person


class EmailToGoodreadsAccount(metaclass=Link):
    name = Utils.make_link_name(Email, GoodreadsAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = GoodreadsAccount


class GoodreadsAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(GoodreadsAccount, Person)

    Value = Attributes.System.Value

    Begin = GoodreadsAccount
    End = Person


class EmailToGravatarAccount(metaclass=Link):
    name = Utils.make_link_name(Email, GravatarAccount)

    Value = Attributes.System.Value

    Begin = Email
    End = GravatarAccount


class GravatarAccountToUrl(metaclass=Link):
    name = Utils.make_link_name(GravatarAccount, URL)

    Value = Attributes.System.Value

    Begin = GravatarAccount
    End = URL


class GravatarAccountToPerson(metaclass=Link):
    name = Utils.make_link_name(GravatarAccount, Person)

    Value = Attributes.System.Value

    Begin = GravatarAccount
    End = Person


class EmailToFullcontactPersonInfo(metaclass=Link):
    name = Utils.make_link_name(Email, FullcontactPersonInfo)

    Value = Attributes.System.Value

    Begin = Email
    End = FullcontactPersonInfo


class PhoneToFullcontactPersonInfo(metaclass=Link):
    name = Utils.make_link_name(FullcontactPersonInfo, Phone)

    Value = Attributes.System.Value

    Begin = Phone
    End = FullcontactPersonInfo


class FullcontactPersonInfoToUniversity(metaclass=Link):
    name = Utils.make_link_name(FullcontactPersonInfo, University)

    Value = Attributes.System.Value

    Begin = FullcontactPersonInfo
    End = University


class FullcontactPersonInfoToURL(metaclass=Link):
    name = Utils.make_link_name(FullcontactPersonInfo, URL)

    Value = Attributes.System.Value

    Begin = FullcontactPersonInfo
    End = URL


class FullcontactPersonInfoToDomain(metaclass=Link):
    name = Utils.make_link_name(FullcontactPersonInfo, Domain)

    Value = Attributes.System.Value

    Begin = FullcontactPersonInfo
    End = Domain


class FullcontactPersonInfoToTwitterAccount(metaclass=Link):
    name = Utils.make_link_name(FullcontactPersonInfo, TwitterAccount)

    Value = Attributes.System.Value

    Begin = FullcontactPersonInfo
    End = TwitterAccount


class FullcontactPersonInfoToFacebookAccount(metaclass=Link):
    name = Utils.make_link_name(FullcontactPersonInfo, FacebookAccount)

    Value = Attributes.System.Value

    Begin = FullcontactPersonInfo
    End = FacebookAccount


class FullcontactPersonInfoToLinkedinAccount(metaclass=Link):
    name = Utils.make_link_name(FullcontactPersonInfo, LinkedinAccount)

    Value = Attributes.System.Value

    Begin = FullcontactPersonInfo
    End = LinkedinAccount


class BankCardToPerson(metaclass=Link):
    name = Utils.make_link_name(BankCard, Person)

    Emptiness = Attributes.System.Emptiness

    Begin = BankCard
    End = Person


class BankCardToCountry(metaclass=Link):
    name = Utils.make_link_name(BankCard, Country)

    Value = Attributes.System.Value

    Begin = BankCard
    End = Country


class BankCardToURL(metaclass=Link):
    name = Utils.make_link_name(BankCard, URL)

    Value = Attributes.System.Value

    Begin = BankCard
    End = URL


class FacebookLikes(metaclass=Link):
    name = 'Facebook likes'

    Count = Attributes.System.Count

    Begin = FacebookAccount
    End = FacebookAccount

    CaptionAttrs = [Count]


class FacebookReposts(metaclass=Link):
    name = 'Facebook reposts'

    Count = Attributes.System.Count

    Begin = FacebookAccount
    End = FacebookAccount

    CaptionAttrs = [Count]


class FacebookComments(metaclass=Link):
    name = 'Facebook comments'

    Count = Attributes.System.Count

    Begin = FacebookAccount
    End = FacebookAccount

    CaptionAttrs = [Count]


class WikipediaUserEdit(metaclass=Link):
    name = 'Wikipedia user edit'

    Datetime = Attributes.System.Datetime
    BytesChanged = Attributes.BytesChanged

    Begin = WikipediaUser
    End = WikipediaArticle


class WikipediaIPEdit(metaclass=Link):
    name = 'Wikipedia IP edit'

    Datetime = Attributes.System.Datetime
    BytesChanged = Attributes.BytesChanged

    Begin = IP
    End = WikipediaArticle


class CarToCountry(metaclass=Link):
    name = Utils.make_link_name(Car, Country)

    Value = Attributes.System.Value

    Begin = Car
    End = Country


class BitcoinWalletToBitcoinWallet(metaclass=Link):
    name = Utils.make_link_name(BitcoinWallet, BitcoinWallet)

    TransactionAmount = Attributes.TransactionAmount
    InputScript = Attributes.InputScript
    OutScript = Attributes.OutScript
    TransactionHash = Attributes.TransactionHash
    Datetime = Attributes.System.Datetime

    Begin = BitcoinWallet
    End = BitcoinWallet
    CaptionAttrs = [TransactionAmount, Datetime]


class BitcoinWalletToTransactionMix(metaclass=Link):
    name = Utils.make_link_name(BitcoinWallet, TransactionMix)

    TransactionAmount = Attributes.TransactionAmount
    InputScript = Attributes.InputScript
    TransactionHash = Attributes.TransactionHash
    Datetime = Attributes.System.Datetime

    Begin = BitcoinWallet
    End = TransactionMix

    CaptionAttrs = [TransactionAmount, Datetime]


class TransactionMixToBitcoinWallet(metaclass=Link):
    name = Utils.make_link_name(TransactionMix, BitcoinWallet)

    TransactionAmount = Attributes.TransactionAmount
    OutScript = Attributes.OutScript
    TransactionHash = Attributes.TransactionHash
    Datetime = Attributes.System.Datetime

    Begin = TransactionMix
    End = BitcoinWallet
    CaptionAttrs = [TransactionAmount, Datetime]


class PhotoToFlickrAccount(metaclass=Link):
    name = Utils.make_link_name(Photo, FlickrAccount)

    Value = Attributes.System.Value

    Begin = Photo
    End = FlickrAccount


class PhotoToFoursquareAccount(metaclass=Link):
    name = Utils.make_link_name(Photo, FoursquareAccount)

    Value = Attributes.System.Value

    Begin = Photo
    End = FoursquareAccount


class PhotoToInstagramAccount(metaclass=Link):
    name = Utils.make_link_name(Photo, InstagramAccount)

    Value = Attributes.System.Value

    Begin = Photo
    End = InstagramAccount


class InstagramPostToInstagramAccount(metaclass=Link):
    name = Utils.make_link_name(InstagramPost, InstagramAccount)

    Value = Attributes.System.Value

    Begin = InstagramPost
    End = InstagramAccount


class StreamToPeriscopeAccount(metaclass=Link):
    name = Utils.make_link_name(Stream, PeriscopeAccount)

    Value = Attributes.System.Value

    Begin = Stream
    End = PeriscopeAccount


class TweetToTwitterAccount(metaclass=Link):
    name = Utils.make_link_name(Tweet, TwitterAccount)

    Value = Attributes.System.Value

    Begin = Tweet
    End = TwitterAccount


class PhotoToVKAccount(metaclass=Link):
    name = Utils.make_link_name(Photo, VKAccount)

    Value = Attributes.System.Value

    Begin = Photo
    End = VKAccount


class PhotoToCarRecord(metaclass=Link):
    name = Utils.make_link_name(Photo, CarRecord)

    Value = Attributes.System.Value

    Begin = Photo
    End = CarRecord


class LinkedinAccountToLinkedinCompany(metaclass=Link):
    name = Utils.make_link_name(LinkedinAccount, LinkedinCompany)

    Value = Attributes.System.Value

    Begin = LinkedinAccount
    End = LinkedinCompany

    CaptionAttrs = [Value]


# endregion


# region Shodan
class ShodanServiceToIP(metaclass=Link):
    name = Utils.make_link_name(ShodanService, IP)

    Port = Attributes.System.Port

    Begin = ShodanService
    End = IP


class ShodanServiceToDomain(metaclass=Link):
    name = Utils.make_link_name(ShodanService, Domain)

    Port = Attributes.System.Port

    Begin = ShodanService
    End = Domain


class DomainToOrganisation(metaclass=Link):
    name = Utils.make_link_name(Domain, Organisation)

    Appeared = Attributes.System.LastAppearance

    Begin = Domain
    End = Organisation


class ServiceProductToIP(metaclass=Link):
    name = Utils.make_link_name(NetworkService, IP)

    Transport = Attributes.System.TransportLayerProto
    Port = Attributes.System.Port

    Begin = NetworkService
    End = IP


class ServiceProductToPort(metaclass=Link):
    name = Utils.make_link_name(NetworkService, Port)

    Transport = Attributes.System.TransportLayerProto

    Begin = NetworkService
    End = Port


class VulnerabilityToShodanService(metaclass=Link):
    name = Utils.make_link_name(Vulnerability, ShodanService)

    Verified = Attributes.Verified

    Begin = Vulnerability
    End = ShodanService


class CertificateToShodanService(metaclass=Link):
    Begin = Certificate
    End = ShodanService


class CertificateToDomain(metaclass=Link):
    Begin = Certificate
    End = Domain


class CertificateIssuerToCertificate(metaclass=Link):
    Begin = CertificateIssuer
    End = Certificate


class OrganisationToCertificate(metaclass=Link):
    Begin = Organisation
    End = Certificate


class OrganisationToCertificateIssuer(metaclass=Link):
    Begin = Organisation
    End = CertificateIssuer
# endregion


# region VirusTotal
class DomainToSample(metaclass=Link):
    name = Utils.make_link_name(Domain, VTSample)

    Appeared = Attributes.System.LastAppearance
    Positives = Attributes.AVPositives

    Begin = Domain
    End = VTSample


class DomainToVTURL(metaclass=Link):
    name = Utils.make_link_name(Domain, VTURL)

    Appeared = Attributes.System.LastAppearance
    Positives = Attributes.AVPositives

    Begin = Domain
    End = VTURL


class SampleToHash(metaclass=Link):
    name = Utils.make_link_name(VTSample, Hash)

    Appeared = Attributes.System.LastAppearance

    Begin = VTSample
    End = Hash


class IPToSample(metaclass=Link):
    name = Utils.make_link_name(IP, VTSample)

    Appeared = Attributes.System.LastAppearance

    Begin = IP
    End = VTSample


class IPToVTURL(metaclass=Link):
    name = Utils.make_link_name(IP, VTURL)

    Appeared = Attributes.System.LastAppearance
    Positives = Attributes.AVPositives

    Begin = IP
    End = VTURL


class VTURLToVTScanResult(metaclass=Link):
    name = Utils.make_link_name(VTURL, VTScanResult)

    Appeared = Attributes.System.LastAppearance
    Positives = Attributes.AVPositives

    Begin = VTURL
    End = VTScanResult


class VTReportToVTScanResult(metaclass=Link):
    name = Utils.make_link_name(VTScannerReport, VTScanResult)

    ScanResult = Attributes.VTScanResult

    Begin = VTScannerReport
    End = VTScanResult


class HashToVTScanResult(metaclass=Link):
    name = Utils.make_link_name(Hash, VTScanResult)

    Positives = Attributes.AVPositives

    Begin = Hash
    End = VTScanResult


class HashToDomain(metaclass=Link):
    name = Utils.make_link_name(Hash, Domain)

    Value = Attributes.System.Value

    Begin = Hash
    End = Domain


class HashToURL(metaclass=Link):
    name = Utils.make_link_name(Hash, URL)

    Value = Attributes.System.Value

    Begin = Hash
    End = URL


# endregion


# region AIPDB
class AbuseToIP(metaclass=Link):
    name = Utils.make_link_name(Abuse, IP)

    Date = Attributes.System.Datetime

    Begin = Abuse
    End = IP


# endregion


# region Cymon
class CymonEventToIP(metaclass=Link):
    name = Utils.make_link_name(CymonEvent, IP)

    Date = Attributes.System.Datetime

    Begin = CymonEvent
    End = IP


# endregion


# region Hybrid
class HybridReportToIP(metaclass=Link):
    name = Utils.make_link_name(HybridReport, IP)

    Datetime = Attributes.System.Datetime

    Begin = HybridReport
    End = IP


class HybridReportToDomain(metaclass=Link):
    name = Utils.make_link_name(HybridReport, Domain)

    Datetime = Attributes.System.Datetime

    Begin = HybridReport
    End = Domain


class HybridReportToURL(metaclass=Link):
    name = Utils.make_link_name(HybridReport, URL)

    Datetime = Attributes.System.Datetime

    Begin = HybridReport
    End = URL


class HybridReportToHash(metaclass=Link):
    name = Utils.make_link_name(HybridReport, Hash)

    Datetime = Attributes.System.Datetime

    Begin = HybridReport
    End = Hash


class MitreAttckToHybridReport(metaclass=Link):
    name = Utils.make_link_name(MitreAttck, HybridReport)

    Value = Attributes.System.Value

    Begin = MitreAttck
    End = HybridReport


class HybridExtraFileToHybridReport(metaclass=Link):
    name = Utils.make_link_name(HybridExtraFile, HybridReport)

    Value = Attributes.System.Value

    Begin = HybridExtraFile
    End = HybridReport


class HybridProcessToHybridReport(metaclass=Link):
    name = Utils.make_link_name(HybridProcess, HybridReport)

    Value = Attributes.System.Value

    Begin = HybridProcess
    End = HybridReport


class HybridCertificateToHybridReport(metaclass=Link):
    name = Utils.make_link_name(HybridCertificate, HybridReport)

    Value = Attributes.System.Value

    Begin = HybridCertificate
    End = HybridReport


class HashToHybridReport(metaclass=Link):
    name = Utils.make_link_name(Hash, HybridReport)

    HashAlgo = Attributes.System.HashAlgo

    Begin = Hash
    End = HybridReport


# endregion


# region HIBP
class BreachToDomain(metaclass=Link):
    name = Utils.make_link_name(HIBPBreach, Domain)

    DataClass = Attributes.HIBPDataClass

    BreachDate = Attributes.HIBPBreachDate
    AddedDate = Attributes.System.DateCreated
    ModifiedDate = Attributes.System.DateModified

    Begin = HIBPBreach
    End = Domain


class BreachToEmail(metaclass=Link):
    name = Utils.make_link_name(HIBPBreach, Email)

    DataClass = Attributes.HIBPDataClass

    BreachDate = Attributes.HIBPBreachDate
    AddedDate = Attributes.System.DateCreated
    ModifiedDate = Attributes.System.DateModified

    Begin = HIBPBreach
    End = Email


class PasteToEmail(metaclass=Link):
    name = Utils.make_link_name(HIBPPaste, Email)

    PasteDate = Attributes.System.DateString

    Begin = HIBPPaste
    End = Email


# endregion


# region Torrents
class IPToTorrentService(metaclass=Link):
    name = Utils.make_link_name(IP, TorrentService)
    Value = Attributes.System.Value
    DateTime = Attributes.System.Datetime
    Begin = IP
    End = TorrentService


# endregion


# region HTTPS
class SSLCertificateSerialNumberToDomain(metaclass=Link):
    name = Utils.make_link_name(SSLCertificateSerialNumber, Domain)

    Value = Attributes.System.Value
    DateTime = Attributes.System.Datetime

    Begin = SSLCertificateSerialNumber
    End = Domain


class SSLCertificateToDomain(metaclass=Link):
    name = Utils.make_link_name(SSLCertificate, Domain)

    Value = Attributes.System.Value
    DateTime = Attributes.System.Datetime

    Begin = SSLCertificate
    End = Domain


class SSLCertificateToIP(metaclass=Link):
    name = Utils.make_link_name(SSLCertificate, IP)

    Value = Attributes.System.Value
    DateTime = Attributes.System.Datetime

    Begin = SSLCertificate
    End = IP


class DomainToDomainWithDate(metaclass=Link):
    name = Utils.make_link_name(Domain, Domain) + ' timeline'
    DateTime = Attributes.System.Datetime

    Begin = Domain
    End = Domain


class EntityToDomain(metaclass=Link):
    name = Utils.make_link_name(Entity, Domain)

    Value = Attributes.System.Value
    DateTime = Attributes.System.Datetime

    Begin = Entity
    End = Domain


class SectigoSertificateEntryToDomain(metaclass=Link):
    name = Utils.make_link_name(SectigoSertificateEntry, Domain)

    Value = Attributes.System.Value
    Datetime = Attributes.System.Datetime

    Begin = SectigoSertificateEntry
    End = Domain


# endregion


# region Mongodb
class MongoDBCollectionToMongoDatabase(metaclass=Link):
    name = Utils.make_link_name(MongoDBCollection, MongoDatabase)

    Value = Attributes.System.Value

    Begin = MongoDBCollection
    End = MongoDatabase


class IPToMongoDatabase(metaclass=Link):
    name = Utils.make_link_name(IP, MongoDatabase)

    Value = Attributes.System.Value

    Begin = IP
    End = MongoDatabase


class ShodanServiceToMongoDatabase(metaclass=Link):
    name = Utils.make_link_name(ShodanService, MongoDatabase)

    Value = Attributes.System.Value

    Begin = ShodanService
    End = MongoDatabase


# endregion


# region Elasticsearch
class ElasticNodeMToElasticNode(metaclass=Link):
    name = Utils.make_link_name(ElasticNodeM, ElasticNode)

    Value = Attributes.System.Datetime

    Begin = ElasticNodeM
    End = ElasticNode


class ElasticNodeToElasticIndex(metaclass=Link):
    name = Utils.make_link_name(ElasticNode, ElasticIndex)

    Value = Attributes.System.Datetime

    Begin = ElasticNode
    End = ElasticIndex


class IPToElasticNodeM(metaclass=Link):
    name = Utils.make_link_name(IP, ElasticNodeM)

    Value = Attributes.System.Datetime

    Begin = IP
    End = ElasticNodeM


class IPToElasticIndex(metaclass=Link):
    name = Utils.make_link_name(IP, ElasticIndex)

    Value = Attributes.System.Datetime

    Begin = IP
    End = ElasticIndex


class ShodanServiceToElasticNodeM(metaclass=Link):
    name = Utils.make_link_name(ShodanService, ElasticNodeM)

    Value = Attributes.System.Value

    Begin = ShodanService
    End = ElasticNodeM


# endregion


# region Miscellanous
class NetblockToAutonomousSystem(metaclass=Link):
    name = Utils.make_link_name(Netblock, AutonomousSystem)

    Emptiness = Attributes.System.Emptiness

    Begin = Netblock
    End = AutonomousSystem


class NetblockToOrganisation(metaclass=Link):
    name = Utils.make_link_name(Netblock, Organisation)

    Emptiness = Attributes.System.Emptiness

    Begin = Netblock
    End = Organisation


class IPToNetblock(metaclass=Link):
    name = Utils.make_link_name(IP, Netblock)

    Emptiness = Attributes.System.Emptiness

    Begin = IP
    End = Netblock


class URLToIP(metaclass=Link):
    name = Utils.make_link_name(URL, IP)

    Value = Attributes.System.Value

    Begin = URL
    End = IP


class PhoneNumberToURL(metaclass=Link):
    name = Utils.make_link_name(PhoneNumber, URL)

    Title = Attributes.System.Title

    Begin = PhoneNumber
    End = URL


class EmailToURL(metaclass=Link):
    name = Utils.make_link_name(Email, URL)

    Title = Attributes.System.Title

    Begin = Email
    End = URL


class DirectoryToDirectory(metaclass=Link):
    name = Utils.make_link_name(Directory, Directory)

    Emptiness = Attributes.System.Emptiness

    Begin = Directory
    End = Directory


class DirectoryToFile(metaclass=Link):
    name = Utils.make_link_name(Directory, File)

    Emptiness = Attributes.System.Emptiness

    Begin = Directory
    End = File


class IPToDirectory(metaclass=Link):
    name = Utils.make_link_name(IP, Directory)

    Emptiness = Attributes.System.Emptiness

    Begin = IP
    End = Directory


class DomainToDirectory(metaclass=Link):
    name = Utils.make_link_name(Domain, Directory)

    Emptiness = Attributes.System.Emptiness

    Begin = Domain
    End = Directory


# endregion


# region Urlscan.io
class WebRequestToWebRequest(metaclass=Link):
    name = Utils.make_link_name(WebRequest, WebRequest)

    HTTPMethod = Attributes.HTTPMethod
    StatusCode = Attributes.StatusCode

    Begin = WebRequest
    End = WebRequest


class WebRequestToIP(metaclass=Link):
    name = Utils.make_link_name(WebRequest, IP)

    Value = Attributes.System.Value

    Begin = WebRequest
    End = IP


class ElasticsearchQueryStringToUrlScanReport(metaclass=Link):
    name = Utils.make_link_name(ElasticsearchQueryString, UrlScanReport)

    Emptiness = Attributes.System.Emptiness

    Begin = ElasticsearchQueryString
    End = UrlScanReport


class IPToPoint(metaclass=Link):
    name = Utils.make_link_name(IP, Point)

    Value = Attributes.System.Value

    Begin = IP
    End = Point


class WebRequestToHash(metaclass=Link):
    name = Utils.make_link_name(WebRequest, Hash)

    Value = Attributes.System.Value

    Begin = WebRequest
    End = Hash


class UrlScanReportToWebRequest(metaclass=Link):
    name = Utils.make_link_name(UrlScanReport, WebRequest)

    Value = Attributes.System.Value

    Begin = UrlScanReport
    End = WebRequest


class UrlScanReportToHyperLink(metaclass=Link):
    name = Utils.make_link_name(UrlScanReport, HyperLink)

    Value = Attributes.System.Value

    Begin = UrlScanReport
    End = HyperLink


class HyperLinkToDomain(metaclass=Link):
    name = Utils.make_link_name(HyperLink, Domain)

    Value = Attributes.System.Value

    Begin = HyperLink
    End = Domain


class UrlScanReportToGlobalVariable(metaclass=Link):
    name = Utils.make_link_name(UrlScanReport, GlobalVariable)

    Value = Attributes.System.Value

    Begin = UrlScanReport
    End = GlobalVariable


class UrlScanReportToWebTechnology(metaclass=Link):
    name = Utils.make_link_name(UrlScanReport, WebTechnology)

    Value = Attributes.System.Value

    Begin = UrlScanReport
    End = WebTechnology


class UrlScanReportToHash(metaclass=Link):
    name = Utils.make_link_name(UrlScanReport, Hash)

    Value = Attributes.System.Value

    Begin = UrlScanReport
    End = Hash


class HashToHashMatch(metaclass=Link):
    name = Utils.make_link_name(Hash, HashMatch)

    Value = Attributes.System.Value

    Begin = Hash
    End = HashMatch


class URLToUrlScanReport(metaclass=Link):
    name = Utils.make_link_name(URL, UrlScanReport)

    Value = Attributes.System.Value

    Begin = URL
    End = UrlScanReport


class URLToURL(metaclass=Link):
    name = Utils.make_link_name(URL, URL)

    Value = Attributes.System.Value

    Begin = URL
    End = URL


# endregion


# endregion


# region Localization
ru_culture = LocalizationCulture('ru')

# region Objects localization
ru_culture.add(Abuse, 'Жалоба')
ru_culture.add(Address, 'Адрес')
ru_culture.add(APT, 'Угроза')
ru_culture.add(AutonomousSystem, 'Автономная система')
ru_culture.add(BaseStation, 'Базовая станция')
ru_culture.add(CallEvent, 'Звонок')
ru_culture.add(Car, 'Автомобиль')
ru_culture.add(CarRecord, 'Регистрация автомобиля')
ru_culture.add(City, 'Город')
ru_culture.add(Country, 'Страна')
ru_culture.add(Domain, 'Домен')
# ru_culture.add(Email, 'Email')
ru_culture.add(Entity, 'Сущность')
ru_culture.add(FacebookAccount, 'Аккаунт Facebook')
ru_culture.add(FlickrAccount, 'Аккаунт Flickr')
ru_culture.add(FoursquareAccount, 'Аккаунт Foursquare')
ru_culture.add(GithubAccount, 'Аккаунт Github')
ru_culture.add(GooglePlusAccount, 'Аккаунт Googleplus')
ru_culture.add(Hash, 'Хеш')
ru_culture.add(IcqAccount, 'Аккаунт ICQ')
# ru_culture.add(IMEI, 'IMEI')
# ru_culture.add(IMSI, 'IMSI')
# ru_culture.add(IP, 'IP')
ru_culture.add(LinkedinAccount, 'Аккаунт LinkedIn')
ru_culture.add(Location, 'Локация')
ru_culture.add(MyspaceAccount, 'Аккаунт Myspace')
ru_culture.add(NetworkInterface, 'Сетевой интерфейс')
ru_culture.add(Organisation, 'Организация')
ru_culture.add(Person, 'Персона')
ru_culture.add(Phone, 'Телефон')
ru_culture.add(PhoneBook, 'Телефонная книга')
ru_culture.add(PhoneNumber, 'Номер телефона')
ru_culture.add(Point, 'Точка')
ru_culture.add(Port, 'Порт')
ru_culture.add(School, 'Школа')
ru_culture.add(SkypeAccount, 'Аккаунт Skype')
ru_culture.add(TelegramAccount, 'Аккаунт Telegram')
ru_culture.add(TwitterAccount, 'Аккаунт Twitter')
ru_culture.add(URL, 'URL')
ru_culture.add(University, 'Университет')
ru_culture.add(Webcam, 'Вебкамера')
ru_culture.add(WhatsappAccount, 'Аккаунт Whatsapp')
ru_culture.add(Work, 'Работа')

ru_culture.add(TumblrAccount, 'Аккаунт Tumblr')
ru_culture.add(HIBPBreach, 'Утечка данных')
ru_culture.add(HIBPPaste, 'Копия текста')
ru_culture.add(HybridCertificate, 'Сертификат Hybrid')
ru_culture.add(HybridExtraFile, 'Извлечённый файл Hybrid')
ru_culture.add(HybridProcess, 'Процесс Hybrid')
ru_culture.add(HybridReport, 'Отчёт Hybrid')
ru_culture.add(MitreAttck, 'MITRE тактика')
ru_culture.add(MongoDBCollection, 'MongoDB: Коллекция')
ru_culture.add(MongoDatabase, 'MongoDB: БД')
ru_culture.add(NetworkService, 'Сетевая служба')
ru_culture.add(ShodanService, 'Shodan: служба')
ru_culture.add(TorNode, 'Узел Tor')
ru_culture.add(TorrentService, 'Торрент-раздача')

ru_culture.add(VTSample, 'Virustotal: образец')
ru_culture.add(VTScanResult, 'Virustotal: сканирование')
ru_culture.add(VTScannerReport, 'Virustotal: отчёт о сканировании')
ru_culture.add(VTURL, 'Virustotal: просканированный URL')
ru_culture.add(ViberAccount, 'Аккаунт Viber')
ru_culture.add(VivinoAccount, 'Аккаунт Vivino')
ru_culture.add(BookmateAccount, 'Аккаунт Bookmate')
ru_culture.add(CymonEvent, 'Отчёт Cymon')
ru_culture.add(CymonSource, 'Источник Cymon')
ru_culture.add(DeezerAccount, 'Аккаунт Deezer')
ru_culture.add(DuolingoAccount, 'Аккаунт Duolingo')
ru_culture.add(EngCompany, 'Британская компания')
ru_culture.add(EngCompanyPerson, 'Лицо в британской компании')
ru_culture.add(ElasticsearchQueryString, 'Строка запроса Elasticsearch')
ru_culture.add(UrlScanReport, 'Отчет Urlscan')
ru_culture.add(WebRequest, 'Веб-запрос')
ru_culture.add(HyperLink, 'Гиперссылка')
ru_culture.add(GlobalVariable, 'Глобальная переменная')
ru_culture.add(WebTechnology, 'Веб-технология')
ru_culture.add(HashMatch, 'Совпадение хэша')
ru_culture.add(File, 'Файл')
ru_culture.add(Directory, 'Директория')
ru_culture.add(WikipediaArticle, 'Статья Википедии')
ru_culture.add(WikipediaUser, 'Пользователь Википедии')

# requires localization!
ru_culture.add(BankCard, 'BankCard')
ru_culture.add(BitcoinWallet, 'BitcoinWallet')
ru_culture.add(ElasticIndex, 'ElasticIndex')
ru_culture.add(ElasticNode, 'ElasticNode')
ru_culture.add(ElasticNodeM, 'ElasticNodeM')
ru_culture.add(GoodreadsAccount, 'GoodreadsAccount')
ru_culture.add(GravatarAccount, 'GravatarAccount')
ru_culture.add(Netblock, 'Netblock')
ru_culture.add(NikePlusAccount, 'NikePlusAccount')
ru_culture.add(Photo, 'Photo')
ru_culture.add(RunkeeperAccount, 'RunkeeperAccount')
ru_culture.add(SSLCertificate, 'SSLCertificate')
ru_culture.add(SSLCertificateSerialNumber, 'SSLCertificateSerialNumber')
ru_culture.add(SearchTerm, 'SearchTerm')
ru_culture.add(SectigoSertificateEntry, 'SectigoSertificateEntry')
ru_culture.add(StravaAccount, 'StravaAccount')
ru_culture.add(Stream, 'Stream')
ru_culture.add(TransactionMix, 'TransactionMix')
ru_culture.add(Tweet, 'Tweet')
# endregion

# region Attributes localization
ru_culture.add(Attributes.System.ASN, 'Номер автономной системы')
ru_culture.add(Attributes.System.Address, 'Адрес')
ru_culture.add(Attributes.System.AppLayerProto, 'Протокол прикладного уровня')
ru_culture.add(Attributes.System.Azimuth, 'Азимут')
ru_culture.add(Attributes.System.Birthday, 'Дата рождения')
ru_culture.add(Attributes.System.BirthdayStr, 'Дата рождения (строка)')
ru_culture.add(Attributes.System.Carrier, 'Оператор')
# ru_culture.add(Attributes.System.Cell, 'CELL')
ru_culture.add(Attributes.System.City, 'Город')
ru_culture.add(Attributes.System.Comment, 'Комментарий')
ru_culture.add(Attributes.System.Count, 'Количество')
ru_culture.add(Attributes.System.Country, 'Страна')
ru_culture.add(Attributes.System.CountryCode, 'Код страны')
ru_culture.add(Attributes.System.Credentials, 'Учётные данные')
ru_culture.add(Attributes.System.Data, 'Данные')
ru_culture.add(Attributes.System.DateAccessed, 'Дата доступа')
ru_culture.add(Attributes.System.DateCreated, 'Дата создания')
ru_culture.add(Attributes.System.DateModified, 'Дата модификации')
ru_culture.add(Attributes.System.DateString, 'Дата string')
ru_culture.add(Attributes.System.Datetime, 'Дата и время')
ru_culture.add(Attributes.System.Description, 'Описание')
ru_culture.add(Attributes.System.Domain, 'Домен')
ru_culture.add(Attributes.System.DomainRegistrant, 'Регистратор домена')
ru_culture.add(Attributes.System.Duration, 'Продолжительность')
# ru_culture.add(Attributes.System.Email, 'Email')
ru_culture.add(Attributes.System.Emptiness, 'Пустота')
ru_culture.add(Attributes.System.FacebookID, 'Facebook id')
ru_culture.add(Attributes.System.FileSize, 'Размер файла')
ru_culture.add(Attributes.System.FileType, 'Тип файла')
ru_culture.add(Attributes.System.Filename, 'Название файла')
ru_culture.add(Attributes.System.FirstAppearance, 'Первое появление')
ru_culture.add(Attributes.System.GeoPoint, 'Геоточка')
ru_culture.add(Attributes.System.GeoPolygon, 'Геополигон')
ru_culture.add(Attributes.System.Geohash, 'Геохеш')
ru_culture.add(Attributes.System.Hash, 'Хеш')
ru_culture.add(Attributes.System.HashAlgo, 'Алгоритм хеширования')
ru_culture.add(Attributes.System.HashDigest, 'Хеш (число)')
# ru_culture.add(Attributes.System.ICQID, 'ICQ id')
# ru_culture.add(Attributes.System.IMEI, 'IMEI')
# ru_culture.add(Attributes.System.IMSI, 'IMSI')
ru_culture.add(Attributes.System.IPAddress, 'IP адрес')
ru_culture.add(Attributes.System.IPAndPort, 'IP и порт')
ru_culture.add(Attributes.System.IPInteger, 'IP (число)')
ru_culture.add(Attributes.System.ISP, 'Интернет-провайдер')
ru_culture.add(Attributes.System.Info, 'Информация')
# ru_culture.add(Attributes.System.Lac, 'LAC')
ru_culture.add(Attributes.System.LastAppearance, 'Последнее появление')
ru_culture.add(Attributes.System.Latitude, 'Широта')
ru_culture.add(Attributes.System.LicensePlate, 'Номер автомобиля')
ru_culture.add(Attributes.System.Location, 'Локация (строка)')
ru_culture.add(Attributes.System.Login, 'Логин')
ru_culture.add(Attributes.System.Longitude, 'Долгота')
ru_culture.add(Attributes.System.MacAddress, 'MAC-адрес')
ru_culture.add(Attributes.System.Manufacturer, 'Производитель')
ru_culture.add(Attributes.System.MaritalStatus, 'Семейное положение')
ru_culture.add(Attributes.System.MiddleName, 'Отчество')
ru_culture.add(Attributes.System.Name, 'Имя')
ru_culture.add(Attributes.System.Nickname, 'Никнейм')
ru_culture.add(Attributes.System.Number, 'Номер')
ru_culture.add(Attributes.System.OS, 'ОС')
ru_culture.add(Attributes.System.Occupation, 'Род занятий')
ru_culture.add(Attributes.System.OrgName, 'Название организации')
ru_culture.add(Attributes.System.PhoneNumber, 'Номер телефона')
ru_culture.add(Attributes.System.Port, 'Порт')
ru_culture.add(Attributes.System.Product, 'Продукт')
ru_culture.add(Attributes.System.Region, 'Регион')
ru_culture.add(Attributes.System.RelationType, 'Вид связи')
ru_culture.add(Attributes.System.Resolved, 'Дата разрешения')
ru_culture.add(Attributes.System.ResponseCode, 'Код ответа')
ru_culture.add(Attributes.System.Role, 'Роль')
ru_culture.add(Attributes.System.School, 'Школа')
ru_culture.add(Attributes.System.Sex, 'Пол')
ru_culture.add(Attributes.System.Surname, 'Фамилия')
ru_culture.add(Attributes.System.Tag, 'Тэг')
# ru_culture.add(Attributes.System.Telco, 'TELCO')
ru_culture.add(Attributes.System.Text, 'Текст')
ru_culture.add(Attributes.System.ThreatName, 'Название угрозы')
ru_culture.add(Attributes.System.Timestamp, 'Временная отметка')
ru_culture.add(Attributes.System.TimestampStr, 'Временная отметка (строка)')
ru_culture.add(Attributes.System.Title, 'Название')
ru_culture.add(Attributes.System.TransportLayerProto, 'Протокол транспортного уровня')
ru_culture.add(Attributes.System.TwitterID, 'Twitter id')
# ru_culture.add(Attributes.System.UID, 'UID')
ru_culture.add(Attributes.System.UIDInt, 'UID (число)')
# ru_culture.add(Attributes.System.URL, 'URL')
ru_culture.add(Attributes.System.University, 'Университет')
# ru_culture.add(Attributes.System.VIN, 'VIN')
ru_culture.add(Attributes.System.Value, 'Значение')
ru_culture.add(Attributes.System.Version, 'Версия')
ru_culture.add(Attributes.System.Work, 'Работа')

ru_culture.add(Attributes.AVLabel, 'Название антивируса')
ru_culture.add(Attributes.AVPositives, 'Позитивных срабатываний')
ru_culture.add(Attributes.AVTotal, 'Всего ативирусов')
ru_culture.add(Attributes.AbuseDescription, 'Описание жалобы')
ru_culture.add(Attributes.AbuseType, 'Тип жалобы')
ru_culture.add(Attributes.AbuseTypeID, 'ID типа жалобы')
ru_culture.add(Attributes.AppointedOn, 'Дата назначения')
ru_culture.add(Attributes.BirthYear, 'Год рождения')
# ru_culture.add(Attributes.CPE, 'CPE')
ru_culture.add(Attributes.CollectionName, 'Название коллекции')
ru_culture.add(Attributes.CommandLine, 'Команда')
# ru_culture.add(Attributes.CompanieshouseID, 'Companieshouse ID')
ru_culture.add(Attributes.CompanyName, 'Название компании')
ru_culture.add(Attributes.CompanyNumber, 'Номер копании')
ru_culture.add(Attributes.CompanyStatus, 'Статус компании')
ru_culture.add(Attributes.Compromised, 'Компрометация')
ru_culture.add(Attributes.CymonSourceName, 'Название источника Cymon')
ru_culture.add(Attributes.DBName, 'БД: название')
ru_culture.add(Attributes.DownloadAvailable, 'Загрузка доступна')
ru_culture.add(Attributes.FilePath, 'Путь файла')
ru_culture.add(Attributes.FilescanId, 'ID сканирования файла')
ru_culture.add(Attributes.HIBPBreachDate, 'Дата утечки')
ru_culture.add(Attributes.HIBPBreachName, 'Название утечки')
ru_culture.add(Attributes.HIBPBreachedDomain, 'Домен утечки')
ru_culture.add(Attributes.HIBPDataClass, 'Класс данных утчеки')
ru_culture.add(Attributes.HIBPDescription, 'Описание утечки данных')
ru_culture.add(Attributes.HIBPIsActive, 'Активная утечка')
ru_culture.add(Attributes.HIBPIsFabricated, 'Сфабрикованная утечка')
ru_culture.add(Attributes.HIBPIsRetired, 'Неактуальная утечка')
ru_culture.add(Attributes.HIBPIsSensitive, 'Чувствительная утечка')
ru_culture.add(Attributes.HIBPIsSpamList, 'Утечка спамлиста')
ru_culture.add(Attributes.HIBPIsVerified, 'Проверенная утечка')
ru_culture.add(Attributes.HIBPLogoType, 'Тип лого утечки')
ru_culture.add(Attributes.HIBPPwnCount, 'Аккаунтов затронуто')
ru_culture.add(Attributes.HybridEnvDesc, 'Описание среды Hybrid')
ru_culture.add(Attributes.HybridEnvironmentId, 'ID среды Hybrid')
ru_culture.add(Attributes.HybridJobID, 'ID задачи Hybrid')
ru_culture.add(Attributes.HybridStartTime, 'Время начала')
ru_culture.add(Attributes.HybridSubmitName, 'Имя загрузки Hybrid')
ru_culture.add(Attributes.HybridThreatScore, 'Оценка угрозы Hybrid')
ru_culture.add(Attributes.HybridThreatScoreStr, 'Оценка угрозы Hybrid (строка)')
ru_culture.add(Attributes.HybridTypeShort, 'Краткий тип Hybrid')
ru_culture.add(Attributes.HybridVXFamily, 'Семейство VX Hybrid')
ru_culture.add(Attributes.HybridVerdict, 'Вердикт Hybrid')
ru_culture.add(Attributes.HybrydAVDetect, 'Положительных срабатываний АВ Hybrid')
ru_culture.add(Attributes.Icon, 'Иконка')
ru_culture.add(Attributes.InformativeIdentifiers, 'Информативные идентификаторы')
ru_culture.add(Attributes.InformativeIdentifiersCount, 'Информативные идентификаторы (кол-во)')
ru_culture.add(Attributes.Issuer, 'Издатель')
ru_culture.add(Attributes.MD5, 'MD5')
ru_culture.add(Attributes.MaliciousIdentifiers, 'Вредоносные идентификаторы')
ru_culture.add(Attributes.MaliciousIdentifiersCount, 'Вредоносные идентификаторы (кол-во)')
ru_culture.add(Attributes.MitreAttckId, 'ID тактики Mitre')
ru_culture.add(Attributes.MitreAttckIdWiki, 'ID тактики Mitre Wiki')
ru_culture.add(Attributes.MitreTactic, 'Тактика Mitre')
ru_culture.add(Attributes.MitreTechnique, 'Техника Mitre')
ru_culture.add(Attributes.Nationality, 'Национальность')
ru_culture.add(Attributes.NormalizedPath, 'Нормализованный путь')
ru_culture.add(Attributes.OSFingerprint, 'Отпечаток ОС')
ru_culture.add(Attributes.OdnoklassnikiID, 'ID Одноклассники')
ru_culture.add(Attributes.Opts, 'Опции')
ru_culture.add(Attributes.Owner, 'Владелец')
ru_culture.add(Attributes.PID, 'PID')
ru_culture.add(Attributes.ParentUID, 'Родительский UID')
ru_culture.add(Attributes.PasteEmailCount, 'Количество адресов в тексте')
ru_culture.add(Attributes.PasteID, 'ID текста')
ru_culture.add(Attributes.PasteSource, 'Источник текста')
ru_culture.add(Attributes.Permalink, 'Перманентный линк')
ru_culture.add(Attributes.ResidenceCountry, 'Страна проживания')
ru_culture.add(Attributes.Resource, 'Ресурс')
ru_culture.add(Attributes.Running, 'Активен')
ru_culture.add(Attributes.RuntimeProcess, 'Runtime-Процесс')
ru_culture.add(Attributes.SHA1, 'SHA1')
ru_culture.add(Attributes.SHA256, 'SHA256')
ru_culture.add(Attributes.SearchEngine, 'Поисковой движок')
ru_culture.add(Attributes.SerialNumber, 'Серийный номер')
ru_culture.add(Attributes.SuspiciousIdentifiers, 'Подозрительные идентификаторы')
ru_culture.add(Attributes.SuspiciousIdentifiersCount, 'Подозрительные идентификаторы (кол-во)')
ru_culture.add(Attributes.VKID, 'VK ID')
ru_culture.add(Attributes.VTScanBy, 'VT сканер')
ru_culture.add(Attributes.VTScanDetail, 'VT детали сканирования')
ru_culture.add(Attributes.VTScanDetected, 'VT Положительных срабатываний')
ru_culture.add(Attributes.VTScanId, 'VT Id сканирования')
ru_culture.add(Attributes.VTScanResult, 'VT результат сканирования')
ru_culture.add(Attributes.ValidFrom, 'Валиден с')
ru_culture.add(Attributes.ValidUntil, 'Валиден по')
ru_culture.add(Attributes.VerboseMsg, 'Подробное сообщение')
ru_culture.add(Attributes.HTTPMethod, 'HTTP метод')
ru_culture.add(Attributes.StatusCode, 'Код состояния')
ru_culture.add(Attributes.QueryString, 'Строка запроса')
ru_culture.add(Attributes.WebDataType, 'Тип веб-данных')
ru_culture.add(Attributes.DataType, 'Тип данных')
ru_culture.add(Attributes.Confidence, 'Доверие')
ru_culture.add(Attributes.Category, 'Категория')
ru_culture.add(Attributes.ProjectName, 'Название проекта')
ru_culture.add(Attributes.ProjectURL, 'URL проекта')
ru_culture.add(Attributes.Subdomain, 'Поддомен')
ru_culture.add(Attributes.WikipediaUserID, 'ID пользователя Википедии')

# requires localization!
ru_culture.add(Attributes.BIN, 'BIN')
ru_culture.add(Attributes.Balance, 'Balance')
ru_culture.add(Attributes.Bank, 'Bank')
ru_culture.add(Attributes.BytesChanged, 'BytesChanged')
ru_culture.add(Attributes.CardLevel, 'CardLevel')
ru_culture.add(Attributes.CardNumber, 'CardNumber')
ru_culture.add(Attributes.DateOfCompletion, 'DateOfCompletion')
ru_culture.add(Attributes.HostCPUusage, 'HostCPUusage')
ru_culture.add(Attributes.HostRAMAvail, 'HostRAMAvail')
ru_culture.add(Attributes.HostRAMCurrent, 'HostRAMCurrent')
ru_culture.add(Attributes.HostRAMMax, 'HostRAMMax')
ru_culture.add(Attributes.HostRole, 'HostRole')
ru_culture.add(Attributes.HostUptime, 'HostUptime')
ru_culture.add(Attributes.HostUptimeStr, 'HostUptimeStr')
ru_culture.add(Attributes.IndexCountDeletedDocuments, 'IndexCountDeletedDocuments')
ru_culture.add(Attributes.IndexCountDocuments, 'IndexCountDocuments')
ru_culture.add(Attributes.IndexHealth, 'IndexHealth')
ru_culture.add(Attributes.IndexName, 'IndexName')
ru_culture.add(Attributes.IndexStatus, 'IndexStatus')
ru_culture.add(Attributes.InputScript, 'InputScript')
ru_culture.add(Attributes.MasterNodeID, 'MasterNodeID')
ru_culture.add(Attributes.MasterNodeName, 'MasterNodeName')
ru_culture.add(Attributes.MasterNodeValue, 'MasterNodeValue')
ru_culture.add(Attributes.Netblock, 'Netblock')
ru_culture.add(Attributes.NodeID, 'NodeID')
ru_culture.add(Attributes.NodeName, 'NodeName')
ru_culture.add(Attributes.NotAfter, 'NotAfter')
ru_culture.add(Attributes.NotBefore, 'NotBefore')
ru_culture.add(Attributes.OutScript, 'OutScript')
ru_culture.add(Attributes.SSLSerialNumber, 'SSLSerialNumber')
ru_culture.add(Attributes.SectigoCertificateID, 'SectigoCertificateID')
ru_culture.add(Attributes.StorageSizeAvail, 'StorageSizeAvail')
ru_culture.add(Attributes.StorageSizeTotal, 'StorageSizeTotal')
ru_culture.add(Attributes.StorageSizeUsed, 'StorageSizeUsed')
ru_culture.add(Attributes.TotalCoinsReceived, 'TotalCoinsReceived')
ru_culture.add(Attributes.TotalCoinsSent, 'TotalCoinsSent')
ru_culture.add(Attributes.TransactionAmount, 'TransactionAmount')
ru_culture.add(Attributes.TransactionCount, 'TransactionCount')
ru_culture.add(Attributes.TransactionHash, 'TransactionHash')
ru_culture.add(Attributes.Vendor, 'Vendor')
ru_culture.add(Attributes.WalletAddress, 'WalletAddress')
# endregion

# region Links localization

ru_culture.add(Call, 'Звонок')
ru_culture.add(FacebookComments, 'Комментарии Facebook')
ru_culture.add(FacebookLikes, 'Лайк Facebook')
ru_culture.add(FacebookReposts, 'Репост Facebook')
ru_culture.add(WikipediaIPEdit, 'Правка Wikipedia с IP')
ru_culture.add(WikipediaUserEdit, 'Правка Wikipedia аккаунтом')


# endregion


class Local(metaclass=Localization):
    ru = ru_culture
# endregion
