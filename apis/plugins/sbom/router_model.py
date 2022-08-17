from marshmallow import Schema, fields
from util import CommonBasicResponse



#################################### Schema ####################################


class SbomPostSchema(Schema):
    project_name = fields.Str(required=True, example="admin")
    branch = fields.Str(required=True, example="master")
    commit = fields.Str(required=True, example="#77777")
    sequence = fields.Int(example=1)


class SbomPatchSchema(Schema):
    scan_status = fields.Str(example="Finished")
    package_nums = fields.Int(example=1)
    scan_overview = fields.Dict(example={
        "severity": "Critical", 
        "size": "53.92MB", 
        "fixable": 4, 
        "total": 67, 
        "Critical": 1, 
        "High": 2, 
        "Low": 6, 
        "Medium": 8, 
        "Negligible": 40, 
        "Unknown": 10
    })
    finished = fields.Boolean(example=True)
    finished_at = fields.Str(example="1970-01-01T00:00:00")
    logs = fields.Str(example="logs")


#################################### Response ####################################


class SbomGetRes(CommonBasicResponse):
    data = fields.List(
        fields.Dict(
            example={
                "branch": "master",
                "commit": "Z7777777",
                "commit_url": "https://",
                "created_at": "1970-01-01T00:00:00",
                "finished": True,
                "finished_at": "1970-01-01T00:00:00",
                "id": 1,
                "logs": "",
                "package_nums": 1,
                "project_id": 1,
                "scan_overview": {},
                "scan_status": "Finished"
            }
        )
    )

class SbomPostRes(Schema):
    id = fields.Int(required=True)


class SbomListResponse(Schema):
    per_page = fields.Int(required=False, description='Show how many items at one page', example="10")
    page = fields.Int(required=False, description='Page number', example="1")


class SbomGetFileList(CommonBasicResponse):
    data = fields.List(fields.Str())


class SbomGetProjectID(Schema):
    project_id = fields.Int(example=3)


class SbomGetSbomID(Schema):
    sbom_id = fields.Int(example=3)

#################################### Response ####################################


class SbomGetRes(CommonBasicResponse):
    data = fields.List(
        fields.Dict(
            example={
                "branch": "master",
                "commit": "Z7777777",
                "commit_url": "https://",
                "created_at": "1970-01-01T00:00:00",
                "finished": True,
                "finished_at": "1970-01-01T00:00:00",
                "id": 1,
                "logs": "",
                "package_nums": 1,
                "project_id": 1,
                "scan_overview": {},
                "scan_status": "Finished"
            }
        )
    )

class SbomPostRes(Schema):
    id = fields.Int(required=True)


class SbomListResponse(Schema):
    per_page = fields.Int(required=False, description='Show how many items at one page', example="2")
    page = fields.Int(required=False, description='Page number', example="2")


class PaginationPageResponse(Schema):
    limit = fields.Int(required=True)
    offset = fields.Int(required=True)


class SbomGetRiskDetailRes(CommonBasicResponse):
    data = fields.Dict(example={
        "detail_list": [
            {
                "description": "OpenSSL 0.9.8i on the Gaisler Research LEON3 SoC on the Xilinx Virtex-II Pro FPGA uses a Fixed Width Exponentiation (FWE) algorithm for certain signature calculations, and does not verify the signature before providing it to a caller, which makes it easier for physically proximate attackers to determine the private key via a modified supply voltage for the microprocessor, related to a \"fault-based attack.\"",
                "id": "CVE-2010-0928",
                "name": "libssl1.1",
                "severity": "Negligible",
                "version": "1.1.1n-0+deb11u3",
                "versions": ""
            },
            {
                "description": "OpenSSL 0.9.8i on the Gaisler Research LEON3 SoC on the Xilinx Virtex-II Pro FPGA uses a Fixed Width Exponentiation (FWE) algorithm for certain signature calculations, and does not verify the signature before providing it to a caller, which makes it easier for physically proximate attackers to determine the private key via a modified supply voltage for the microprocessor, related to a \"fault-based attack.\"",
                "id": "CVE-2010-0928",
                "name": "openssl",
                "severity": "Negligible",
                "version": "1.1.1n-0+deb11u3",
                "versions": ""
            },
            {
                "description": "The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.",
                "id": "CVE-2010-4756",
                "name": "libc-bin",
                "severity": "Negligible",
                "version": "2.31-13+deb11u3",
                "versions": ""
            },
            {
                "description": "The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.",
                "id": "CVE-2010-4756",
                "name": "libc6",
                "severity": "Negligible",
                "version": "2.31-13+deb11u3",
                "versions": ""
            },
            {
                "description": "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
                "id": "CVE-2011-3374",
                "name": "apt",
                "severity": "Negligible",
                "version": "2.2.4",
                "versions": ""
            },
            {
                "description": "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
                "id": "CVE-2011-3374",
                "name": "libapt-pkg6.0",
                "severity": "Negligible",
                "version": "2.2.4",
                "versions": ""
            },
            {
                "description": "The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a \"BEAST\" attack.",
                "id": "CVE-2011-3389",
                "name": "libgnutls30",
                "severity": "Medium",
                "version": "3.7.1-5+deb11u1",
                "versions": ""
            },
            {
                "description": "_is_safe in the File::Temp module for Perl does not properly handle symlinks.",
                "id": "CVE-2011-4116",
                "name": "perl-base",
                "severity": "Negligible",
                "version": "5.32.1-4+deb11u2",
                "versions": ""
            },
            {
                "description": "The default configuration of nginx, possibly 1.3.13 and earlier, uses world-readable permissions for the (1) access.log and (2) error.log files, which allows local users to obtain sensitive information by reading the files.",
                "id": "CVE-2013-0337",
                "name": "nginx",
                "severity": "Low",
                "version": "1.22.0-1~bullseye",
                "versions": ""
            },
            {
                "description": "expat 2.1.0 and earlier does not properly handle entities expansion unless an application developer uses the XML_SetEntityDeclHandler function, which allows remote attackers to cause a denial of service (resource consumption), send HTTP requests to intranet servers, or read arbitrary files via a crafted XML document, aka an XML External Entity (XXE) issue.  NOTE: it could be argued that because expat already provides the ability to disable external entity expansion, the responsibility for resolving this issue lies with application developers; according to this argument, this entry should be REJECTed, and each affected application would need its own CVE.",
                "id": "CVE-2013-0340",
                "name": "libexpat1",
                "severity": "Negligible",
                "version": "2.2.10-2+deb11u3",
                "versions": ""
            }
        ],
        "page": {
            "current": 2,
            "limit": 10,
            "next": 3,
            "offset": 10,
            "pages": 15,
            "prev": 1,
            "total": 147
        }
    }, required=True)


class SbomGetSbonListRes(CommonBasicResponse):
    data = fields.Dict(example={
        "Sbom_list": [
            {
                "branch": "develop",
                "commit": "Z7777777",
                "created_at": "1970-01-01 00:00:00",
                "finished": "true",
                "finished_at": "1970-01-01 00:00:00",
                "id": 1,
                "logs": "Nice",
                "package_nums": 10,
                "project_id": 137,
                "scan_overview": {},
                "scan_status": "Running",
                "sequence": ""
            },
            {
                "branch": "develops",
                "commit": "a123445",
                "created_at": "1970-01-01 00:00:00",
                "finished": "true",
                "finished_at": "2022-08-10 14:26:56",
                "id": 4,
                "logs": "didn't find the file",
                "package_nums": 143,
                "project_id": 137,
                "scan_overview": {
                    "Critical": 7,
                    "High": 22,
                    "Low": 10,
                    "Medium": 22,
                    "Negligible": 82,
                    "Unknown": 4,
                    "total": 147
                },
                "scan_status": "Success",
                "sequence": 11
            }
        ],
        "page": {
            "current": 2,
            "next": 3,
            "pages": 3,
            "per_page": 2,
            "prev": 1,
            "total": 6
        }})


class SbomGetRiskOverviewRes(CommonBasicResponse):
    data = fields.Dict(example={
            "Critical": 7,
            "High": 22,
            "Low": 10,
            "Medium": 22,
            "Negligible": 82,
            "Unknown": 4,
            "total": 147
        }, required=True)


class SbomDownloadReportRes(Schema):
    file_name = fields.Str(required=True)