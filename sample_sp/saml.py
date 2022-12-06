from dataclasses import dataclass

from saml2 import BINDING_HTTP_POST, md, BINDING_HTTP_REDIRECT, samlp, xmldsig
from saml2.client import Saml2Client
from saml2.config import Config
from saml2.mdstore import InMemoryMetaData
from saml2.sigver import get_xmlsec_binary

# @dataclass
# class IdPConfig:
#     entity_id: str
#     single_sign_on_url: str
#     x509_cert: str
#
#     def __hash__(self):
#         return hash(self.entity_id)


if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin", "/usr/local/bin"])
else:
    xmlsec_path = "/usr/bin/xmlsec1"


def saml_client():
    saml_settings = {
        # Currently xmlsec1 binaries are used for all the signing and encryption stuff.This option defines where the binary is situated.
        "xmlsec_binary": xmlsec_path,
        # The SP ID. It is recommended that the entityid should point to a real webpage where the metadata for the entity can be found.
        "entityid": "http://ec2-15-207-110-124.ap-south-1.compute.amazonaws.com",
        # Indicates that attributes that are not recognized (they are not configured in attribute-mapping), will not be discarded.
        "allow_unknown_attributes": True,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [
                        ##as mentioned in the sequence diagram we can use either redirect or post here.
                        ("http://ec2-15-207-110-124.ap-south-1.compute.amazonaws.com/saml2/acs/", BINDING_HTTP_POST),
                    ]
                },
                # Don't verify that the incoming requests originate from us via the built-in cache for authn request ids in pysaml2
                "allow_unsolicited": True,
                # Don't sign authn requests, since signed requests only make sense in a situation where you control both the SP and IdP
                "authn_requests_signed": False,
                # Assertion must be signed
                "want_assertions_signed": False,
                # Response signing is optional.
                "want_response_signed": False,
            }
        },
        "metadata": {
            "local": [
                "/home/app/webapp/sample_sp/idp.xml",
            ],
        },
    }

    config = Config()
    config.load(saml_settings)

    return Saml2Client(config=config)
