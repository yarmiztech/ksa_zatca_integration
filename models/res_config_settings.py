# -*- coding: utf-8 -*-
from odoo import fields, models, exceptions
import requests
import base64
import math
import json
import os


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    zatca_link = fields.Char("Api Link", config_parameter='zatca_link',
                             required="1", default="https://gw-apic-gov.gazt.gov.sa/e-invoicing/developer-portal")
    zatca_sdk_path = fields.Char(config_parameter='zatca_sdk_path')
    zatca_status = fields.Char(config_parameter='zatca_status')
    zatca_onboarding_status = fields.Boolean(config_parameter='zatca_onboarding_status')
    zatca_on_board_status_details = fields.Char(config_parameter='zatca_on_board_status_details')
    zatca_pih = fields.Char(config_parameter='zatca_pih', default='NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==')

    csr_common_name = fields.Char("Common Name", config_parameter='csr_common_name', required="1")  # CN
    csr_serial_number = fields.Char("EGS Serial Number", config_parameter='csr_serial_number', required="1")  # SN
    csr_organization_identifier = fields.Char("Organization Identifier",
                                              config_parameter='csr_organization_identifier', required="1")  # UID
    csr_organization_unit_name = fields.Char("Organization Unit Name",
                                             config_parameter='csr_organization_unit_name', required="1")  # OU
    csr_organization_name = fields.Char("Organization Name", config_parameter='csr_organization_name', required="1")  # O
    csr_country_name = fields.Char("Country Name", config_parameter='csr_country_name', required="1")  # C
    csr_invoice_type = fields.Char("Invoice Type", config_parameter='csr_invoice_type', required="1")  # title
    csr_location_address = fields.Char("Location", config_parameter='csr_location_address', required="1")  # registeredAddress
    csr_industry_business_category = fields.Char("Industry",
                                                 config_parameter='csr_industry_business_category', required="1")  # BusinessCategory
    csr_otp = fields.Char("Otp", config_parameter='csr_otp')
    csr_certificate = fields.Char("Certificate", config_parameter='csr_certificate', required="0")

    zatca_is_sandbox = fields.Boolean('Testing ?', config_parameter='zatca_is_sandbox')
    zatca_private_key = fields.Char("Private key", config_parameter='zatca_private_key')

    def generate_zatca_certificate(self):
        conf = self.env['ir.config_parameter'].sudo()
        conf.set_param('zatca_onboarding_status', False)
        if not conf.get_param("csr_otp", False):
            raise exceptions.MissingError("OTP required")
        try:
            config_cnf = '''
                oid_section = OIDs
                [ OIDs ]
                certificateTemplateName= 1.3.6.1.4.1.311.20.2
                [ req ]
                default_bits = 2048
                emailAddress = myEmail@gmail.com
                req_extensions = v3_req
                x509_extensions = v3_ca
                prompt = no
                default_md = sha256
                req_extensions = req_ext
                distinguished_name = dn
                [ dn ]
                C = ''' + str(conf.get_param("csr_country_name", '')) + '''
                OU = ''' + str(conf.get_param("csr_organization_unit_name", '')) + '''
                O = ''' + str(conf.get_param("csr_organization_name", '')) + '''
                CN = ''' + str(conf.get_param("csr_common_name", '')) + '''
                [ v3_req ]
                basicConstraints = CA:FALSE
                keyUsage = digitalSignature, nonRepudiation, keyEncipherment
                [ req_ext ]
                certificateTemplateName = ASN1:PRINTABLESTRING:ZATCA-Code-Signing
                subjectAltName = dirName:alt_names            
                [ alt_names ]
                SN = ''' + str(conf.get_param("csr_serial_number", '')) + '''
                UID = ''' + str(conf.get_param("csr_organization_identifier", '')) + '''
                title = ''' + str(conf.get_param("csr_invoice_type", '')) + '''
                registeredAddress = ''' + str(conf.get_param("csr_location_address", '')) + '''
                businessCategory = ''' + str(conf.get_param("csr_industry_business_category", '')) + '''
            '''

            f = open('/tmp/zatca.cnf', 'w+')
            f.write(config_cnf)
            f.close()

            # Certiciate calculation moved to new function

            if self.zatca_is_sandbox:
                private_key = conf.get_param("zatca_private_key", '')
                if private_key.find('-----BEGIN EC PRIVATE KEY-----') > -1:
                    private_key = private_key.replace('-----BEGIN EC PRIVATE KEY-----', '') \
                        .replace('-----END EC PRIVATE KEY-----', '').replace(' ', '').replace('\n', '')
                for x in range(1, math.ceil(len(private_key) / 64)):
                    private_key = private_key[:64 * x + x -1] + '\n' + private_key[64 * x + x -1:]
                private_key = "-----BEGIN EC PRIVATE KEY-----\n" + private_key + "\n-----END EC PRIVATE KEY-----"

                f = open('/tmp/zatcaprivatekey.pem', 'w+')
                f.write(private_key)
                f.close()
            else:
                private_key = 'openssl ecparam -name secp256k1 -genkey -noout -out /tmp/zatcaprivatekey.pem'
            public_key = 'openssl ec -in /tmp/zatcaprivatekey.pem -pubout -conv_form compressed -out /tmp/zatcapublickey.pem'
            public_key_bin = 'openssl base64 -d -in /tmp/zatcapublickey.pem -out /tmp/zatcapublickey.bin'
            csr = 'openssl req -new -sha256 -key /tmp/zatcaprivatekey.pem -extensions v3_req -config /tmp/zatca.cnf -out /tmp/zatca_taxpayper.csr'
            csr_base64 = "openssl base64 -in /tmp/zatca_taxpayper.csr -out /tmp/zatca_taxpayper_64.csr"
            if not self.zatca_is_sandbox:
                os.system(private_key)
            os.system(public_key)
            os.system(public_key_bin)
            os.system(csr)
            os.system(csr_base64)
            conf.set_param('zatca_status', 'Certificate, private & public key generated')
            csr_invoice_type = conf.get_param('csr_invoice_type', False)

            qty = 3
            if csr_invoice_type == '1100':
                zatca_on_board_status_details = {
                    'standard': {
                        'credit': 0,
                        'debit': 0,
                        'invoice': 0,
                    },
                    'simplified': {
                        'credit': 0,
                        'debit': 0,
                        'invoice': 0,
                    }
                }
                message = "Standard & its associated invoices and Simplified & its associated invoices"
                message = "Standard: invoice, debit, credit, \nSimplified: invoice, debit, credit, "
                qty = 6
            elif csr_invoice_type == '1000':
                zatca_on_board_status_details = {
                    'standard': {
                        'credit': 0,
                        'debit': 0,
                        'invoice': 0,
                    }
                }
                message = "Standard & its associated invoices"
                message = "Standard: invoice, debit, credit, "
            elif csr_invoice_type == '0100':
                zatca_on_board_status_details = {
                    'simplified': {
                        'credit': 0,
                        'debit': 0,
                        'invoice': 0,
                    }
                }
                message = "Simplified & its associated invoices"
                message = "Simplified: invoice, debit, credit, "
            conf.set_param('zatca_on_board_status_details', json.dumps(zatca_on_board_status_details))
            conf.set_param('zatca_status', 'Onboarding started, required ' + str(qty) + ' invoices' + "\n" + message)

            # filepath = os.popen("find -name 'zatca_sdk'").read()
            # filepath = filepath.replace('zatca_sdk', '').replace('\n', '')
            # self.env['ir.config_parameter'].sudo().set_param("zatca_sdk_path", filepath)

        except Exception as e:
            # raise exceptions.MissingError(e)
            raise exceptions.MissingError('Server Error, Contact administrator.')
        self.compliance_api()
        conf.set_param('csr_otp', None)
        # self.compliance_api('/production/csids', 1)
        #     CNF, PEM, CSR created

    def compliance_api(self, endpoint='/compliance', renew=0):
        link = "https://gw-apic-gov.gazt.gov.sa/e-invoicing/developer-portal"
        conf = self.env['ir.config_parameter'].sudo()
        if endpoint == '/compliance':
            zatca_otp = conf.get_param("csr_otp", False)
            headers = {'accept': 'application/json',
                       'OTP': zatca_otp,
                       'Accept-Version': 'V2',
                       'Content-Type': 'application/json'}

            f = open('/tmp/zatca_taxpayper_64.csr', 'r')
            csr = f.read()
            data = {'csr': csr.replace('\n', '')}
        elif endpoint == '/production/csids' and not renew:
            user = conf.get_param("zatca_sb_bsToken", False)
            password = conf.get_param("zatca_sb_secret", False)
            compliance_request_id = conf.get_param("zatca_sb_reqID", False)
            auth = base64.b64encode(('%s:%s' % (user, password)).encode('utf-8')).decode('utf-8')
            headers = {'accept': 'application/json',
                       'Accept-Version': 'V2',
                       'Authorization': 'Basic ' + auth,
                       'Content-Type': 'application/json'}

            data = {'compliance_request_id': compliance_request_id}
        elif endpoint == '/production/csids' and renew:
            user = conf.get_param("zatca_bsToken", False)
            password = conf.get_param("zatca_secret", False)
            auth = base64.b64encode(('%s:%s' % (user, password)).encode('utf-8')).decode('utf-8')
            zatca_otp = conf.get_param("csr_otp", False)
            headers = {'accept': 'application/json',
                       'OTP': zatca_otp,
                       'Accept-Language': 'en',
                       'Accept-Version': 'V2',
                       'Authorization': 'Basic ' + auth,
                       'Content-Type': 'application/json'}
            f = open('/tmp/zatca_taxpayper_64.csr', 'r')
            csr = f.read()
            data = {'csr': csr.replace('\n', '')}
        try:
            req = requests.post(link + endpoint, headers=headers, data=json.dumps(data))
            if req.status_code == 500:
                if req.text:
                    response = json.loads(req.text)
                    raise exceptions.AccessError(response['message'])
                raise exceptions.AccessError('Invalid Request, zatca, \ncontact system administer')
            elif req.status_code == 400:
                if req.text:
                    response = json.loads(req.text)
                    raise exceptions.AccessError(response['message'])
                raise exceptions.AccessError('Invalid Request, odoo, \ncontact system administer')
            elif req.status_code == 401:
                if req.text:
                    response = json.loads(req.text)
                    raise exceptions.AccessError(response['message'])
                raise exceptions.AccessError('Unauthorized, \ncontact system administer')
            elif req.status_code == 200:
                response = json.loads(req.text)
                if endpoint == '/compliance':
                    conf.set_param("zatca_sb_bsToken", response['binarySecurityToken'])
                    conf.set_param("zatca_sb_reqID", response['requestID'])
                    conf.set_param("zatca_sb_secret", response['secret'])
                else:
                    conf.set_param("zatca_bsToken", response['binarySecurityToken'])
                    conf.set_param("zatca_reqID", response['requestID'])
                    conf.set_param("zatca_secret", response['secret'])
                # if endpoint == '/compliance':
                #     self.compliance_api('/production/csids')
                # else:
                #     response['tokenType']
                #     response['dispositionMessage']
        except Exception as e:
            raise exceptions.AccessDenied(e)

    def production_credentials(self):
        conf = self.env['ir.config_parameter'].sudo()
        if conf.get_param('zatca_certificate_status', '0') != "1":
            raise exceptions.MissingError("Register Certificate before proceeding.")
        if self.zatca_is_sandbox:
            zatca_bsToken = "TUlJRDFEQ0NBM21nQXdJQkFnSVRid0FBZTNVQVlWVTM0SS8rNVFBQkFBQjdkVEFLQmdncWhrak9QUVFEQWpCak1SVXdFd1lLQ1pJbWlaUHlMR1FCR1JZRmJHOWpZV3d4RXpBUkJnb0praWFKay9Jc1pBRVpGZ05uYjNZeEZ6QVZCZ29Ka2lhSmsvSXNaQUVaRmdkbGVIUm5ZWHAwTVJ3d0dnWURWUVFERXhOVVUxcEZTVTVXVDBsRFJTMVRkV0pEUVMweE1CNFhEVEl5TURZeE1qRTNOREExTWxvWERUSTBNRFl4TVRFM05EQTFNbG93U1RFTE1Ba0dBMVVFQmhNQ1UwRXhEakFNQmdOVkJBb1RCV0ZuYVd4bE1SWXdGQVlEVlFRTEV3MW9ZWGxoSUhsaFoyaHRiM1Z5TVJJd0VBWURWUVFERXdreE1qY3VNQzR3TGpFd1ZqQVFCZ2NxaGtqT1BRSUJCZ1VyZ1FRQUNnTkNBQVRUQUs5bHJUVmtvOXJrcTZaWWNjOUhEUlpQNGI5UzR6QTRLbTdZWEorc25UVmhMa3pVMEhzbVNYOVVuOGpEaFJUT0hES2FmdDhDL3V1VVk5MzR2dU1ObzRJQ0p6Q0NBaU13Z1lnR0ExVWRFUVNCZ0RCK3BId3dlakViTUJrR0ExVUVCQXdTTVMxb1lYbGhmREl0TWpNMGZETXRNVEV5TVI4d0hRWUtDWkltaVpQeUxHUUJBUXdQTXpBd01EYzFOVGc0TnpBd01EQXpNUTB3Q3dZRFZRUU1EQVF4TVRBd01SRXdEd1lEVlFRYURBaGFZWFJqWVNBeE1qRVlNQllHQTFVRUR3d1BSbTl2WkNCQ2RYTnphVzVsYzNNek1CMEdBMVVkRGdRV0JCU2dtSVdENmJQZmJiS2ttVHdPSlJYdkliSDlIakFmQmdOVkhTTUVHREFXZ0JSMllJejdCcUNzWjFjMW5jK2FyS2NybVRXMUx6Qk9CZ05WSFI4RVJ6QkZNRU9nUWFBL2hqMW9kSFJ3T2k4dmRITjBZM0pzTG5waGRHTmhMbWR2ZGk1ellTOURaWEowUlc1eWIyeHNMMVJUV2tWSlRsWlBTVU5GTFZOMVlrTkJMVEV1WTNKc01JR3RCZ2dyQmdFRkJRY0JBUVNCb0RDQm5UQnVCZ2dyQmdFRkJRY3dBWVppYUhSMGNEb3ZMM1J6ZEdOeWJDNTZZWFJqWVM1bmIzWXVjMkV2UTJWeWRFVnVjbTlzYkM5VVUxcEZhVzUyYjJsalpWTkRRVEV1WlhoMFoyRjZkQzVuYjNZdWJHOWpZV3hmVkZOYVJVbE9WazlKUTBVdFUzVmlRMEV0TVNneEtTNWpjblF3S3dZSUt3WUJCUVVITUFHR0gyaDBkSEE2THk5MGMzUmpjbXd1ZW1GMFkyRXVaMjkyTG5OaEwyOWpjM0F3RGdZRFZSMFBBUUgvQkFRREFnZUFNQjBHQTFVZEpRUVdNQlFHQ0NzR0FRVUZCd01DQmdnckJnRUZCUWNEQXpBbkJna3JCZ0VFQVlJM0ZRb0VHakFZTUFvR0NDc0dBUVVGQndNQ01Bb0dDQ3NHQVFVRkJ3TURNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUNWd0RNY3E2UE8rTWNtc0JYVXovdjFHZGhHcDdycVNhMkF4VEtTdjgzOElBSWhBT0JOREJ0OSszRFNsaWpvVmZ4enJkRGg1MjhXQzM3c21FZG9HV1ZyU3BHMQ=="
            zatca_secret = "Xlj15LyMCgSC66ObnEO/qVPfhSbs3kDTjWnGheYhfSs="
            conf.set_param("zatca_bsToken", zatca_bsToken)
            conf.set_param("zatca_reqID", 'N/A')
            conf.set_param("zatca_secret", zatca_secret)
        else:
            self.compliance_api('/production/csids', 0)
        conf.set_param('zatca_status', 'production credentials received.')
        conf.set_param('csr_otp', None)

    def production_credentials_renew(self):
        conf = self.env['ir.config_parameter'].sudo()
        if conf.get_param('zatca_certificate_status', '0') != "1":
            raise exceptions.MissingError("Register Certificate before proceeding.")
        if not conf.get_param("csr_otp", False):
            raise exceptions.MissingError("OTP required")
        if self.zatca_is_sandbox:
            zatca_bsToken = "TUlJRDFEQ0NBM21nQXdJQkFnSVRid0FBZTNVQVlWVTM0SS8rNVFBQkFBQjdkVEFLQmdncWhrak9QUVFEQWpCak1SVXdFd1lLQ1pJbWlaUHlMR1FCR1JZRmJHOWpZV3d4RXpBUkJnb0praWFKay9Jc1pBRVpGZ05uYjNZeEZ6QVZCZ29Ka2lhSmsvSXNaQUVaRmdkbGVIUm5ZWHAwTVJ3d0dnWURWUVFERXhOVVUxcEZTVTVXVDBsRFJTMVRkV0pEUVMweE1CNFhEVEl5TURZeE1qRTNOREExTWxvWERUSTBNRFl4TVRFM05EQTFNbG93U1RFTE1Ba0dBMVVFQmhNQ1UwRXhEakFNQmdOVkJBb1RCV0ZuYVd4bE1SWXdGQVlEVlFRTEV3MW9ZWGxoSUhsaFoyaHRiM1Z5TVJJd0VBWURWUVFERXdreE1qY3VNQzR3TGpFd1ZqQVFCZ2NxaGtqT1BRSUJCZ1VyZ1FRQUNnTkNBQVRUQUs5bHJUVmtvOXJrcTZaWWNjOUhEUlpQNGI5UzR6QTRLbTdZWEorc25UVmhMa3pVMEhzbVNYOVVuOGpEaFJUT0hES2FmdDhDL3V1VVk5MzR2dU1ObzRJQ0p6Q0NBaU13Z1lnR0ExVWRFUVNCZ0RCK3BId3dlakViTUJrR0ExVUVCQXdTTVMxb1lYbGhmREl0TWpNMGZETXRNVEV5TVI4d0hRWUtDWkltaVpQeUxHUUJBUXdQTXpBd01EYzFOVGc0TnpBd01EQXpNUTB3Q3dZRFZRUU1EQVF4TVRBd01SRXdEd1lEVlFRYURBaGFZWFJqWVNBeE1qRVlNQllHQTFVRUR3d1BSbTl2WkNCQ2RYTnphVzVsYzNNek1CMEdBMVVkRGdRV0JCU2dtSVdENmJQZmJiS2ttVHdPSlJYdkliSDlIakFmQmdOVkhTTUVHREFXZ0JSMllJejdCcUNzWjFjMW5jK2FyS2NybVRXMUx6Qk9CZ05WSFI4RVJ6QkZNRU9nUWFBL2hqMW9kSFJ3T2k4dmRITjBZM0pzTG5waGRHTmhMbWR2ZGk1ellTOURaWEowUlc1eWIyeHNMMVJUV2tWSlRsWlBTVU5GTFZOMVlrTkJMVEV1WTNKc01JR3RCZ2dyQmdFRkJRY0JBUVNCb0RDQm5UQnVCZ2dyQmdFRkJRY3dBWVppYUhSMGNEb3ZMM1J6ZEdOeWJDNTZZWFJqWVM1bmIzWXVjMkV2UTJWeWRFVnVjbTlzYkM5VVUxcEZhVzUyYjJsalpWTkRRVEV1WlhoMFoyRjZkQzVuYjNZdWJHOWpZV3hmVkZOYVJVbE9WazlKUTBVdFUzVmlRMEV0TVNneEtTNWpjblF3S3dZSUt3WUJCUVVITUFHR0gyaDBkSEE2THk5MGMzUmpjbXd1ZW1GMFkyRXVaMjkyTG5OaEwyOWpjM0F3RGdZRFZSMFBBUUgvQkFRREFnZUFNQjBHQTFVZEpRUVdNQlFHQ0NzR0FRVUZCd01DQmdnckJnRUZCUWNEQXpBbkJna3JCZ0VFQVlJM0ZRb0VHakFZTUFvR0NDc0dBUVVGQndNQ01Bb0dDQ3NHQVFVRkJ3TURNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUNWd0RNY3E2UE8rTWNtc0JYVXovdjFHZGhHcDdycVNhMkF4VEtTdjgzOElBSWhBT0JOREJ0OSszRFNsaWpvVmZ4enJkRGg1MjhXQzM3c21FZG9HV1ZyU3BHMQ=="
            zatca_secret = "Xlj15LyMCgSC66ObnEO/qVPfhSbs3kDTjWnGheYhfSs="
            conf.set_param("zatca_bsToken", zatca_bsToken)
            conf.set_param("zatca_reqID", 'N/A')
            conf.set_param("zatca_secret", zatca_secret)
        else:
            self.compliance_api('/production/csids', 1)
        conf.set_param('zatca_status', 'production credentials renewed.')
        conf.set_param('csr_otp', None)

    def register_certificate(self):
        conf = self.env['ir.config_parameter'].sudo()
        certificate = conf.get_param("csr_certificate", '')
        if certificate.find('-----BEGIN CERTIFICATE-----') > -1:
            certificate = certificate.replace('-----BEGIN CERTIFICATE-----', '') \
                .replace('-----END CERTIFICATE-----', '').replace(' ', '').replace('\n', '')
        for x in range(1, math.ceil(len(certificate) / 64)):
            certificate = certificate[:64 * x + x - 1] + '\n' + certificate[64 * x + x - 1:]
        certificate = "-----BEGIN CERTIFICATE-----\n" + certificate + "\n-----END CERTIFICATE-----"

        f = open('/tmp/zatca_cert.pem', 'w+')
        f.write(certificate)
        f.close()

        certificate_public_key = "openssl x509 -pubkey -noout -in /tmp/zatca_cert.pem -out /tmp/zatca_cert_publickey.pem"
        certificate_public_key_bin = "openssl base64 -d -in /tmp/zatca_cert_publickey.pem -out /tmp/zatca_cert_publickey.bin"
        certificate_signature_algorithm = "openssl x509 -in /tmp/zatca_cert.pem -text -noout"
        cert = os.popen(certificate_signature_algorithm).read()
        cert_find = cert.rfind("Signature Algorithm: ecdsa-with-SHA256")
        if cert_find > 0 and cert_find + 38 < len(cert):
            cert_sig_algo = cert[cert.rfind("Signature Algorithm: ecdsa-with-SHA256") + 38:].replace('\n', '') \
                .replace(':', '') \
                .replace(' ', '')
            conf.set_param("zatca_cert_sig_algo", cert_sig_algo)
        else:
            raise exceptions.ValidationError("Invalid Certificate Provided.")

        os.system(certificate_public_key)
        os.system(certificate_public_key_bin)
        conf.set_param('zatca_certificate_status', '1')
