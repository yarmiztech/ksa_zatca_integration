from cryptography.hazmat.backends import default_backend
from odoo import api, fields, models, exceptions
from cryptography import x509
from decimal import Decimal
import lxml.etree as ET
import binascii
import requests
import hashlib
import base64
import uuid
import json
import os


class AccountMove(models.Model):
    _inherit = "account.move"

    zatca_hash_cleared_invoice = fields.Binary("cleared invoice returned from ZATCA", attachment=True, readonly=1, copy=False)
    zatca_hash_cleared_invoice_name = fields.Char(copy=False)

    zatca_invoice = fields.Binary("generated invoice for ZATCA", attachment=True, readonly=1, copy=False)
    zatca_invoice_name = fields.Char(copy=False)
    credit_debit_reason = fields.Char(string="Reasons for issuance of credit / debit note", copy=False,
                                   help="Reasons as per Article 40 (paragraph 1) of KSA VAT regulations")
    invoice_date = fields.Date(string='Invoice/Bill Date', readonly=True, index=True, copy=False,
                               states={'draft': [('readonly', False)]}, default=fields.date.today())
    invoice_datetime = fields.Datetime(string='Invoice/Bill Date', readonly=True, index=True, copy=False,
                                   states={'draft': [('readonly', False)]}, default=fields.datetime.now())
    zatca_compliance_invoices_api = fields.Html(readonly=1, copy=False)

    l10n_sa_invoice_type = fields.Selection([('Standard', 'Standard'), ('Simplified', 'Simplified')],
                                            string="Invoice Type", default="Standard", copy=False)

    l10n_is_third_party_invoice = fields.Boolean(string="Is Third Party",
                                                 help="Flag indicating whether the invoice was created by a third party")
    l10n_is_nominal_invoice = fields.Boolean(string="Is Nominal",
                                             help="The invoice is issued for goods that are provided without "
                                                  "consideration as per KSA VAT regulation.")
    l10n_is_exports_invoice = fields.Boolean(string="Is Export",
                                             help="The invoice is issued to a foreign buyer as per KSA VAT regulation.")
    l10n_is_summary_invoice = fields.Boolean(string="Is Summary",
                                             help="The invoice is issued for sales occurring over a period of time and "
                                                  "occurs for some types of invoicing arrangements between seller and "
                                                  "buyer.")
    l10n_is_self_billed_invoice = fields.Boolean(string="Is Self Billed",
                                                 help="The invoice is issued by the buyer instead of the supplier. It "
                                                      "is only applicable in B2B scenarios. It will not have any effect"
                                                      " on the fields, however its mandated that the invoice states "
                                                      "that it is self-billed.")

    # Never show these fields on front
    invoice_uuid = fields.Char('zatca uuid', readonly=1, copy=False)
    zatca_invoice_hash = fields.Char(readonly=1, copy=False)
    zatca_invoice_hash_hex = fields.Char(readonly=1, copy=False)
    zatca_hash_invoice = fields.Binary("ZATCA generated invoice for hash", attachment=True, readonly=1, copy=False)
    zatca_hash_invoice_name = fields.Char(readonly=1, copy=False)
    zatca_onboarding_status = fields.Boolean(readonly=1, default=lambda self: self.env['ir.config_parameter'].sudo().get_param('zatca_onboarding_status', False)
                                             , copy=False)

    l10n_sa_qr_code_str = fields.Char(string='Zatka QR Code', copy=False)
    sa_qr_code_str = fields.Char(string='Zatka QR Code', copy=False, readonly=1)
    l10n_sa_is_tax_invoice = fields.Boolean(readonly=1, copy=False)

    @api.onchange('invoice_datetime')
    def _onchange_invoice_datetime(self):
        self.invoice_date = self.invoice_datetime.date()

    def create_xml_file(self, previous_hash=0):
        amount_verification = 0  # for debug mode
        conf = self.env['ir.config_parameter'].sudo()
        # No longer needed
        # if not previous_hash:
        #     self.create_xml_file(previous_hash=1)

        # STEP # 3 in "5. Signing Process"
        # in https://zatca.gov.sa/ar/E-Invoicing/Introduction/Guidelines/Documents/E-invoicing%20Detailed%20Technical%20Guidelines.pdf
        zatca_certificate_status = conf.get_param('zatca_certificate_status', '0')
        if zatca_certificate_status != "1":
            raise exceptions.MissingError("Register Certificate before proceeding.")

        f = open('/tmp/zatca_cert.pem', 'r')
        certificate = f.read()
        original_certificate = certificate.replace('-----BEGIN CERTIFICATE-----', '')\
                                          .replace('-----END CERTIFICATE-----', '')\
                                          .replace(' ', '').replace('\n', '')
        sha_256_3 = hashlib.sha256()
        sha_256_3.update(original_certificate.encode())
        base_64_3 = base64.b64encode(sha_256_3.hexdigest().encode()).decode('UTF-8')

        cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
        cert_issuer = ''
        for x in range(len(cert.issuer.rdns) - 1, -1, -1):
            cert_issuer += cert.issuer.rdns[x].rfc4514_string() + ", "
        cert_issuer = cert_issuer[:-2]

        signature_certificate = '''<ds:Object>
                            <xades:QualifyingProperties Target="signature" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
                                <xades:SignedProperties Id="xadesSignedProperties">
                                    <xades:SignedSignatureProperties>
                                        <xades:SigningTime>''' + fields.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ') + '''</xades:SigningTime>
                                        <xades:SigningCertificate>
                                            <xades:Cert>
                                                <xades:CertDigest>
                                                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                                    <ds:DigestValue>''' + str(base_64_3) + '''</ds:DigestValue>
                                                </xades:CertDigest>
                                                <xades:IssuerSerial>
                                                    <ds:X509IssuerName>''' + str(cert_issuer) + '''</ds:X509IssuerName>
                                                    <ds:X509SerialNumber>''' + str(cert.serial_number) + '''</ds:X509SerialNumber>
                                                </xades:IssuerSerial>
                                            </xades:Cert>
                                        </xades:SigningCertificate>
                                    </xades:SignedSignatureProperties>
                                </xades:SignedProperties>
                            </xades:QualifyingProperties>
                        </ds:Object>'''

        # STEP # 5 in "5. Signing Process"
        # in https://zatca.gov.sa/ar/E-Invoicing/Introduction/Guidelines/Documents/E-invoicing%20Detailed%20Technical%20Guidelines.pdf

        signature_certificate_for_hash = '''<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">
                                    <xades:SignedSignatureProperties>
                                        <xades:SigningTime>''' + fields.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ') + '''</xades:SigningTime>
                                        <xades:SigningCertificate>
                                            <xades:Cert>
                                                <xades:CertDigest>
                                                    <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                                    <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">''' + str(base_64_3) + '''</ds:DigestValue>
                                                </xades:CertDigest>
                                                <xades:IssuerSerial>
                                                    <ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">''' + str(cert_issuer) + '''</ds:X509IssuerName>
                                                    <ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">''' + str(cert.serial_number) + '''</ds:X509SerialNumber>
                                                </xades:IssuerSerial>
                                            </xades:Cert>
                                        </xades:SigningCertificate>
                                    </xades:SignedSignatureProperties>
                                </xades:SignedProperties>'''
        sha_256_5 = hashlib.sha256()
        sha_256_5.update(signature_certificate_for_hash.encode())
        base_64_5 = base64.b64encode(sha_256_5.hexdigest().encode()).decode('UTF-8')

        signature = '''      <ds:SignedInfo>
                                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                                <ds:Reference Id="invoiceSignedData" URI="">
                                    <ds:Transforms>
                                        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                            <ds:XPath>not(//ancestor-or-self::ext:UBLExtensions)</ds:XPath>
                                        </ds:Transform>
                                        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                            <ds:XPath>not(//ancestor-or-self::cac:Signature)</ds:XPath>
                                        </ds:Transform>
                                        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                            <ds:XPath>not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID="QR"])</ds:XPath>
                                        </ds:Transform>
                                        <ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                                    </ds:Transforms>
                                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                    <ds:DigestValue>zatca_invoice_hash</ds:DigestValue>
                                </ds:Reference>
                                <ds:Reference Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties" URI="#xadesSignedProperties">
                                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                    <ds:DigestValue>zatca_signature_hash</ds:DigestValue>
                                </ds:Reference>
                            </ds:SignedInfo>
                            <ds:SignatureValue>zatca_signature_value</ds:SignatureValue>
                            <ds:KeyInfo>
                                <ds:X509Data>
                                    <ds:X509Certificate>''' + str(original_certificate) + '''</ds:X509Certificate>
                                </ds:X509Data>
                            </ds:KeyInfo>'''
        # signature = ''
        # UBL 2.1 sequence
        if self.company_id.currency_id.name != 'SAR':
            # BR-KSA-CL-02
            raise exceptions.ValidationError('currency must be SAR')
        if len(self.invoice_line_ids.ids) <= 0:
            raise exceptions.MissingError('at least one invoice line is required.')
        if self.invoice_datetime > fields.Datetime.now():
            raise exceptions.ValidationError('Date should be less then or equal to today.')
        if not self.company_id.district or not self.company_id.building_no or not self.company_id.additional_no or\
            not self.company_id.city or not self.company_id.zip or not self.company_id.state_id.id or\
                not self.company_id.country_id.id or not self.company_id.street:
            raise exceptions.ValidationError('Some Values are missing in Company Address')

        bt_3 = '381' if self.debit_origin_id.id else ('383' if self.move_type == 'out_refund' else '388')
        if bt_3 != '388':
            bt_25 = str(self.ref.replace('Reversal of: ', '')[0: self.ref.replace('Reversal of: ', '').find(',')])
            bt_25 = self.env['account.move'].search([('name', '=', bt_25)])
            if bt_25.l10n_sa_invoice_type != self.l10n_sa_invoice_type:
                raise exceptions.ValidationError("Mismatched Invoice Type for original and associated invoice.")

        classified_tax_category_list = self.invoice_line_ids.tax_ids.mapped('classified_tax_category')
        # is_tax_invoice = 0 if 'O' in classified_tax_category_list or not len(classified_tax_category_list) else 1
        is_tax_invoice = 1 if self.l10n_sa_invoice_type == 'Standard' else 0
        if is_tax_invoice:
            if conf.get_param('csr_invoice_type') not in ['1100', '1000']:
                raise exceptions.AccessDenied("Certificate not allowed for Standard Invoices.")
            if 'O' in classified_tax_category_list or not len(classified_tax_category_list):
                raise exceptions.ValidationError("Tax Category 'O' can't be used in Standard Invoice")
        if not is_tax_invoice and conf.get_param('csr_invoice_type') not in ['1100', '0100']:
            raise exceptions.AccessDenied("Certificate not allowed for Standard Invoices.")

        if is_tax_invoice and not self.partner_id.district or not self.partner_id.building_no or\
                not self.partner_id.additional_no or not self.partner_id.city or not self.partner_id.zip or\
                not self.partner_id.state_id.id or not self.partner_id.country_id.id or not\
                self.partner_id.street:
            message = 'Some Values are missing in Customer Address, which are required for tax invoices'
            raise exceptions.ValidationError(message)

        self.invoice_uuid = self.invoice_uuid if self.invoice_uuid and self.invoice_uuid != '' else str(str(uuid.uuid4()))

        ksa_16 = int(conf.get_param('zatca.icv_counter'))
        ksa_16 += 1
        conf.set_param('zatca.icv_counter', str(ksa_16))

        company_vat = 0
        # BR-KSA-26
        # ksa_13 = 0
        # ksa_13 = base64.b64encode(bytes(hashlib.sha256(str(ksa_13).encode('utf-8')).hexdigest(), encoding='utf-8')).decode('UTF-8')
        ksa_13 = conf.sudo().get_param('zatca_pih', 'NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==')
        # signature = 0 if is_tax_invoice else 1
        is_third_party_invoice = 0
        is_nominal_invoice = 0
        is_exports_invoice = 0
        is_summary_invoice = 0
        is_self_billed_invoice = 0  # not allowed in odoo
        # BR-KSA-31 (KSA-2)
        ksa_2 = '01' if is_tax_invoice else '02'  # Simplified in case of tax category O
        ksa_2 += '1' if not is_tax_invoice else str(int(self.l10n_is_third_party_invoice))
        ksa_2 += '1' if not is_tax_invoice else str(int(self.l10n_is_nominal_invoice))
        ksa_2 += str(int(self.l10n_is_exports_invoice))
        ksa_2 += '1' if not is_tax_invoice else str(int(self.l10n_is_summary_invoice))
        ksa_2 += "0" if self.l10n_is_exports_invoice else str(int(self.l10n_is_self_billed_invoice))

        if company_vat and not self.l10n_is_exports_invoice:
            if len(str(self.company_id.vat)) != 15:
                raise exceptions.ValidationError('Vat must be exactly 15 minutes')
            if len(str(self.company_id.vat))[0] != '3' or len(str(self.company_id.vat))[-1] != '3':
                raise exceptions.ValidationError('Vat must start/end with 3')

        document_level_allowance_charge = 0
        vat_tax = 0
        bt_31 = self.company_id.vat
        bg_23_list = {}
        bt_92 = 0  # No document level allowance, in default odoo
        bt_106 = float(round(Decimal(str(0)), 2))  # Sum of bt-131 Calculated in invoice line loop.
        bt_107 = float(round(Decimal(str(bt_92)), 2))
        delivery = 1
        not_know = 0
        bt_81 = 10 if 'cash' else (30 if 'credit' else (42 if 'bank account' else (48 if 'bank card' else 1)))
        if bt_3 == '388':
            bt_81 = 48
        accounting_seller_party = 0
        bt_1 = self.id  # may be name is better
        ubl_2_1 = '''
        <Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
                 xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
                 xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
                 xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">'''
        # if not ksa_13 and signature:  # need to check this
        if signature and not previous_hash:
            ubl_2_1 += '''
            <ext:UBLExtensions>'''
            if signature:
                ubl_2_1 += '''
                <ext:UBLExtension>
                    <ext:ExtensionURI>urn:oasis:names:specification:ubl:dsig:enveloped:xades</ext:ExtensionURI>
                    <ext:ExtensionContent>
                        <sig:UBLDocumentSignatures xmlns:sac="urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2" 
                                                   xmlns:sbc="urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2"
                                                   xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2">
                            <sac:SignatureInformation>
                                <cbc:ID>urn:oasis:names:specification:ubl:signature:1</cbc:ID>
                                <sbc:ReferencedSignatureID>urn:oasis:names:specification:ubl:signature:Invoice</sbc:ReferencedSignatureID>
                                <ds:Signature Id="signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'''
                ubl_2_1 += signature
                ubl_2_1 += signature_certificate
                ubl_2_1 += '''  </ds:Signature>
                            </sac:SignatureInformation>
                        </sig:UBLDocumentSignatures>
                    </ext:ExtensionContent>
                </ext:UBLExtension>      '''
            ubl_2_1 += '''
            </ext:UBLExtensions>'''
        if not previous_hash:
            ubl_2_1 += '''
                <cbc:UBLVersionID>2.1</cbc:UBLVersionID>'''
        ubl_2_1 += '''
            <cbc:ProfileID>reporting:1.0</cbc:ProfileID>
            <cbc:ID>''' + str(bt_1) + '''</cbc:ID>
            <cbc:UUID>''' + self.invoice_uuid + '''</cbc:UUID>
            <cbc:IssueDate>''' + self.invoice_datetime.strftime('%Y-%m-%d') + '''</cbc:IssueDate>
            <cbc:IssueTime>''' + self.invoice_datetime.strftime('%H:%M:%S') + '''</cbc:IssueTime>
            <cbc:InvoiceTypeCode name="''' + ksa_2 + '''">''' + bt_3 + '''</cbc:InvoiceTypeCode>
            <cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode>
            <cbc:TaxCurrencyCode>SAR</cbc:TaxCurrencyCode>'''
        if self.purchase_id.id:
            ubl_2_1 += '''
            <cac:OrderReference>
                <cbc:ID>''' + str(self.purchase_id) + '''</cbc:ID>
            </cac:OrderReference>'''
        if bt_3 != '388':  # BR-KSA-56
            bt_25 = str(self.ref.replace('Reversal of: ', '')[0: self.ref.replace('Reversal of: ', '').find(',')])
            bt_25 = self.env['account.move'].search([('name', '=', bt_25)])
            ubl_2_1 += '''
            <cac:BillingReference>
                <cac:InvoiceDocumentReference>
                    <cbc:ID>''' + str(bt_25.id) + '''</cbc:ID>
                    <cbc:IssueDate>''' + str(bt_25.invoice_datetime.strftime('%Y-%m-%d')) + '''</cbc:IssueDate>
                </cac:InvoiceDocumentReference>
            </cac:BillingReference>'''
        ubl_2_1 += '''
            <cac:AdditionalDocumentReference>
                <cbc:ID>ICV</cbc:ID>
                <cbc:UUID>''' + str(ksa_16) + '''</cbc:UUID>
            </cac:AdditionalDocumentReference>
            <cac:AdditionalDocumentReference>
                <cbc:ID>PIH</cbc:ID>
                <cac:Attachment>
                    <cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">''' + str(ksa_13) + '''</cbc:EmbeddedDocumentBinaryObject>
                </cac:Attachment>
            </cac:AdditionalDocumentReference>'''
        if not is_tax_invoice:
        # if is_tax_invoice:
            ubl_2_1 += '''<cac:AdditionalDocumentReference>
                <cbc:ID>QR</cbc:ID>
                <cac:Attachment>
                    <cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">zatca_l10n_sa_qr_code_str</cbc:EmbeddedDocumentBinaryObject>
                </cac:Attachment>
            </cac:AdditionalDocumentReference>'''
        if not previous_hash:
            if signature:  # BR-KSA-60
                ubl_2_1 += '''
            <cac:Signature>
                <cbc:ID>urn:oasis:names:specification:ubl:signature:Invoice</cbc:ID>
                <cbc:SignatureMethod>urn:oasis:names:specification:ubl:dsig:enveloped:xades</cbc:SignatureMethod>
            </cac:Signature>'''
        ubl_2_1 += '''
            <cac:AccountingSupplierParty>
                <cac:Party>'''
        ubl_2_1 += '''
                    <cac:PartyIdentification>
                        <cbc:ID schemeID="''' + self.company_id.license + '''">''' + self.company_id.license_no + '''</cbc:ID>
                    </cac:PartyIdentification>
                    <cac:PostalAddress>
                        <cbc:StreetName>''' + self.company_id.street + '''</cbc:StreetName>'''
        if self.company_id.street2:
            ubl_2_1 += '''
                        <cbc:AdditionalStreetName>''' + self.company_id.street2 + '''</cbc:AdditionalStreetName>'''
        if len(str(self.company_id.additional_no)) != 4:
            raise exceptions.ValidationError('Company/Seller Additional Number must be exactly 4 digits')
        if len(str(self.company_id.zip)) != 5:
            raise exceptions.ValidationError('Company/Seller PostalZone/Zip must be exactly 5 digits')
        ubl_2_1 += '''  <cbc:BuildingNumber>''' + str(self.company_id.building_no) + '''</cbc:BuildingNumber>
                        <cbc:PlotIdentification>''' + str(self.company_id.additional_no) + '''</cbc:PlotIdentification>
                        <cbc:CitySubdivisionName>''' + self.company_id.district + '''</cbc:CitySubdivisionName>
                        <cbc:CityName>''' + self.company_id.city + '''</cbc:CityName>
                        <cbc:PostalZone>''' + str(self.company_id.zip) + '''</cbc:PostalZone>
                        <cbc:CountrySubentity>''' + self.company_id.state_id.name + '''</cbc:CountrySubentity>
                        <cac:Country>
                            <cbc:IdentificationCode>''' + self.company_id.country_id.code + '''</cbc:IdentificationCode>
                        </cac:Country>
                    </cac:PostalAddress>
                    <cac:PartyTaxScheme>
                        <cbc:CompanyID>''' + bt_31 + '''</cbc:CompanyID>
                        <cac:TaxScheme>
                            <cbc:ID>VAT</cbc:ID>
                        </cac:TaxScheme>
                    </cac:PartyTaxScheme>
                    <cac:PartyLegalEntity>
                        <cbc:RegistrationName>''' + self.company_id.name + '''</cbc:RegistrationName>
                    </cac:PartyLegalEntity>
                </cac:Party>
            </cac:AccountingSupplierParty>
            <cac:AccountingCustomerParty>
                <cac:Party>
                    <cac:PartyIdentification>
                        <cbc:ID schemeID="''' + self.partner_id.buyer_identification + '''">''' + self.partner_id.buyer_identification_no + '''</cbc:ID>
                    </cac:PartyIdentification>'''
        if is_tax_invoice:  # Not applicable for simplified tax invoices and associated credit notes and debit notes
            ubl_2_1 += '''
                    <cac:PostalAddress>
                        <cbc:StreetName>''' + self.partner_id.street + '''</cbc:StreetName>'''
            if self.partner_id.street2:
                ubl_2_1 += '''
                        <cbc:AdditionalStreetName>''' + self.partner_id.street2 + '''</cbc:AdditionalStreetName>'''
            ubl_2_1 += '''
                        <cbc:BuildingNumber>''' + str(self.partner_id.building_no) + '''</cbc:BuildingNumber>'''
            if self.partner_id.additional_no:
                ubl_2_1 += '''
                        <cbc:PlotIdentification>''' + str(self.partner_id.additional_no) + '''</cbc:PlotIdentification>'''
            ubl_2_1 += '''
                        <cbc:CitySubdivisionName>''' + self.partner_id.district + '''</cbc:CitySubdivisionName>
                        <cbc:CityName>''' + self.partner_id.city + '''</cbc:CityName>
                        <cbc:PostalZone>''' + str(self.partner_id.zip) + '''</cbc:PostalZone>
                        <cbc:CountrySubentity>''' + self.partner_id.state_id.name + '''</cbc:CountrySubentity>
                        <cac:Country>
                            <cbc:IdentificationCode>''' + self.partner_id.country_id.code + '''</cbc:IdentificationCode>
                        </cac:Country>
                    </cac:PostalAddress>
                    <cac:PartyTaxScheme>'''
            if self.partner_id.vat and not self.l10n_is_exports_invoice:  # BR-KSA-46
                ubl_2_1 += '''
                        <cbc:CompanyID>''' + self.partner_id.vat + '''</cbc:CompanyID>'''
            ubl_2_1 += '''
                        <cac:TaxScheme>
                            <cbc:ID>VAT</cbc:ID>
                        </cac:TaxScheme>
                    </cac:PartyTaxScheme>'''
        bt_121 = 0  # in ['VATEX-SA-EDU', 'VATEX-SA-HEA']
        # BR-KSA-25 and BR-KSA-42
        if is_tax_invoice or ((not is_tax_invoice or ksa_2) and bt_121) or \
                (not is_tax_invoice and self.l10n_is_summary_invoice):
            ubl_2_1 += '''
                    <cac:PartyLegalEntity>
                        <cbc:RegistrationName>''' + self.partner_id.name + '''</cbc:RegistrationName>
                    </cac:PartyLegalEntity>'''
        if bt_121 in ['VATEX-SA-EDU', 'VATEX-SA-HEA'] and self.partner_id.buyer_identification != 'NAT':  #BR-KSA-49
            message = "As tax exemption reason code is in 'VATEX-SA-EDU', 'VATEX-SA-HEA'"
            message += " then Buyer Identification must be 'NAT'"
            raise exceptions.ValidationError(message)
        ubl_2_1 += '''
                </cac:Party>
            </cac:AccountingCustomerParty>'''
        latest_delivery_date = 1 if not is_tax_invoice and self.l10n_is_summary_invoice else 0
        if delivery and ((bt_3 == '388' and ksa_2[:2] == '01' or not is_tax_invoice and self.l10n_is_summary_invoice) or (latest_delivery_date and not_know)):
            ubl_2_1 += '''
            <cac:Delivery>'''
            ksa_5 = self.l10n_sa_delivery_date
            if bt_3 == '388' and ksa_2[:2] == '01' or not is_tax_invoice and self.l10n_is_summary_invoice:
                ubl_2_1 += '''
                <cbc:ActualDeliveryDate>''' + str(ksa_5.strftime('%Y-%m-%d')) + '''</cbc:ActualDeliveryDate>'''
            if latest_delivery_date and not_know:
                ksa_24 = self.l10n_sa_delivery_date
                if ksa_24 < ksa_5:
                    raise exceptions.ValidationError('LatestDeliveryDate must be less then or equal to ActualDeliveryDate')
                ubl_2_1 += '''
                <cbc:LatestDeliveryDate> ''' + str(ksa_24.strftime('%Y-%m-%d')) + ''' </cbc:LatestDeliveryDate> '''
            if not_know:
                ubl_2_1 += '''
                <cac:DeliveryLocation>
                    <cac:Address>
                        <cac:Country>
                            <cbc:IdentificationCode>''' + "" + '''</cbc:IdentificationCode>
                        </cac:Country>
                    </cac:Address>
                </cac:DeliveryLocation'''
            ubl_2_1 += '''
            </cac:Delivery>'''
        ubl_2_1 += '''<cac:PaymentMeans>
            <cbc:PaymentMeansCode>''' + str(bt_81) + '''</cbc:PaymentMeansCode>'''
        if bt_3 != '388':
            ubl_2_1 += '''
            <cbc:InstructionNote>''' + str(self.credit_debit_reason) + '''</cbc:InstructionNote>'''
        ubl_2_1 += '''
        </cac:PaymentMeans>'''
        if document_level_allowance_charge:
            bt_96 = float(round(Decimal(str(0)), 2))
            bt_96 = 100 if bt_96 > 100 else (0 if bt_96 < 0 else bt_96)
            ubl_2_1 += '''
            <cac:AllowanceCharge>
                <cbc:ChargeIndicator>false</cbc:ChargeIndicator>
                <cbc:AllowanceChargeReason>Discount</cbc:AllowanceChargeReason>
                <cbc:Amount currencyID="SAR">''' + str(bt_92) + '''</cbc:Amount>
                <cbc:BaseAmount currencyID="SAR">''' + str(bt_92) + '''</cbc:BaseAmount>
                <cac:TaxCategory>
                    <cbc:ID>''' + "0" + '''</cbc:ID>
                    <cbc:Percent>''' + str(bt_96) + '''</cbc:Percent>
                    <cac:TaxScheme>
                        <cbc:ID>''' + "0" + '''</cbc:ID>
                    </cac:TaxScheme>
                </cac:TaxCategory>
            </cac:AllowanceCharge>'''
        invoice_line_xml = ''
        for invoice_line_id in self.invoice_line_ids:
            if invoice_line_id.discount:
                bt_137 = float(round(Decimal(str(invoice_line_id.price_unit * invoice_line_id.quantity)), 2))
                bt_138 = invoice_line_id.discount  # BR-KSA-DEC-01 for BT-138 only done
                bt_136 = float(round(Decimal(str(bt_137 * bt_138 / 100)), 2))
            else:
                bt_136 = float(round(Decimal(str(0)), 2))
                bt_137 = float(round(Decimal(str(0)), 2))
                bt_138 = invoice_line_id.discount  # BR-KSA-DEC-01 for BT-138 only done
            bt_129 = invoice_line_id.quantity
            bt_147 = 0  # NO ITEM PRICE DISCOUNT bt_148 * invoice_line_id.discount/100 if invoice_line_id.discount else 0
            bt_148 = invoice_line_id.price_unit
            bt_146 = bt_148 - bt_147
            bt_149 = 1  # ??
            bt_131 = float(round(Decimal(str(((bt_146 / bt_149) * bt_129))), 2))
            bt_131 -= float(round(Decimal(str(bt_136)), 2))
            bt_131 = float(round(Decimal(str(bt_131)), 2))
            bt_106 += float(round(Decimal(str(bt_131)), 2))
            bt_106 = float(round(Decimal(str(bt_106)), 2))
            bt_151 = invoice_line_id.tax_ids.classified_tax_category if invoice_line_id.tax_ids else "O"
            bt_152 = float(round(Decimal(str(invoice_line_id.tax_ids.amount)), 2)) if invoice_line_id.tax_ids else 0
            bt_152 = 100 if bt_152 > 100 else (0 if bt_152 < 0 else bt_152)

            if bt_151 == "Z":
                bt_152 = 0
                if not bg_23_list.get("Z", False):
                    bg_23_list["Z"] = {'bt_116': 0, 'bt_121': invoice_line_id.tax_ids.tax_exemption_code,
                                       'bt_120': invoice_line_id.tax_ids.tax_exemption_text,
                                       'bt_119': bt_152, 'bt_117': 0}
                bg_23_list["Z"]['bt_116'] += bt_131
                # bg_23_list = ["Z"]  # BR-Z-01
            elif bt_151 == "E":
                bt_152 = 0
                if not bg_23_list.get("E", False):
                    bg_23_list["E"] = {'bt_116': 0, 'bt_121': invoice_line_id.tax_ids.tax_exemption_code,
                                       'bt_120': invoice_line_id.tax_ids.tax_exemption_text,
                                       'bt_119': bt_152, 'bt_117': 0}
                bg_23_list["E"]['bt_116'] += bt_131
                # bg_23_list = ["E"]  # BR-E-01
            elif bt_151 == "S":
                if not bg_23_list.get("S", False):
                    bg_23_list["S"] = {'bt_116': 0, 'bt_119': bt_152, 'bt_117': 0}
                bg_23_list["S"]['bt_116'] += bt_131
                # bg_23_list = ["E"]  # BR-S-09
            elif bt_151 == "O":
                bt_152 = 0
                if not bg_23_list.get("O", False):
                    bg_23_list["O"] = {'bt_116': 0, 'bt_121': 'Not subject to VAT',
                                       'bt_120': 'Not subject to VAT', 'bt_119': 0, 'bt_117': 0}
                bg_23_list["O"]['bt_116'] += bt_131
                # bg_23_list = ["O"]  # BR-O-01

            invoice_line_xml += '''
            <cac:InvoiceLine>
                <cbc:ID>''' + str(invoice_line_id.id) + '''</cbc:ID>
                <cbc:InvoicedQuantity unitCode="PCE">''' + str(bt_129) + '''</cbc:InvoicedQuantity>
                <cbc:LineExtensionAmount currencyID="SAR">''' + str(bt_131) + '''</cbc:LineExtensionAmount>'''
            if invoice_line_id.discount: #line_allowance_charge:
                invoice_line_xml += '''
                <cac:AllowanceCharge>
                    <cbc:ChargeIndicator>false</cbc:ChargeIndicator>
                    <cbc:AllowanceChargeReasonCode>95</cbc:AllowanceChargeReasonCode>
                    <cbc:AllowanceChargeReason>Discount</cbc:AllowanceChargeReason>'''
                # invoice_line_xml += '''
                #     <cbc:MultiplierFactorNumeric>''' + str(bt_138) + '''</cbc:MultiplierFactorNumeric>'''
                invoice_line_xml += '''
                    <cbc:Amount currencyID="SAR">''' + str(bt_136) + '''</cbc:Amount>'''
                # invoice_line_xml += '''
                #     <cbc:BaseAmount currencyID="SAR">''' + str(bt_137) + '''</cbc:BaseAmount>'''
                if bt_151 != 'O':
                    invoice_line_xml += '''
                        <cac:TaxCategory>
                            <cbc:ID>S</cbc:ID>
                            <cbc:Percent>15</cbc:Percent>
                            <cac:TaxScheme>
                                <cbc:ID>VAT</cbc:ID>
                            </cac:TaxScheme>
                        </cac:TaxCategory>'''
                invoice_line_xml += '''
                    </cac:AllowanceCharge>'''
            ksa_11 = float(round(Decimal(str(bt_131 * bt_152/100)), 2))  #BR-KSA-50
            ksa_12 = float(round(Decimal(str(bt_131 + ksa_11)), 2))  # BR-KSA-51
            if is_tax_invoice:
                invoice_line_xml += '''
                <cac:TaxTotal>'''
                if is_tax_invoice:  #BR-KSA-52 and BR-KSA-53
                    invoice_line_xml += '''
                    <cbc:TaxAmount currencyID="SAR">''' + str(ksa_11) + '''</cbc:TaxAmount>
                    <cbc:RoundingAmount currencyID="SAR">''' + str(ksa_12) + '''</cbc:RoundingAmount>'''
                invoice_line_xml += '''
                </cac:TaxTotal>'''
            invoice_line_xml += '''
                <cac:Item>
                    <cbc:Name>''' + str(invoice_line_id.product_id.name) + '''</cbc:Name>'''
            if invoice_line_id.product_id.barcode and invoice_line_id.product_id.code_type:
                invoice_line_xml += '''
                    <cac:StandardItemIdentification>
                        <cbc:ID schemeID="''' + str(invoice_line_id.product_id.code_type) + '''">''' + str(invoice_line_id.product_id.barcode) + '''</cbc:ID>
                    </cac:StandardItemIdentification>'''
            invoice_line_xml += '''
                    <cac:ClassifiedTaxCategory>
                        <cbc:ID>''' + str(bt_151) + '''</cbc:ID>'''
            if bt_151 != 'O':
                invoice_line_xml += '''
                        <cbc:Percent>''' + str(bt_152) + '''</cbc:Percent>'''
            invoice_line_xml += '''
                        <cac:TaxScheme>
                            <cbc:ID>VAT</cbc:ID>
                        </cac:TaxScheme>
                    </cac:ClassifiedTaxCategory>
                </cac:Item>
                <cac:Price>
                    <cbc:PriceAmount currencyID="SAR">''' + str(bt_146) + '''</cbc:PriceAmount>
                    <cbc:BaseQuantity unitCode="PCE">''' + str(bt_149) + '''</cbc:BaseQuantity>
                </cac:Price>
            </cac:InvoiceLine>'''
        bt_110 = float(round(Decimal(str(0)), 2))  # Sum of bt-117 Calculated in bg_23 loop
        tax_subtotal_xml = ''
        for bg_23 in bg_23_list.keys():
            bt_116 = float(round(Decimal(str(bg_23_list[bg_23]['bt_116'])), 2))
            bt_119 = bg_23_list[bg_23]['bt_119']
            bt_118 = bg_23
            if bt_118 == "S":
                bt_117 = float(round(Decimal(str(bt_116 * (bt_119 / 100))), 2))
                bt_110 += bt_117
            else:
                bt_117 = float(round(Decimal(str(0)), 2))
            tax_subtotal_xml += '''
            <cac:TaxSubtotal>
                <cbc:TaxableAmount currencyID="SAR">''' + str(bt_116) + '''</cbc:TaxableAmount>
                <cbc:TaxAmount currencyID="SAR">''' + str(bt_117) + '''</cbc:TaxAmount>
                <cac:TaxCategory>
                    <cbc:ID>''' + str(bt_118) + '''</cbc:ID>'''
            if bt_118 != "O":
                tax_subtotal_xml += '''
                    <cbc:Percent>''' + str(bt_119) + '''</cbc:Percent>'''
            if bt_118 != "S" and bt_118 in ['E', 'O', 'Z']:
                bt_120 = bg_23_list[bg_23]['bt_120']
                bt_121 = bg_23_list[bg_23]['bt_121']
                tax_subtotal_xml += '''
                    <cbc:TaxExemptionReasonCode>''' + str(bt_121) + '''</cbc:TaxExemptionReasonCode>
                    <cbc:TaxExemptionReason>''' + str(bt_120) + '''</cbc:TaxExemptionReason>'''
            tax_subtotal_xml += '''
                    <cac:TaxScheme>
                        <cbc:ID>VAT</cbc:ID>
                    </cac:TaxScheme>
                </cac:TaxCategory>
            </cac:TaxSubtotal>'''
        bt_109 = float(round(Decimal(str(bt_106 - bt_107)), 2))
        bt_111 = bt_110  # Same as bt-110
        bt_112 = float(round(Decimal(str(bt_109 + bt_110)), 2))
        bt_113 = float(round(Decimal(str(self.amount_total - self.amount_residual)), 2))
        bt_115 = float(round(Decimal(str(bt_112 - bt_113)), 2))
        ubl_2_1 += '''
            <cac:TaxTotal>
                <cbc:TaxAmount currencyID="SAR">''' + str(bt_110) + '''</cbc:TaxAmount>'''
        ubl_2_1 += tax_subtotal_xml
        ubl_2_1 += '''
            </cac:TaxTotal>
            <cac:TaxTotal>
                <cbc:TaxAmount currencyID="SAR">''' + str(bt_111) + '''</cbc:TaxAmount>
            </cac:TaxTotal>'''
        ubl_2_1 += '''
            <cac:LegalMonetaryTotal>
                <cbc:LineExtensionAmount currencyID="SAR">''' + str(bt_106) + '''</cbc:LineExtensionAmount>
                <cbc:TaxExclusiveAmount currencyID="SAR">''' + str(bt_109) + (" | " + str(self.amount_untaxed) if amount_verification else '') +'''</cbc:TaxExclusiveAmount>
                <cbc:TaxInclusiveAmount currencyID="SAR">''' + str(bt_112) + (" | " + str(self.amount_total) if amount_verification else '') + '''</cbc:TaxInclusiveAmount>'''
        if not_know:
            ubl_2_1 += '''
                <cbc:ChargeTotalAmount currencyID="SAR">''' + str("0") + '''</cbc:ChargeTotalAmount>'''
        if bt_113:
            ubl_2_1 += '''
                <cbc:PrepaidAmount currencyID="SAR">''' + str(bt_113) + '''</cbc:PrepaidAmount>'''
        if not_know:
            ubl_2_1 += '''
                <cbc:PayableRoundingAmount currencyID="SAR">''' + str("0") + '''</cbc:PayableRoundingAmount>'''
        ubl_2_1 += '''
                <cbc:PayableAmount currencyID="SAR">''' + str(bt_115 if bt_115 > 0 else 0) + (" | " + str(self.amount_residual) if amount_verification else '') + '''</cbc:PayableAmount>
            </cac:LegalMonetaryTotal>'''
        ubl_2_1 += invoice_line_xml
        ubl_2_1 += '''
        </Invoice>'''

        file_name_specification = str(bt_31) + "_" + self.invoice_datetime.strftime('%Y%m%dT%H%M%SZ') + "_" + str(self.id)
        self.zatca_invoice_name = file_name_specification + ".xml"
        self.hash_with_c14n_canonicalization(xml=ubl_2_1)
        conf.sudo().set_param('zatca_pih', self.zatca_invoice_hash)
        if signature:
            hash_filename = hashlib.sha256(('account_move_' + str(self.id) + '_signature_value').encode("UTF-8")).hexdigest()
            f = open('/tmp/' + str(hash_filename), 'wb+')
            f.write(base64.b64decode(self.zatca_invoice_hash))
            f.close()
            signature = '''openssl dgst -sha256 -sign /tmp/zatcaprivatekey.pem /tmp/''' + hash_filename + ''' | base64 /dev/stdin'''
            print(signature)
            signature_value = os.popen(signature).read()
            signature_value = signature_value.replace('\n', '').replace(' ', '')
            print(signature_value)
            os.system('''rm  /tmp/''' + str(hash_filename))
            if not signature_value or signature_value in [None, '']:
                raise exceptions.ValidationError('Error in private key, kindly regenerate credentials.')

            # signature_filename = hashlib.sha256(('account_move_' + str(self.id) + '_signature_value').encode("UTF-8")).hexdigest()
            # os.system('''echo ''' + str(signature_value) + ''' | base64 -d /dev/stdin > /tmp/''' + str(signature_filename))
            # Signature validation
            # signature_verify = '''echo ''' + str(self.zatca_invoice_hash_hex) + ''' | openssl dgst -verify /tmp/zatcapublickey.pem -signature /tmp/''' + str(signature_filename) + ''' /dev/stdin'''
            # if "Verified OK" not in os.popen(signature_verify).read():
            #     raise exceptions.ValidationError("Signature can't be verified, try again.")
            # os.system('''rm  /tmp/''' + str(signature_filename))

            ubl_2_1 = ubl_2_1.replace('zatca_signature_hash', str(base_64_5))
            ubl_2_1 = ubl_2_1.replace('zatca_signature_value', str(signature_value))
            self.compute_qr_code_str(signature_value, is_tax_invoice, bt_112, bt_110)
            if not is_tax_invoice:
            # if is_tax_invoice:
                ubl_2_1 = ubl_2_1.replace('zatca_l10n_sa_qr_code_str', str(self.l10n_sa_qr_code_str))
        ubl_2_1 = ubl_2_1.replace('zatca_invoice_hash', str(self.zatca_invoice_hash))

        atts = self.env['ir.attachment'].sudo().search([('res_model', '=', 'account.move'), ('res_field', '=', 'zatca_invoice'),
                                                        ('res_id', 'in', self.ids)])
        if atts:
            atts.sudo().write({'datas': base64.b64encode(bytes(ubl_2_1, 'utf-8'))})
        else:
            atts.sudo().create([{
                'name': file_name_specification + ".xml",
                'res_model': 'account.move',
                'res_field': 'zatca_invoice',
                'res_id': self.id,
                'type': 'binary',
                'datas': base64.b64encode(bytes(ubl_2_1, 'utf-8')),
                'mimetype': 'text/xml',
                # 'datas_fname': file_name_specification + ".xml"
            }])
        print("ZATCA: xml invoice & hash invoice generated.")

    def generate_signature(self):
        # STEP # 1 => DONE  => NOT NEEDED, DONE ABOVE
        # STEP # 2 => DONE  => NOT NEEDED, DONE ABOVE
        # STEP # 3 => DONE  => NOT NEEDED, DONE ABOVE
        # STEP # 4 => DONE  => NOT NEEDED, DONE ABOVE
        # STEP # 5 => Still remaining
        # STEP # 6 => DONE  => NOT NEEDED, DONE ABOVE
        pass

    def compliance_invoices_api(self):
        link = "https://gw-apic-gov.gazt.gov.sa/e-invoicing/developer-portal"
        endpoint = '/compliance/invoices'

        conf = self.env['ir.config_parameter'].sudo()

        if conf.get_param('zatca_status', '') == 'Onboarding failed, restart process !!':
            raise exceptions.AccessDenied('Onboarding failed, restart process !!')

        zatca_on_board_status_details = json.loads(conf.get_param('zatca_on_board_status_details', '{"error": "404"}'))
        is_tax_invoice = 'standard' if self.l10n_sa_invoice_type == 'Standard' else 'simplified'
        bt_3 = 'debit' if self.debit_origin_id.id else ('credit' if self.move_type == 'out_refund' else 'invoice')

        user = conf.get_param("zatca_sb_bsToken", False)
        password = conf.get_param("zatca_sb_secret", False)
        auth = base64.b64encode(('%s:%s' % (user, password)).encode('utf-8')).decode('utf-8')
        headers = {'accept': 'application/json',
                   'Accept-Language': 'en',
                   'Accept-Version': 'V2',
                   'Authorization': 'Basic ' + auth,
                   'Content-Type': 'application/json'}

        data = {
            'invoiceHash': self.zatca_invoice_hash,
            # 'invoiceHash': self.hash_with_c14n_canonicalization(api_invoice=1),
            'uuid': self.invoice_uuid,
            'invoice': self.zatca_invoice.decode('UTF-8'),
        }
        try:
            req = requests.post(link + endpoint, headers=headers, data=json.dumps(data))
            if req.status_code == 500:
                raise exceptions.AccessError('Invalid Request, \ncontact system administer')
            elif req.status_code == 401:

                raise exceptions.AccessError('Unauthorized Request, \nUpdate configuration for sandbox')
            elif req.status_code in [200, 400]:
                response = json.loads(req.text)
                string = "<table style='width:100%'>"
                string += "<tr><td  colspan='6'><b>validationResults</b></td></tr>"

                for key, value in response['validationResults'].items():
                    if type(value) == list:
                        string += "<tr><td  colspan='6'><center><b>" + key + "</b></center></td></tr>"
                        qty = 1
                        for val in value:
                            color = 'green' if str(val['status']).lower() == 'pass' else 'red'
                            string += "<tr>"
                            string += "<td colspan='2' style='border: 1px solid black;'>" + str(qty) + "</td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'type' + "</b></td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'code' + "</b></td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'category' + "</b></td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'status' + "</b></td>"
                            string += "</tr>"
                            string += "<tr>"
                            string += "<td  style='border: 1px solid black;' colspan='2'></td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['type']) + "</td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['code']) + "</td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['category']) + "</td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['status']) + "</td>"
                            string += "</tr>"
                            string += "<tr>"
                            string += "<td colspan='2'  style='border: 1px solid black;'><b>" + 'message' + "</b></td>"
                            string += "<td colspan='4'  style='border: 1px solid black;color: " + color + ";'>" + str(val['message']) + "</td>"
                            string += "</tr>"
                            qty += 1
                    else:
                        string += "<tr>"
                        string += "<td>" + key + "</td><td colspan='3'>" + str(value) + "</td>"
                        string += "</tr>"
                string += "<tr><td colspan='2'><b>reportingStatus</b></td><td colspan='4'>" + str(response['reportingStatus']) + "</td></tr>"
                string += "<tr><td colspan='2'><b>clearanceStatus</b></td><td colspan='4'>" + str(response['clearanceStatus']) + "</td></tr>"
                string += "<tr><td colspan='2'><b>qrSellertStatus</b></td><td colspan='4'>" + str(response['qrSellertStatus']) + "</td></tr>"
                string += "<tr><td colspan='2'><b>qrBuyertStatus </b></td><td colspan='4'>" + str(response['qrBuyertStatus'])+ "</td></tr>"
                string += "<tr><td colspan='6'></td></tr>"

                if response['validationResults']['errorMessages'] == [] and response['validationResults']['status'] == 'PASS' and \
                    (response['reportingStatus'] == "REPORTED" or response['clearanceStatus'] == "CLEARED"):
                    zatca_on_board_status_details[is_tax_invoice][bt_3] = 1
                    conf.set_param('zatca_on_board_status_details', json.dumps(zatca_on_board_status_details))
                    total_required = []
                    for x in zatca_on_board_status_details.keys():
                        total_required += list(zatca_on_board_status_details[x].values())
                    invoices_required = str(len(total_required) - sum(total_required))
                    if invoices_required == '0':
                        conf.set_param('zatca_status', "Onboarding completed, request for production credentials now")
                        conf.set_param('csr_otp', None)
                        conf.set_param('zatca_onboarding_status', 1)
                        string += "<tr><td colspan='6'><center><b>" + \
                                  str("Onboarding completed, request for production credentials now") + "</b></center></td></tr>"
                    else:
                        on_board_status = json.loads(conf.get_param('zatca_on_board_status_details'))
                        status = ''
                        if on_board_status.get('standard', 0):
                            status += "\nStandard: "
                            if not on_board_status.get('standard', 0).get('invoice', 0):
                                status += "invoice,"
                            if not on_board_status.get('standard', 0).get('credit', 0):
                                status += "credit,"
                            if not on_board_status.get('standard', 0).get('debit', 0):
                                status += "debit,"
                        if on_board_status.get('simplified', 0):
                            status += "\nSimplified: "
                            if not on_board_status.get('simplified', 0).get('invoice', 0):
                                status += "invoice,"
                            if not on_board_status.get('simplified', 0).get('credit', 0):
                                status += "credit,"
                            if not on_board_status.get('simplified', 0).get('debit', 0):
                                status += "debit,"
                        zatca_status = conf.get_param('zatca_status', 'invoices\n')
                        zatca_status[:zatca_status.find('invoices\n') + 9] + status
                        conf.set_param('zatca_status', zatca_status[:zatca_status.find('invoices\n') + 9] + status)

                        conf.set_param('zatca_status',
                                       conf.get_param('zatca_status')[:29] + invoices_required +
                                       conf.get_param('zatca_status')[30:])
                        string += "<tr><td colspan='6'><center><b>" + \
                                  str("Onboarding in progress, " + invoices_required + " invoices remaining") + "</b></center></td></tr>"
                        if status.rfind('\n'):
                            string += "<tr><td colspan='6'><center><b>" + \
                                      str(status[:status.rfind('\n')]) + "</b></center></td></tr>"
                            string += "<tr><td colspan='6'><center><b>" + \
                                      str(status[status.rfind('\n'):]) + "</b></center></td></tr>"
                        else:
                            string += "<tr><td colspan='6'><center><b>" + \
                                      str(status) + "</b></center></td></tr>"
                    string += "</table>"
                else:
                    string += "<tr><td colspan='6'><center><b>" + \
                              str('Onboarding failed, restart process !!') + "</b></center></td></tr>"
                    string += "</table>"
                    conf.set_param('zatca_on_board_status_details', json.dumps(zatca_on_board_status_details))
                    conf.set_param('zatca_status', 'Onboarding failed, restart process !!')
                    conf.set_param('zatca_onboarding_status', 0)
                    conf.set_param('csr_certificate', None)
                    conf.set_param('csr_otp', None)
            json_iterated = string
            self.zatca_compliance_invoices_api = json_iterated
            return {
                'type': 'ir.actions.act_window',
                'name': "Zatca Response",
                'res_model': 'account.move',
                'view_mode': 'form',
                'res_id': self.id,
                'views': [(self.env.ref('ksa_zatca_integration.zatca_response').id, 'form')],
            }
        except Exception as e:
            raise exceptions.AccessDenied(e)

    def invoices_clearance_single_api(self):
        link = "https://gw-apic-gov.gazt.gov.sa/e-invoicing/developer-portal"
        endpoint = '/invoices/clearance/single'

        conf = self.env['ir.config_parameter'].sudo()

        user = conf.get_param("zatca_bsToken", False)
        password = conf.get_param("zatca_secret", False)
        auth = base64.b64encode(('%s:%s' % (user, password)).encode('utf-8')).decode('utf-8')
        headers = {'accept': 'application/json',
                   'Accept-Language': 'en',
                   'Clearance-Status': '1',
                   'Accept-Version': 'V2',
                   'Authorization': 'Basic ' + auth,
                   'Content-Type': 'application/json'}

        data = {
            'invoiceHash': self.zatca_invoice_hash,
            # 'invoiceHash': self.hash_with_c14n_canonicalization(api_invoice=1),
            'uuid': self.invoice_uuid,
            'invoice': self.zatca_invoice.decode('UTF-8'),
        }
        try:
            req = requests.post(link + endpoint, headers=headers, data=json.dumps(data))
            if req.status_code == 500:
                raise exceptions.AccessError('Invalid Request, \ncontact system administer')
            elif req.status_code == 401:
                raise exceptions.AccessError('Unauthorized Request, \nUpdate configuration for production')
            elif req.status_code in [200, 400]:
                response = json.loads(req.text)
                string = "<table style='width:100%'>"
                string += "<tr><td  colspan='6'><b>validationResults</b></td></tr>"

                for key, value in response['validationResults'].items():
                    if type(value) == list:
                        string += "<tr><td  colspan='6'><center><b>" + key + "</b></center></td></tr>"
                        qty = 1
                        for val in value:
                            color = 'green' if str(val['status']).lower() == 'pass' else 'red'
                            string += "<tr>"
                            string += "<td colspan='2' style='border: 1px solid black;'>" + str(qty) + "</td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'type' + "</b></td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'code' + "</b></td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'category' + "</b></td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'status' + "</b></td>"
                            string += "</tr>"
                            string += "<tr>"
                            string += "<td  style='border: 1px solid black;' colspan='2'></td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['type']) + "</td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['code']) + "</td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['category']) + "</td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['status']) + "</td>"
                            string += "</tr>"
                            string += "<tr>"
                            string += "<td colspan='2'  style='border: 1px solid black;'><b>" + 'message' + "</b></td>"
                            string += "<td colspan='4'  style='border: 1px solid black;color: " + color + ";'>" + str(val['message']) + "</td>"
                            string += "</tr>"
                            qty += 1
                    else:
                        string += "<tr>"
                        string += "<td>" + key + "</td><td colspan='3'>" + str(value) + "</td>"
                        string += "</tr>"
                string += "<tr><td colspan='2'><b>clearanceStatus</b></td><td colspan='4'>" + str(response['clearanceStatus']) + "</td></tr>"
                string += "<tr><td colspan='2'><b>clearedInvoice</b></td><td colspan='4'>" + str(response['clearedInvoice']) + "</td></tr>"
                string += "</table>"

                json_iterated = string
                self.zatca_compliance_invoices_api = json_iterated

                file_name_specification = str(self.company_id.vat) + "_" + self.invoice_datetime.strftime('%Y%m%dT%H%M%SZ') + "_" + str(self.id)
                atts = self.env['ir.attachment'].sudo().search([('res_model', '=', 'account.move'),
                                                                ('res_field', '=', 'zatca_hash_cleared_invoice'),
                                                                ('res_id', 'in', self.ids)])
                if response['clearedInvoice']:
                    bt_3 = 'debit_note' if self.debit_origin_id.id else ('credit_note' if self.move_type == 'out_refund' else 'invoice')
                    if atts:
                        atts.sudo().write({'datas': response['clearedInvoice']})
                    else:
                        atts.sudo().create([{
                            'name': file_name_specification + ".xml",
                            'res_model': 'account.move',
                            'res_field': 'zatca_hash_cleared_invoice',
                            'res_id': self.id,
                            'type': 'binary',
                            'datas': response['clearedInvoice'],
                            'mimetype': 'text/xml',
                        }])
                    self.zatca_hash_cleared_invoice_name = file_name_specification + ".xml"
            return {
                'type': 'ir.actions.act_window',
                'name': "Zatca Response",
                'res_model': 'account.move',
                'view_mode': 'form',
                'res_id': self.id,
                'views': [(self.env.ref('ksa_zatca_integration.zatca_response').id, 'form')],
            }
        except Exception as e:
            raise exceptions.AccessDenied(e)

    def invoices_reporting_single_api(self):
        link = "https://gw-apic-gov.gazt.gov.sa/e-invoicing/developer-portal"
        endpoint = '/invoices/reporting/single'

        conf = self.env['ir.config_parameter'].sudo()

        user = conf.get_param("zatca_bsToken", False)
        password = conf.get_param("zatca_secret", False)

        auth = base64.b64encode(('%s:%s' % (user, password)).encode('utf-8')).decode('utf-8')
        headers = {'accept': 'application/json',
                   'Accept-Language': 'en',
                   'Clearance-Status': '1',
                   'Accept-Version': 'V2',
                   'Authorization': 'Basic ' + auth,
                   'Content-Type': 'application/json'}

        data = {
            'invoiceHash': self.zatca_invoice_hash,
            # 'invoiceHash': self.hash_with_c14n_canonicalization(api_invoice=1),
            'uuid': self.invoice_uuid,
            'invoice': self.zatca_invoice.decode('UTF-8'),
        }
        try:
            req = requests.post(link + endpoint, headers=headers, data=json.dumps(data))
            if req.status_code == 500:
                raise exceptions.AccessError('Invalid Request, \ncontact system administer')
            elif req.status_code == 401:
                raise exceptions.AccessError('Unauthorized Request, \nUpdate configuration for production')
            elif req.status_code in [200, 400]:
                response = json.loads(req.text)
                string = "<table style='width:100%'>"
                string += "<tr><td  colspan='6'><b>validationResults</b></td></tr>"

                for key, value in response['validationResults'].items():
                    if type(value) == list:
                        string += "<tr><td  colspan='6'><center><b>" + key + "</b></center></td></tr>"
                        qty = 1
                        for val in value:
                            color = 'green' if str(val['status']).lower() == 'pass' else 'red'
                            string += "<tr>"
                            string += "<td colspan='2' style='border: 1px solid black;'>" + str(qty) + "</td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'type' + "</b></td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'code' + "</b></td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'category' + "</b></td>"
                            string += "<td  style='border: 1px solid black;'><b>" + 'status' + "</b></td>"
                            string += "</tr>"
                            string += "<tr>"
                            string += "<td  style='border: 1px solid black;' colspan='2'></td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['type']) + "</td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['code']) + "</td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['category']) + "</td>"
                            string += "<td  style='border: 1px solid black;color: " + color + ";'>" + str(val['status']) + "</td>"
                            string += "</tr>"
                            string += "<tr>"
                            string += "<td colspan='2'  style='border: 1px solid black;'><b>" + 'message' + "</b></td>"
                            string += "<td colspan='4'  style='border: 1px solid black;color: " + color + ";'>" + str(val['message']) + "</td>"
                            string += "</tr>"
                            qty += 1
                    else:
                        string += "<tr>"
                        string += "<td>" + key + "</td><td colspan='3'>" + str(value) + "</td>"
                        string += "</tr>"
                string += "<tr><td colspan='2'><b>reportingStatus</b></td><td colspan='4'>" + str(response['reportingStatus']) + "</td></tr>"
                string += "</table>"

                json_iterated = string
                self.zatca_compliance_invoices_api = json_iterated
            return {
                'type': 'ir.actions.act_window',
                'name': "Zatca Response",
                'res_model': 'account.move',
                'view_mode': 'form',
                'res_id': self.id,
                'views': [(self.env.ref('ksa_zatca_integration.zatca_response').id, 'form')],
            }
        except Exception as e:
            raise exceptions.AccessDenied(e)

    def hash_with_c14n_canonicalization(self, api_invoice=0, xml=0):
        invoice = base64.b64decode(self.zatca_invoice).decode() if not xml else xml
        xml_file = ET.fromstring(invoice)
        if not api_invoice:
            xsl_file = ET.fromstring('''<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                            xmlns:xs="http://www.w3.org/2001/XMLSchema"
                            xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
                            xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
                            xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
                            xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
                            exclude-result-prefixes="xs"
                            version="2.0">
                <xsl:output omit-xml-declaration="yes" encoding="utf-8" indent="no"/>
                <xsl:template match="node() | @*">
                    <xsl:copy>
                        <xsl:apply-templates select="node() | @*"/>
                    </xsl:copy>
                </xsl:template>
                <xsl:template match="//*[local-name()='Invoice']//*[local-name()='UBLExtensions']"></xsl:template>
                <xsl:template match="//*[local-name()='AdditionalDocumentReference'][cbc:ID[normalize-space(text()) = 'QR']]"></xsl:template>
                 <xsl:template match="//*[local-name()='Invoice']/*[local-name()='Signature']"></xsl:template>
            </xsl:stylesheet>''')
            transform = ET.XSLT(xsl_file.getroottree())
            transformed_xml = transform(xml_file.getroottree())
        else:
            transformed_xml = xml_file.getroottree()
        #
        # transformed_xml.find("//{http://uri.etsi.org/01903/v1.3.2#}SignedSignatureProperties")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(ET.tostring(transformed_xml))
        generated_hash = sha256_hash.hexdigest()
        base64_encoded = base64.b64encode(sha256_hash.digest()).decode()
        if not api_invoice:
            self.zatca_invoice_hash = base64_encoded
            self.zatca_invoice_hash_hex = generated_hash
        else:
            return base64_encoded

        atts = self.env['ir.attachment'].sudo().search([('res_model', '=', 'account.move'),
                                                        ('res_field', '=', 'zatca_hash_invoice'),
                                                        ('res_id', 'in', self.ids)])
        if atts:
            atts.sudo().write({'datas': base64.b64encode(ET.tostring(transformed_xml))})
        else:
            atts.sudo().create([{
                'name': self.zatca_invoice_name.replace('.xml', '_hash.xml'),
                'res_model': 'account.move',
                'res_field': 'zatca_hash_invoice',
                'res_id': self.id,
                'type': 'binary',
                'datas': base64.b64encode(ET.tostring(transformed_xml)),
                'mimetype': 'text/xml',
            }])
        self.zatca_hash_invoice_name = self.zatca_invoice_name.replace('.xml', '_hash.xml')

    def _compute_qr_code_str(self):
        try:
            invoice = base64.b64decode(self.zatca_invoice).decode()
            xml_file = ET.fromstring(invoice).getroottree()
            is_tax_invoice = 1 if self.l10n_sa_invoice_type == 'Standard' else 0
            signature_value = xml_file.find("//{http://www.w3.org/2000/09/xmldsig#}SignatureValue").text
            bt_112 = xml_file.find("//{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxInclusiveAmount").text
            bt_110 = xml_file.find("//{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxAmount").text
            self.compute_qr_code_str(signature_value, is_tax_invoice, bt_112, bt_110)
        except:
            self.l10n_sa_qr_code_str = "emFpbiBpcmZhbiB3YWhlZWQ="

    def compute_qr_code_str(self, signature_value, is_tax_invoice, bt_112, bt_110):
        def get_qr_encoding(tag, field):
            company_name_byte_array = field if tag in [8, 9] else field.encode()
            company_name_tag_encoding = tag.to_bytes(length=1, byteorder='big')
            company_name_length_encoding = len(company_name_byte_array).to_bytes(length=1, byteorder='big')
            return company_name_tag_encoding + company_name_length_encoding + company_name_byte_array

        for record in self:
            qr_code_str = ''
            if record.l10n_sa_confirmation_datetime and record.company_id.vat:
                seller_name_enc = get_qr_encoding(1, record.company_id.display_name)
                company_vat_enc = get_qr_encoding(2, record.company_id.vat)
                time_sa = fields.Datetime.context_timestamp(self.with_context(tz='Asia/Riyadh'), record.l10n_sa_confirmation_datetime)
                # timestamp_enc = get_qr_encoding(3, time_sa.isoformat())
                timestamp_enc = get_qr_encoding(3, time_sa.strftime('%Y-%m-%dT%H:%M:%SZ'))
                timestamp_enc = get_qr_encoding(3, self.invoice_datetime.strftime('%Y-%m-%dT%H:%M:%SZ'))
                # invoice_total_enc = get_qr_encoding(4, float_repr(abs(record.amount_total_signed), 2))
                invoice_total_enc = get_qr_encoding(4, str(bt_112))
                # total_vat_enc = get_qr_encoding(5, float_repr(abs(record.amount_tax_signed), 2))
                total_vat_enc = get_qr_encoding(5, str(bt_110))

                invoice_hash = get_qr_encoding(6, record.zatca_invoice_hash)
                ecdsa_signature = get_qr_encoding(7, signature_value)

                f = open('/tmp/zatca_cert_publickey.bin', 'rb')
                cert_pub_key = f.read()
                ecdsa_public_key = get_qr_encoding(8, cert_pub_key)
                if not is_tax_invoice:
                    conf = self.env['ir.config_parameter'].sudo()
                    ecdsa_cert_value = get_qr_encoding(9, binascii.unhexlify(conf.get_param("zatca_cert_sig_algo", '')))

                str_to_encode = seller_name_enc + company_vat_enc + timestamp_enc + invoice_total_enc + total_vat_enc
                str_to_encode += invoice_hash + ecdsa_signature + ecdsa_public_key
                if not is_tax_invoice:
                    str_to_encode += ecdsa_cert_value
                qr_code_str = base64.b64encode(str_to_encode).decode()
            record.l10n_sa_qr_code_str = qr_code_str
            record.sa_qr_code_str = qr_code_str

    def zatca_response(self):
        return {
            'type': 'ir.actions.act_window',
            'name': "Zatca Response",
            'res_model': 'account.move',
            'view_mode': 'form',
            'res_id': self.id,
            'views': [(self.env.ref('ksa_zatca_integration.zatca_response').id, 'form')],
        }

    def send_for_compliance(self):
        self.create_xml_file()
        return self.compliance_invoices_api()

    def send_for_clearance(self):
        self.create_xml_file()
        return self.invoices_clearance_single_api()

    def send_for_reporting(self):
        self.create_xml_file()
        return self.invoices_reporting_single_api()

    # ZATCA Exception

    def unlink(self):
        message = "Based on the VAT regulation, after issuing an invoice, it is prohibited to " \
                  "modify or cancel the invoice. and according the regulation, a debit/credit " \
                  "notes must be generated to modify or cancel the generated invoice. Therefore" \
                  " the supplier should issue an electronic credit/debit note linked to the original." \
                  " modified invoice"
        if self.state != 'draft' and self.move_type in ['out_invoice', 'out_refund']:
            raise exceptions.AccessDenied(message)
        return super(AccountMove, self).unlink()

    def button_draft(self):
        message = "Based on the VAT regulation, after issuing an invoice, it is prohibited to " \
                  "modify or cancel the invoice. and according the regulation, a debit/credit " \
                  "notes must be generated to modify or cancel the generated invoice. Therefore" \
                  " the supplier should issue an electronic credit/debit note linked to the original." \
                  " modified invoice"
        if self.state == 'posted' and self.move_type in ['out_invoice', 'out_refund']:
            raise exceptions.AccessDenied(message)
        return super(AccountMove, self).button_draft()

    def button_cancel(self):
        message = "Based on the VAT regulation, after issuing an invoice, it is prohibited to " \
                  "modify or cancel the invoice. and according the regulation, a debit/credit " \
                  "notes must be generated to modify or cancel the generated invoice. Therefore" \
                  " the supplier should issue an electronic credit/debit note linked to the original." \
                  " modified invoice"
        if self.state == 'posted' and self.move_type in ['out_invoice', 'out_refund']:
            raise exceptions.AccessDenied(message)
        return super(AccountMove, self).button_cancel()
