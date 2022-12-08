from odoo import api, fields, models


class ResCompany(models.Model):
    _inherit = 'res.company'

    arabic = fields.Char('Arabic Name')
    group_vat_no = fields.Char('Group Vat No')

    signature_custom = fields.Binary('Signature')
    sig_stamp = fields.Binary(string="Stamp Picture")
    bank_name = fields.Char('Bank Name')
    iban = fields.Char('IBAN')
    account_name = fields.Char('Account Name')
    # to bypass errors
    other_seller_id = fields.Char()
