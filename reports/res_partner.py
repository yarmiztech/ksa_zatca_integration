from odoo import api, fields, models


class ResPartner(models.Model):
    _inherit = 'res.partner'

    arabic_name = fields.Text('Arabic Name')
    group_vat_no = fields.Char('Group Vat No')
    # to bypass errors
    other_buyer_id = fields.Char()
