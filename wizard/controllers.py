# -*- coding: utf-8 -*-
# from odoo import http


# class ZifZatcaPhase2(http.Controller):
#     @http.route('/zif_zatca_phase_2/zif_zatca_phase_2', auth='public')
#     def index(self, **kw):
#         return "Hello, world"

#     @http.route('/zif_zatca_phase_2/zif_zatca_phase_2/objects', auth='public')
#     def list(self, **kw):
#         return http.request.render('zif_zatca_phase_2.listing', {
#             'root': '/zif_zatca_phase_2/zif_zatca_phase_2',
#             'objects': http.request.env['zif_zatca_phase_2.zif_zatca_phase_2'].search([]),
#         })

#     @http.route('/zif_zatca_phase_2/zif_zatca_phase_2/objects/<model("zif_zatca_phase_2.zif_zatca_phase_2"):obj>', auth='public')
#     def object(self, obj, **kw):
#         return http.request.render('zif_zatca_phase_2.object', {
#             'object': obj
#         })
