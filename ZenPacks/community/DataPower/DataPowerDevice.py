import json

from . import schema


class DataPowerDevice(schema.DataPowerDevice):

    def get_domains(self):
        domains_list = []
        for domain in self.dataPowerDomains():
            domain_dict = {'id': domain.id, 'name': domain.title}
            domains_list.append(domain_dict)

        return domains_list

