# stdlib Imports
import base64
import json

# Zenoss Imports
from Products.DataCollector.plugins.CollectorPlugin import PythonPlugin
from Products.DataCollector.plugins.DataMaps import ObjectMap, RelationshipMap
from ZenPacks.community.DataPower.lib.utils import SkipCertifContextFactory

# Twisted Imports
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.web.client import Agent, readBody
from twisted.web.http_headers import Headers


class DataPowerGateway(PythonPlugin):
    """
    Doc about this plugin
    """

    requiredProperties = (
        'zDataPowerPort',
        'zDataPowerUsername',
        'zDataPowerPassword',
        'get_domains'
    )

    deviceProperties = PythonPlugin.deviceProperties + requiredProperties

    @inlineCallbacks
    def collect(self, device, log):
        log.debug('{}: Modeling collect'.format(device.id))

        port = getattr(device, 'zDataPowerPort', None)

        username = getattr(device, 'zDataPowerUsername', None)
        if not username:
            log.error("%s: zDataPowerUsername is not defined", device.id)
            returnValue(None)

        password = getattr(device, 'zDataPowerPassword', None)
        if not password:
            log.error("%s: zDataPowerPassword is not defined", device.id)
            returnValue(None)

        ip_address = device.manageIp
        if not ip_address:
            log.error("%s: IP Address cannot be empty", device.id)
            returnValue(None)

        domains = device.get_domains
        basicAuth = base64.encodestring('{}:{}'.format(username, password))
        authHeader = "Basic " + basicAuth.strip()
        headers = {"Authorization": [authHeader],
                   "User-Agent": ["Mozilla/3.0Gold"],
                   }
        agent = Agent(reactor, contextFactory=SkipCertifContextFactory())
        results = {'domains': {}}
        for domain in domains:
            try:
                url = "https://{}:{}/mgmt/config/{}/APIConnectGatewayService".format(ip_address, port, domain['name'])
                response = yield agent.request('GET', url, Headers(headers))
                response_body = yield readBody(response)
                results['domains'][domain['name']] = json.loads(response_body)
            except Exception as e:
                log.error('{}: {}'.format(device.id, e))

        url = "https://{}:{}/mgmt/config/default/HostAlias".format(ip_address, port)
        try:
            response = yield agent.request('GET', url, Headers(headers))
            response_body = yield readBody(response)
            results['hostalias'] = json.loads(response_body)
        except Exception as e:
            log.error('{}: {}'.format(device.id, e))
        returnValue(results)

    def process(self, device, results, log):
        """
        Must return one of :
            - None, changes nothing. Good in error cases.
            - A RelationshipMap, for the device to component information
            - An ObjectMap, for the device device information
            - A list of RelationshipMaps and ObjectMaps, both
        """
        # Just retrieve the Host Aliases
        host_dict = {}
        if 'hostalias' in results:
            for host in results["hostalias"]['HostAlias']:
                host_dict[host['name']] = host['IPAddress']

        rm = []
        if 'domains' in results:
            domains_data = results['domains']
            for domain_name, domain_data in domains_data.items():
                if "APIConnectGatewayService" not in domain_data:
                    continue
                maps = []
                comp_domain = 'dataPowerDomains/{}'.format(self.prepId(domain_name))
                apicgw = domain_data["APIConnectGatewayService"]
                gw_address = apicgw["APIGatewayAddress"]
                if gw_address == '0.0.0.0':
                    continue
                gw_ip = host_dict.get(gw_address, None)
                gw_port = apicgw["APIGatewayPort"]
                om_gw = ObjectMap()
                om_gw.id = self.prepId('{}_{}_{}'.format(domain_name, gw_address, gw_port))
                om_gw.title = '{} ({}:{})'.format(gw_address, gw_ip, gw_port)
                om_gw.domain = domain_name
                om_gw.gateway_address = gw_address
                om_gw.gateway_port = gw_port
                om_gw.gateway_ip = gw_ip
                maps.append(om_gw)

                rm.append(RelationshipMap(relname='dataPowerGateways',
                                          modname='ZenPacks.community.DataPower.DataPowerGateway',
                                          compname=comp_domain,
                                          objmaps=maps))
        return rm
