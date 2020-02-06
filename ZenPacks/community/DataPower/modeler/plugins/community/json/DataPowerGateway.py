# stdlib Imports
import json
import base64
import re

# Twisted Imports
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, DeferredSemaphore, DeferredList
from twisted.web.client import getPage, Agent

# Zenoss Imports
from Products.DataCollector.plugins.CollectorPlugin import PythonPlugin
from Products.DataCollector.plugins.DataMaps import ObjectMap, RelationshipMap
from Products.ZenUtils.Utils import monkeypatch


# TODO : CamelCase (check in YAML)
# TODO : cleanup
# TODO : PEP8
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
        headers = {"Authorization": authHeader,
                   "User-Agent": "Mozilla/3.0Gold",
                   }
        deferreds = []
        sem = DeferredSemaphore(1)
        for domain in domains:
            url = "https://{}:{}/mgmt/config/{}/APIConnectGatewayService".format(ip_address, port, domain['name'])
            d = sem.run(getPage, url, headers=headers)
            deferreds.append(d)

        url = "https://{}:{}/mgmt/config/default/HostAlias".format(ip_address, port)
        d = sem.run(getPage, url, headers=headers)
        deferreds.append(d)

        results = yield DeferredList(deferreds, consumeErrors=True)
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
        for success, item in results:
            item = json.loads(item)
            if "HostAlias" not in item:
                continue
            for host in item["HostAlias"]:
                host_dict[host['name']] = host['IPAddress']

        rm = []
        for success, item in results:
            item = json.loads(item)
            if "APIConnectGatewayService" not in item:
                continue
            href = item["_links"]["self"]["href"]
            r = re.match("/mgmt/config/(.*)/APIConnectGatewayService", href)
            if r:
                maps = []
                domain = r.group(1)
                comp_domain = 'dataPowerDomains/{}'.format(self.prepId(domain))
                apicgw = item["APIConnectGatewayService"]
                gw_address = apicgw["APIGatewayAddress"]
                if gw_address == '0.0.0.0':
                    continue
                gw_ip = host_dict.get(gw_address, None)
                gw_port = apicgw["APIGatewayPort"]
                om_gw = ObjectMap()
                om_gw.id = self.prepId('{}_{}_{}'.format(domain, gw_address, gw_port))
                om_gw.title = '{} ({}:{})'.format(gw_address, gw_ip, gw_port)
                om_gw.domain = domain
                om_gw.gateway_address = gw_address
                om_gw.gateway_port = gw_port
                om_gw.gateway_ip = gw_ip
                maps.append(om_gw)

                rm.append(RelationshipMap(relname='dataPowerGateways',
                                          modname='ZenPacks.community.DataPower.DataPowerGateway',
                                          compname=comp_domain,
                                          objmaps=maps))
        return rm
