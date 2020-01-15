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
class DataPowerInterface(PythonPlugin):
    """
    Doc about this plugin
    """

    requiredProperties = (
        'zDataPowerPort',
        'zDataPowerUsername',
        'zDataPowerPassword',
        'zInterfaceMapIgnoreNames',
        'zInterfaceMapIgnoreTypes',
    )

    deviceProperties = PythonPlugin.deviceProperties + requiredProperties

    @staticmethod
    def add_tag(result, label):
        return tuple((label, result))

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

        url = "https://{}:{}/mgmt/status/default/NetworkInterfaceStatus".format(ip_address, port)
        log.debug('url: {}'.format(url))
        basicAuth = base64.encodestring('{}:{}'.format(username, password))
        authHeader = "Basic " + basicAuth.strip()
        headers = {"Authorization": authHeader,
                   "User-Agent": "Mozilla/3.0Gold",
                   }
        d = yield getPage(url, headers=headers)
        returnValue(d)

    def process(self, device, results, log):
        """
        Must return one of :
            - None, changes nothing. Good in error cases.
            - A RelationshipMap, for the device to component information
            - An ObjectMap, for the device device information
            - A list of RelationshipMaps and ObjectMaps, both
        """
        results = json.loads(results)
        networkinterfaces = results.get('NetworkInterfaceStatus', [])

        zInterfaceMapIgnoreNames = getattr(device, 'zInterfaceMapIgnoreNames', None)
        zInterfaceMapIgnoreTypes = getattr(device, 'zInterfaceMapIgnoreTypes', None)

        if_maps = []
        rm = []
        for interface in networkinterfaces:
            if_name = interface["Name"]
            if zInterfaceMapIgnoreNames and re.search(zInterfaceMapIgnoreNames, if_name):
                continue
            if_type = interface["IPType"]
            if zInterfaceMapIgnoreTypes and re.search(zInterfaceMapIgnoreTypes, if_type):
                continue

            if_ip = interface["IP"]

            om_if = ObjectMap()
            om_if.id = self.prepId(if_name)
            om_if.title = if_name

            if if_ip:
                if_netmask = interface["PrefixLength"]
                om_if.setIpAddresses = ['{}/{}'.format(if_ip, if_netmask)]
            else:
                om_if.setIpAddresses = []

            om_if.interfaceName = if_name
            om_if.ifIndex = interface["InterfaceIndex"]
            om_if.ips = if_ip.split(",")
            om_if.macaddress = interface["MACAddress"]
            om_if.type = if_type
            om_if.mtu = interface["MTU"]
            if_maps.append(om_if)

        # modname = 'ZenPacks.community.DataPower.DataPowerInterface',
        rm.append(RelationshipMap(compname='os',
                                  relname='dataPowerInterfaces',
                                  modname='ZenPacks.community.DataPower.DataPowerInterface',
                                  objmaps=if_maps))

        return rm
