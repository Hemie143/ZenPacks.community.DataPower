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
from Products.DataCollector.plugins.DataMaps import ObjectMap, RelationshipMap, MultiArgs
from Products.ZenUtils.Utils import monkeypatch


# TODO : CamelCase (check in YAML)
# TODO : cleanup
# TODO : PEP8
class DataPowerDevice(PythonPlugin):
    """
    Doc about this plugin
    """

    requiredProperties = (
        'zDataPowerPort',
        'zDataPowerUsername',
        'zDataPowerPassword',
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

        url = "https://{}:{}/mgmt/status/default/FirmwareStatus2".format(ip_address, port)
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
        info = results.get('FirmwareStatus2', [])

        om = self.objectMap()

        version = info.get('Version', '')
        devtype = info.get('DeliveryType', '')
        build = info.get('Build', '')
        om.setOSProductKey = MultiArgs('{} {} (Build: {})'.format(version, devtype, build), 'IBM DataPower')
        return om
