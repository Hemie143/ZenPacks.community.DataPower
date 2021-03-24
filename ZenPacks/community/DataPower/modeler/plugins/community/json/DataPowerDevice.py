# stdlib Imports
import base64
import json

# Zenoss Imports
from Products.DataCollector.plugins.CollectorPlugin import PythonPlugin
from Products.DataCollector.plugins.DataMaps import MultiArgs
from ZenPacks.community.DataPower.lib.utils import SkipCertifContextFactory

# Twisted Imports
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.web.client import Agent, readBody
from twisted.web.http_headers import Headers


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
        headers = {"Authorization": [authHeader],
                   "User-Agent": ["Mozilla/3.0Gold"],
                   }
        agent = Agent(reactor, contextFactory=SkipCertifContextFactory())
        try:
            response = yield agent.request('GET', url, Headers(headers))
            response_body = yield readBody(response)
            results = json.loads(response_body)
        except:
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
        info = results.get('FirmwareStatus2', [])

        om = self.objectMap()

        version = info.get('Version', '')
        devtype = info.get('DeliveryType', '')
        build = info.get('Build', '')
        om.setOSProductKey = MultiArgs('{} {} (Build: {})'.format(version, devtype, build), 'IBM DataPower')
        return om
