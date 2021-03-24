# stdlib Imports
import base64
import json
import re

# Zenoss Imports
from Products.DataCollector.plugins.CollectorPlugin import PythonPlugin
from Products.DataCollector.plugins.DataMaps import ObjectMap, RelationshipMap
from ZenPacks.community.DataPower.lib.utils import SkipCertifContextFactory

# Twisted Imports
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.web.client import Agent, readBody
from twisted.web.http_headers import Headers


class DataPowerFilesystem(PythonPlugin):
    """
    Doc about this plugin
    """

    requiredProperties = (
        'zDataPowerPort',
        'zDataPowerUsername',
        'zDataPowerPassword',
        'zFileSystemMapIgnoreNames',
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

        url = "https://{}:{}/mgmt/status/default/FilesystemStatus".format(ip_address, port)
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
        # results = json.loads(results)
        filesystems = results.get("FilesystemStatus", [])

        knownFilesystems = ['Encrypted', 'Internal', 'Temporary']
        knownFSre = '|'.join(knownFilesystems)
        foundFilesystems = set()

        zFileSystemMapIgnoreNames = getattr(device, 'zFileSystemMapIgnoreNames', None)

        fs_maps = []
        rm = []
        reFS = '(Free|Total)(.+)$'

        for filesystem in filesystems:
            r = re.search(reFS, filesystem)
            if not r:
                continue
            fs_type = r.group(2)
            fs_name = '{} Space'.format(fs_type)
            if zFileSystemMapIgnoreNames and re.search(zFileSystemMapIgnoreNames, fs_name):
                continue
            if fs_name not in foundFilesystems:
                foundFilesystems.add(fs_name)
                om_fs = ObjectMap()
                om_fs.id = self.prepId(fs_name)
                om_fs.title = fs_name
                om_fs.mount = fs_name
                fs_maps.append(om_fs)

        rm.append(RelationshipMap(compname='',
                                  relname='dataPowerFileSystems',
                                  modname='ZenPacks.community.DataPower.DataPowerFileSystem',
                                  objmaps=fs_maps))
        return rm
