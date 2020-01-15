import json
import logging
import base64

# Twisted Imports
from twisted.internet.defer import returnValue, DeferredSemaphore, DeferredList, inlineCallbacks
from twisted.web.client import getPage

# Zenoss imports
from ZenPacks.zenoss.PythonCollector.datasources.PythonDataSource import PythonDataSourcePlugin
from Products.ZenUtils.Utils import prepId

# Setup logging
log = logging.getLogger('zen.DataPowerOS')


class Cpu(PythonDataSourcePlugin):
    proxy_attributes = (
        'zDataPowerPort',
        'zDataPowerUsername',
        'zDataPowerPassword',
    )

    @staticmethod
    def add_tag(result, label):
        return tuple((label, result))

    @classmethod
    def config_key(cls, datasource, context):
        log.debug('In config_key {} {} {}'.format(context.device().id, datasource.getCycleTime(context),
                                                  'CPU'))

        return (
            context.device().id,
            datasource.getCycleTime(context),
            'CPU'
        )

    @inlineCallbacks
    def collect(self, config):
        log.debug('Starting CPUUsage collect')
        ip_address = config.manageIp
        if not ip_address:
            log.error("%s: IP Address cannot be empty", device.id)
            returnValue(None)

        ds0 = config.datasources[0]
        url = "https://{}:{}/mgmt/status/default/CPUUsage".format(ip_address, ds0.zDataPowerPort)
        log.debug('url: {}'.format(url))
        basicAuth = base64.encodestring('{}:{}'.format(ds0.zDataPowerUsername, ds0.zDataPowerPassword))
        authHeader = "Basic " + basicAuth.strip()
        headers = {"Authorization": authHeader,
                   "User-Agent": "Mozilla/3.0Gold",
                   }
        d = yield getPage(url, headers=headers)
        returnValue(d)

    def onSuccess(self, result, config):
        log.debug('Success job - result is {}'.format(result))
        data = self.new_data()
        result = json.loads(result)

        ds0 = config.datasources[0]
        log.debug('ds0.component: {}'.format(ds0.component))
        log.debug('ds0.datasource: {}'.format(ds0.datasource))
        for point in ds0.points:
            log.debug('point.id: {}'.format(point.id))


        data['values'][None]['cpu_cpuusage1'] = result['CPUUsage']['oneMinute']
        data['values'][None]['cpu_cpuusage10'] = result['CPUUsage']['tenMinutes']
        log.debug('CPU Data: {}'.format(data))
        return data

    def onError(self, result, config):
        log.error('Error - result is {}'.format(result))
        # TODO: send event of collection failure
        return {}


class Memory(PythonDataSourcePlugin):
    proxy_attributes = (
        'zDataPowerPort',
        'zDataPowerUsername',
        'zDataPowerPassword',
    )

    @classmethod
    def config_key(cls, datasource, context):
        log.debug('In config_key {} {} {}'.format(context.device().id, datasource.getCycleTime(context),
                                                  'Memory'))

        return (
            context.device().id,
            datasource.getCycleTime(context),
            'Memory'
        )

    @inlineCallbacks
    def collect(self, config):
        log.debug('Starting MemoryStatus collect')
        ip_address = config.manageIp
        if not ip_address:
            log.error("%s: IP Address cannot be empty", device.id)
            returnValue(None)

        ds0 = config.datasources[0]
        url = "https://{}:{}/mgmt/status/default/MemoryStatus".format(ip_address, ds0.zDataPowerPort)
        log.debug('url: {}'.format(url))
        basicAuth = base64.encodestring('{}:{}'.format(ds0.zDataPowerUsername, ds0.zDataPowerPassword))
        authHeader = "Basic " + basicAuth.strip()
        headers = {"Authorization": authHeader,
                   "User-Agent": "Mozilla/3.0Gold",
                   }
        d = yield getPage(url, headers=headers)
        returnValue(d)

    def onSuccess(self, result, config):
        log.debug('Success job - result is {}'.format(result))
        data = self.new_data()
        result = json.loads(result)
        data['values'][None]['memory_totalmemory'] = result['MemoryStatus']['TotalMemory']
        data['values'][None]['memory_usedmemory'] = result['MemoryStatus']['UsedMemory']
        data['values'][None]['memory_reqmemory'] = result['MemoryStatus']['ReqMemory']
        data['values'][None]['memory_holdmemory'] = result['MemoryStatus']['HoldMemory']
        data['values'][None]['memory_reservedmemory'] = result['MemoryStatus']['ReservedMemory']
        data['values'][None]['memory_installedmemory'] = result['MemoryStatus']['InstalledMemory']
        data['values'][None]['memory_usedmemoryperc'] = float(result['MemoryStatus']['UsedMemory']) / \
                                                        result['MemoryStatus']['TotalMemory'] * 100
        return data

    def onError(self, result, config):
        log.error('Error - result is {}'.format(result))
        # TODO: send event of collection failure
        return {}


class Interface(PythonDataSourcePlugin):
    proxy_attributes = (
        'zDataPowerPort',
        'zDataPowerUsername',
        'zDataPowerPassword',
    )

    if_adminstatus = {
        "up": 0,
    }

    if_operstatus = {
        "up": 0,
        "down": 5,
        "testing": 3,
        "unknown": 3,
        "dormant": 3,
        "notPresent": 3,
        "LowerLayerDown": 3,
    }

    @classmethod
    def config_key(cls, datasource, context):
        log.debug('In config_key {} {} {}'.format(context.device().id, datasource.getCycleTime(context),
                                                  'Interface'))

        return (
            context.device().id,
            datasource.getCycleTime(context),
            'Interface'
        )

    @inlineCallbacks
    def collect(self, config):
        log.debug('Starting Interface collect')
        ip_address = config.manageIp
        if not ip_address:
            log.error("%s: IP Address cannot be empty", device.id)
            returnValue(None)

        ds0 = config.datasources[0]
        url = "https://{}:{}/mgmt/status/default/NetworkInterfaceStatus".format(ip_address, ds0.zDataPowerPort)
        log.debug('url: {}'.format(url))
        basicAuth = base64.encodestring('{}:{}'.format(ds0.zDataPowerUsername, ds0.zDataPowerPassword))
        authHeader = "Basic " + basicAuth.strip()
        headers = {"Authorization": authHeader,
                   "User-Agent": "Mozilla/3.0Gold",
                   }
        d = yield getPage(url, headers=headers)
        returnValue(d)

    def onSuccess(self, result, config):
        log.debug('Success job - result is {}'.format(result))
        data = self.new_data()
        result = json.loads(result)['NetworkInterfaceStatus']
        # log.debug('CCC result: {}'.format(len(result)))
        for interface in result:
            if_name = interface['Name']
            if_id = prepId(if_name)
            adminStatusText = interface['AdminStatus']
            operStatusText = interface['OperStatus']
            adminStatusVal = self.if_adminstatus.get(adminStatusText, 3)
            operStatusVal = self.if_adminstatus.get(operStatusText, 3)
            log.debug("CCC {}: Adminstatus: {}".format(if_name, adminStatusText))
            log.debug("CCC {}: Operstatus : {}".format(if_name, operStatusText))
            data['values'][if_id]['adminstatus'] = adminStatusVal
            data['values'][if_id]['operstatus'] = operStatusVal
            data['events'].append({
                'device': config.id,
                'component': if_id,
                'severity': adminStatusVal,
                'eventKey': 'DataPowerInterface',
                'eventClassKey': 'DataPowerInterface',
                'summary': 'Interface {} - Admin Status is {}'.format(if_name, adminStatusText),
                'message': 'Interface {} - Admin Status is {}'.format(if_name, adminStatusText),
                'eventClass': '/Status/Interface',
            })
            data['events'].append({
                'device': config.id,
                'component': if_id,
                'severity': operStatusVal,
                'eventKey': 'DataPowerInterface',
                'eventClassKey': 'DataPowerInterface',
                'summary': 'Interface {} - Admin Status is {}'.format(if_name, operStatusText),
                'message': 'Interface {} - Admin Status is {}'.format(if_name, operStatusText),
                'eventClass': '/Status/Interface',
            })

            data['values'][if_id]['ifInOctets'] = interface['RxHCBytes']
            data['values'][if_id]['ifOutOctets'] = interface['TxHCBytes']
            data['values'][if_id]['ifInPackets'] = interface['RxHCPackets']
            data['values'][if_id]['ifOutPackets'] = interface['TxHCPackets']
            data['values'][if_id]['ifInErrors'] = interface['RxErrors2']
            data['values'][if_id]['ifOutErrors'] = interface['TxErrors2']
            data['values'][if_id]['ifInDrops'] = interface['RxDrops2']
            data['values'][if_id]['ifOutDrops'] = interface['TxDrops2']
        '''
        "InterfaceIndex" : 7,
        "InterfaceType" : "Ethernet",
        "Name" : "eth3",
        "AdminStatus" : "up",
        "OperStatus" : "up",
        "IPType" : "ipv4",
        "IP" : "10.1.20.161",
        "PrefixLength" : 24,
        "MACAddress" : "00:50:56:92:05:24",
        "MTU" : 1500,
        "RxHCBytes" : 88960492,
        "RxHCPackets" : 959945,
        "RxErrors2" : 0,
        "RxDrops2" : 123,
        "TxHCBytes" : 4571804,
        "TxHCPackets" : 67471,
        "TxErrors2" : 0,
        "TxDrops2" : 0},
        '''


        '''
                   if_name = interface["Name"]
            if zInterfaceMapIgnoreNames and re.search(zInterfaceMapIgnoreNames, if_name):
                continue
            if_type = interface["IPType"]
            if zInterfaceMapIgnoreTypes and re.search(zInterfaceMapIgnoreTypes, if_type):
                continue

            if_ip = interface["IP"]

            om_if = ObjectMap()
            om_if.id = self.prepId(if_name)
        '''

        '''
        data['values'][None]['memory_totalmemory'] = result['MemoryStatus']['TotalMemory']
        data['values'][None]['memory_usedmemory'] = result['MemoryStatus']['UsedMemory']
        data['values'][None]['memory_reqmemory'] = result['MemoryStatus']['ReqMemory']
        data['values'][None]['memory_holdmemory'] = result['MemoryStatus']['HoldMemory']
        data['values'][None]['memory_reservedmemory'] = result['MemoryStatus']['ReservedMemory']
        data['values'][None]['memory_installedmemory'] = result['MemoryStatus']['InstalledMemory']
        test = float(result['MemoryStatus']['UsedMemory']) / result['MemoryStatus']['TotalMemory'] * 100
        log.debug('test: {}'.format(test))
        data['values'][None]['memory_usedmemoryperc'] = float(result['MemoryStatus']['UsedMemory']) / \
                                                        result['MemoryStatus']['TotalMemory'] * 100
        log.debug('freememory: {}'.format(result['MemoryStatus']['FreeMemory']))
        log.debug('memory_usedmemoryperc: {}'.format(data['values'][None]['memory_usedmemoryperc']))
        log.debug('Memory Data: {}'.format(data))
        '''

        '''              
              usedmemoryperc: usedmemoryperc
        '''

        return data

    def onError(self, result, config):
        log.error('Error - result is {}'.format(result))
        # TODO: send event of collection failure
        return {}


class DataPowerFileSystem(PythonDataSourcePlugin):
    proxy_attributes = (
        'zDataPowerPort',
        'zDataPowerUsername',
        'zDataPowerPassword',
    )

    @classmethod
    def config_key(cls, datasource, context):
        log.debug('In config_key {} {} {}'.format(context.device().id, datasource.getCycleTime(context),
                                                  'FileSystem'))

        return (
            context.device().id,
            datasource.getCycleTime(context),
            'FileSystem'
        )

    @inlineCallbacks
    def collect(self, config):
        log.debug('Starting FilesystemStatus collect')
        ip_address = config.manageIp
        if not ip_address:
            log.error("%s: IP Address cannot be empty", device.id)
            returnValue(None)

        ds0 = config.datasources[0]
        url = "https://{}:{}/mgmt/status/default/FilesystemStatus".format(ip_address, ds0.zDataPowerPort)
        log.debug('url: {}'.format(url))
        basicAuth = base64.encodestring('{}:{}'.format(ds0.zDataPowerUsername, ds0.zDataPowerPassword))
        authHeader = "Basic " + basicAuth.strip()
        headers = {"Authorization": authHeader,
                   "User-Agent": "Mozilla/3.0Gold",
                   }
        d = yield getPage(url, headers=headers)
        returnValue(d)

    def onSuccess(self, result, config):
        log.debug('Success job - result is {}'.format(result))
        data = self.new_data()
        result = json.loads(result)

        total = result['FilesystemStatus']['TotalEncrypted']
        free = result['FilesystemStatus']['FreeEncrypted']
        data['values']['Encrypted']['filesystem_total'] = total
        data['values']['Encrypted']['filesystem_used'] = total - free
        data['values']['Encrypted']['filesystem_percentUsed'] = (total - free) / float(total) * 100

        total = result['FilesystemStatus']['TotalTemporary']
        free = result['FilesystemStatus']['FreeTemporary']
        data['values']['Temporary']['filesystem_total'] = total
        data['values']['Temporary']['filesystem_used'] = total - free
        data['values']['Temporary']['filesystem_percentUsed'] = (total - free) / float(total) * 100

        total = result['FilesystemStatus']['TotalInternal']
        free = result['FilesystemStatus']['FreeInternal']
        data['values']['Internal']['filesystem_total'] = total
        data['values']['Internal']['filesystem_used'] = total - free
        data['values']['Internal']['filesystem_percentUsed'] = (total - free) / float(total) * 100

        return data

    def onError(self, result, config):
        log.error('Error - result is {}'.format(result))
        # TODO: send event of collection failure
        return {}
