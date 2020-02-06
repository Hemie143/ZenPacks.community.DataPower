import json
import logging
import base64
import re

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

        for datasource in config.datasources:
            if_id = datasource.component
            log.debug('AAA if_id: {}'.format(if_id))
            for interface in result:
                # TODO : enhance this, as it will work only if the id is identical to the interface name
                if interface['Name'] == if_id:
                    result.remove(interface)
                    break
            adminStatusText = interface['AdminStatus']
            operStatusText = interface['OperStatus']
            adminStatusVal = self.if_adminstatus.get(adminStatusText, 3)
            operStatusVal = self.if_operstatus.get(operStatusText, 3)
            data['values'][if_id]['intf_adminstatus'] = adminStatusVal
            data['values'][if_id]['intf_operstatus'] = operStatusVal
            data['values'][if_id]['intf_ifinoctets'] = interface['RxHCBytes']
            data['values'][if_id]['intf_ifoutoctets'] = interface['TxHCBytes']
            data['values'][if_id]['intf_ifinpackets'] = interface['RxHCPackets']
            data['values'][if_id]['intf_ifoutpackets'] = interface['TxHCPackets']
            data['values'][if_id]['intf_ifinerrors'] = interface['RxErrors2']
            data['values'][if_id]['intf_ifouterrors'] = interface['TxErrors2']
            data['values'][if_id]['intf_ifindrops'] = interface['RxDrops2']
            data['values'][if_id]['intf_ifoutdrops'] = interface['TxDrops2']

            data['events'].append({
                'device': config.id,
                'component': if_id,
                'severity': adminStatusVal,
                'eventKey': 'DataPowerInterface',
                'eventClassKey': 'DataPowerInterface',
                'summary': 'Interface {} - Admin Status is {}'.format(if_id, adminStatusText),
                'message': 'Interface {} - Admin Status is {}'.format(if_id, adminStatusText),
                'eventClass': '/Status/Interface',
            })
            data['events'].append({
                'device': config.id,
                'component': if_id,
                'severity': operStatusVal,
                'eventKey': 'DataPowerInterface',
                'eventClassKey': 'DataPowerInterface',
                'summary': 'Interface {} - Admin Status is {}'.format(if_id, operStatusText),
                'message': 'Interface {} - Admin Status is {}'.format(if_id, operStatusText),
                'eventClass': '/Status/Interface',
            })

        log.debug('data: {}'.format(data))

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
        filesystem_metrics = result['FilesystemStatus']

        for datasource in config.datasources:
            fs_id = datasource.component
            fs_type = fs_id.split(' ')[0]
            total = filesystem_metrics['Total{}'.format(fs_type)]
            free = filesystem_metrics['Free{}'.format(fs_type)]
            data['values'][fs_id]['filesystem_total'] = total
            data['values'][fs_id]['filesystem_used'] = total - free
            data['values'][fs_id]['filesystem_percentUsed'] = (total - free) / float(total) * 100

        return data

    def onError(self, result, config):
        log.error('Error - result is {}'.format(result))
        # TODO: send event of collection failure
        return {}
