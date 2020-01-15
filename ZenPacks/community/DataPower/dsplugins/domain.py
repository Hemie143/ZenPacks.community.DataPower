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
log = logging.getLogger('zen.DataPowerDomain')


class DomainState(PythonDataSourcePlugin):
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
                                                  'Domain'))

        return (
            context.device().id,
            datasource.getCycleTime(context),
            'Domain'
        )

    @inlineCallbacks
    def collect(self, config):
        log.debug('Starting Domain collect')
        ip_address = config.manageIp
        if not ip_address:
            log.error("%s: IP Address cannot be empty", device.id)
            returnValue(None)

        ds0 = config.datasources[0]
        url = "https://{}:{}/mgmt/status/default/DomainStatus".format(ip_address, ds0.zDataPowerPort)
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


class DomainState(PythonDataSourcePlugin):
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
                                                  'Domain'))

        return (
            context.device().id,
            datasource.getCycleTime(context),
            'Domain'
        )

    @inlineCallbacks
    def collect(self, config):
        log.debug('Starting Domain collect')
        ip_address = config.manageIp
        if not ip_address:
            log.error("%s: IP Address cannot be empty", device.id)
            returnValue(None)

        ds0 = config.datasources[0]
        url = "https://{}:{}/mgmt/status/default/DomainStatus".format(ip_address, ds0.zDataPowerPort)
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

