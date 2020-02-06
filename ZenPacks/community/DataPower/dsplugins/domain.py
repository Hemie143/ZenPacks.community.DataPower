import json
import logging
import base64
import re

# Twisted Imports
from twisted.internet import reactor
from twisted.internet.defer import returnValue, DeferredSemaphore, DeferredList, inlineCallbacks
from twisted.web.client import getPage, Agent, readBody
from twisted.web.http_headers import Headers
from twisted.internet.error import TimeoutError

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

    domain_if_state = {
        'ok': 0,
    }

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
        domain_status = result['DomainStatus']

        for datasource in config.datasources:
            d_id = datasource.component
            for domain in domain_status:
                # TODO : enhance this, as it will work only if the id is identical to the interface name
                if domain['Domain'] == d_id:
                    domain_status.remove(domain)
                    break
            interface_state_text = domain['InterfaceState']
            interface_state = self.domain_if_state.get(interface_state_text, 3)
            data['values'][d_id]['interface_state'] = interface_state
            data['events'].append({
                'device': config.id,
                'component': d_id,
                'severity': interface_state,
                'eventKey': 'DataPowerDomain',
                'eventClassKey': 'DataPowerDomain',
                'summary': 'Domain {} - Interface State is {}'.format(d_id, interface_state_text),
                'message': 'Domain {} - Interface State is {}'.format(d_id, interface_state_text),
                'eventClass': '/Status/DataPower/Domain',
            })
        return data

    def onError(self, result, config):
        log.error('Error - result is {}'.format(result))
        # TODO: send event of collection failure
        return {}


class DomainObject(PythonDataSourcePlugin):
    proxy_attributes = (
        'zDataPowerPort',
        'zDataPowerUsername',
        'zDataPowerPassword',
        'zDomainObjectIgnoreNames',
    )

    @staticmethod
    def add_tag(result, label):
        return tuple((label, result))

    @classmethod
    def config_key(cls, datasource, context):
        log.debug('In config_key {} {} {} {}'.format(context.device().id, datasource.getCycleTime(context), context.id,
                                                     'DomainObject'))

        return (
            context.device().id,
            datasource.getCycleTime(context),
            context.id,
            'DomainObject'
        )

    @inlineCallbacks
    def collect(self, config):
        log.debug('Starting Domain collect')
        ip_address = config.manageIp
        if not ip_address:
            log.error("%s: IP Address cannot be empty", device.id)
            returnValue(None)

        ds0 = config.datasources[0]
        basicAuth = base64.encodestring('{}:{}'.format(ds0.zDataPowerUsername, ds0.zDataPowerPassword))
        authHeader = "Basic " + basicAuth.strip()
        headers = {"Authorization": authHeader,
                   "User-Agent": "Mozilla/3.0Gold",
                   }

        for datasource in config.datasources:
            d_id = datasource.component
            url = "https://{}:{}/mgmt/status/{}/ObjectStatus".format(ip_address, datasource.zDataPowerPort, d_id)
            log.debug('url: {}'.format(url))
            d = yield getPage(url, headers=headers)

        returnValue(d)

    def onSuccess(self, result, config):
        # log.debug('Success job - result is {}'.format(result))
        data = self.new_data()
        result = json.loads(result)

        ds0 = config.datasources[0]
        ignoreNames = ds0.zDomainObjectIgnoreNames
        domain_id = ds0.component
        object_status = result['ObjectStatus']
        domain_state_text = 'up'
        domain_state = 0
        message = []
        for object in object_status:
            objectname = object['Name']
            if ignoreNames and re.search(ignoreNames, objectname):
                # (default-gateway-peering)
                continue
            opstate = object['OpState']
            adminstate = object['AdminState']
            if adminstate == 'enabled' and opstate != "up":
                domain_state_text = 'down'
                domain_state = 4
                message.append('Object {} of Class {} is {}: {}'.format(objectname, object['Class'], opstate,
                                                                        object['ErrorCode']))

        data['values'][domain_id]['object_status'] = domain_state
        data['events'].append({
            'device': config.id,
            'component': domain_id,
            'severity': domain_state,
            'eventKey': 'DataPowerDomainObject',
            'eventClassKey': 'DataPowerDomainObject',
            'summary': 'Domain {} - Object State is {}'.format(domain_id, domain_state_text),
            'message': '\r\n'.join(message),
            'eventClass': '/Status/DataPower/Domain',
        })
        return data

    def onError(self, result, config):
        log.error('Error - result is {}'.format(result))
        # TODO: send event of collection failure
        return {}


class GatewayService(PythonDataSourcePlugin):
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
        log.debug('In config_key {} {} {} {}'.format(context.device().id, datasource.getCycleTime(context), context.id,
                                                     'GatewayService'))

        return (
            context.device().id,
            datasource.getCycleTime(context),
            context.id,
            'GatewayService'
        )

    @classmethod
    def params(cls, datasource, context):
        log.info('Starting GatewayService params')
        params = {}
        params['gateway_ip'] = context.gateway_ip
        params['gateway_port'] = context.gateway_port
        return params

    @inlineCallbacks
    def collect(self, config):
        log.debug('Starting GatewayService collect')
        ip_address = config.manageIp
        if not ip_address:
            log.error("%s: IP Address cannot be empty", device.id)
            returnValue(None)

        agent = Agent(reactor)

        ds0 = config.datasources[0]
        basicAuth = base64.encodestring('{}:{}'.format(ds0.zDataPowerUsername, ds0.zDataPowerPassword))
        authHeader = "Basic " + basicAuth.strip()
        headers = {"Authorization": [authHeader],
                   "User-Agent": ['Mozilla/3.0Gold'],
                   }

        ds0 = config.datasources[0]
        gateway_ip = ds0.params['gateway_ip']
        gateway_port = ds0.params['gateway_port']
        url = "https://{}:{}".format(gateway_ip, gateway_port)
        response = None
        severity = 3
        msg = None
        try:
            response = yield agent.request('GET', url, Headers(headers))
            severity = 0
            msg = 'Gateway Service {}:{} : Reachable'.format(gateway_ip, gateway_port)
            # response_body = yield readBody(response)
        except TimeoutError as e:
            severity = 3
            msg = 'Gateway Service {}:{} : Time out'.format(gateway_ip, gateway_port)
        except Exception as e:
            severity = 3
            msg = 'Gateway Service {}:{} : NOT reachable'.format(gateway_ip, gateway_port)

        # Check for response and response._state


        data = self.new_data()
        data['values'][ds0.component]['gw_status'] = severity
        data['events'].append({
            'device': config.id,
            'component': ds0.component,
            'severity': severity,
            'eventKey': 'GatewayService',
            'eventClassKey': 'GatewayService',
            'summary': msg,
            'message': msg,
            'eventClass': '/Status/DataPower/GatewayService',
        })

        returnValue(data)

