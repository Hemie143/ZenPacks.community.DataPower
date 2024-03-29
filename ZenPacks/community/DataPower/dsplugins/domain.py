import base64
import json
import logging
import re

# Zenoss imports
from ZenPacks.community.DataPower.lib.utils import SkipCertifContextFactory, StringProtocol
from ZenPacks.zenoss.PythonCollector.datasources.PythonDataSource import PythonDataSourcePlugin

# Twisted Imports
from twisted.internet import reactor
from twisted.internet.defer import returnValue, inlineCallbacks
from twisted.internet.error import TimeoutError
from twisted.web.client import Agent, readBody, RedirectAgent
from twisted.web.http_headers import Headers

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


    def onSuccess(self, result, config):
        log.debug('Success job - result is {}'.format(result))
        data = self.new_data()
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
        headers = {"Authorization": [authHeader],
                   "User-Agent": ["Mozilla/3.0Gold"],
                   }
        agent = Agent(reactor, contextFactory=SkipCertifContextFactory())

        for datasource in config.datasources:
            d_id = datasource.component
            url = "https://{}:{}/mgmt/status/{}/ObjectStatus".format(ip_address, datasource.zDataPowerPort, d_id)
            log.debug('url: {}'.format(url))
            try:
                response = yield agent.request('GET', url, Headers(headers))
                response_body = yield readBody(response)
                # log.debug('response_body: {}'.format(response_body))
                results = json.loads(response_body)
                # log.debug('results: {}'.format(results))
            except:
                log.error('{}: {}'.format(device.id, e))
        returnValue(results)

    def onSuccess(self, result, config):
        # log.debug('Success job - result is {}'.format(result))
        data = self.new_data()

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

    @classmethod
    def config_key(cls, datasource, context):
        log.info('In config_key {} {} {} {} {}'.format(context.device().id,
                                                       datasource.getCycleTime(context),
                                                       datasource.rrdTemplate().id,
                                                       datasource.id,
                                                       datasource.plugin_classname,
                                                       ))

        return (
            context.device().id,
            datasource.getCycleTime(context),
            datasource.rrdTemplate().id,
            datasource.id,
            datasource.plugin_classname,
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

        agent = RedirectAgent(Agent(reactor, contextFactory=SkipCertifContextFactory()))

        ds0 = config.datasources[0]
        basicAuth = base64.encodestring('{}:{}'.format(ds0.zDataPowerUsername, ds0.zDataPowerPassword))
        authHeader = "Basic " + basicAuth.strip()
        headers = {"Authorization": [authHeader],
                   "User-Agent": ['Mozilla/3.0Gold'],
                   }

        results = {}
        for ds in config.datasources:
            gateway_ip = ds.params['gateway_ip']
            gateway_port = ds.params['gateway_port']
            url = "https://{}:{}/webapi-init-check".format(gateway_ip, gateway_port)
            results[ds.component] = {}
            try:
                response = yield agent.request('GET', url, Headers(headers))
                log.debug('HTTP code : **{}**'.format(response.code))
                results[ds.component]['http_code'] = response.code
                # The body is empty in all cases
            except Exception as e:
                log.error('Gateway Services - collect: {} - {}'.format(e.args, e))
                results[ds.component]['http_code'] = -1
        returnValue(results)

    def onSuccess(self, results, config):
        log.debug('Success - result is {}'.format(results))

        data = self.new_data()
        for ds in config.datasources:
            component = ds.component
            if component in results:
                result = results[component]
                gateway_ip = ds.params['gateway_ip']
                gateway_port = ds.params['gateway_port']
                if result['http_code'] == -1:
                    severity = 4
                    msg = 'Gateway Service {}:{} : Down'.format(gateway_ip, gateway_port)
                elif result['http_code'] > 399:
                    severity = 4
                    msg = 'Gateway Service {}:{} : HTTP code={}'.format(gateway_ip, gateway_port, result['http_code'])
                else:
                    severity = 0
                    msg = 'Gateway Service {}:{} : Up'.format(gateway_ip, gateway_port)

                data['values'][component]['gw_status'] = severity
                data['events'].append({
                    'device': config.id,
                    'component': component,
                    'severity': severity,
                    'eventKey': 'GatewayService',
                    'eventClassKey': 'GatewayService',
                    'summary': msg,
                    'message': msg,
                    'eventClass': '/Status/DataPower/GatewayService',
                })
        return data
