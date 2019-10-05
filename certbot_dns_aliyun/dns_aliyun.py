"""DNS Authenticator for Aliyun."""
import logging
import json

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkalidns.request.v20150109.AddDomainRecordRequest import AddDomainRecordRequest
from aliyunsdkalidns.request.v20150109.DeleteDomainRecordRequest import DeleteDomainRecordRequest
from aliyunsdkalidns.request.v20150109.DescribeSubDomainRecordsRequest \
     import DescribeSubDomainRecordsRequest

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://account.aliyun.com/login/login.htm'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Aliyun

    This Authenticator uses the Aliyun API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using Aliyun for '
                   'DNS).')
    ttl = 600

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='Aliyun credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Aliyun API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Aliyun credentials INI file',
            {
                'api-key': 'API key for Aliyun account, obtained from {0}'.format(ACCOUNT_URL),
                'secret-key': 'Secret key for Aliyun account, obtained from {0}'
                              .format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_alidns_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_alidns_client().del_txt_record(domain, validation_name, validation)

    def _get_alidns_client(self):
        return _AlidnsClient(self.credentials.conf('api-key'), self.credentials.conf('secret-key'))


class _AlidnsClient(object):
    """
    Encapsulates all communication with the Aliyun API.
    """

    def __init__(self, api_key, secret_key):
        self.ac = AcsClient(api_key, secret_key, 'cn-hangzhou')

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the Alidns zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Aliyun API
        """

        if self._find_txt_record_id(domain, record_name, record_content):
            logger.debug('TXT record exited; no add needed.')
            return

        request = AddDomainRecordRequest()

        domain_root = '.'.join(domain.split('.')[-2:])
        doamin_rr = record_name[:record_name.find(domain_root)-1]
        request.set_accept_format('json')
        request.set_DomainName(domain_root)
        request.set_Type("TXT")
        request.set_RR(doamin_rr)
        request.set_Value(record_content)
        request.set_TTL(record_ttl)

        try:
            self.ac.do_action_with_exception(request)
        except ClientException as e:
            logger.error('Encountered ClientException adding TXT record: %d %s', e, e)
            raise errors.PluginError('Error communicating with the aliyun API: {0}'.format(e))

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the Aliyun zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        record_id = self._find_txt_record_id(domain, record_name, record_content)
        if record_id is None:
            logger.debug('TXT record not found; no cleanup needed.')
            return

        request = DeleteDomainRecordRequest()
        request.set_accept_format('json')
        request.set_RecordId(record_id)

        try:
            self.ac.do_action_with_exception(request)
            logger.debug('Successfully deleted TXT record.')
        except ClientException as e:
            logger.warning('Encountered Aliyun ClientException deleting TXT record: %s', e)

    def _find_txt_record_id(self, domain, record_name, record_content):
        """
        Find the record_id for a TXT record with the given name and content.

        :param str domain: The domain to use to look up the Aliyun zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :returns: The record_id, if found.
        :rtype: str
        """

        request = DescribeSubDomainRecordsRequest()
        request.set_accept_format('json')

        request.set_SubDomain(record_name)

        try:
            response = self.ac.do_action_with_exception(request)
        except ClientException as e:
            logger.warning('Encountered Aliyun ClientException described domain records: %s', e)
            return None

        for record in json.loads(response)['DomainRecords']['Record']:
            if record["RR"] + '.' + record["DomainName"] == record_name and record["Type"] == "TXT" \
               and record["Value"] == record_content:
                return record["RecordId"]

        return None
