# _*_ coding:utf-8 _*_
__author__ = "JuneZhu"
__date__ = "2019/9/16 17:31"
import http.client
import random
import time
from datetime import datetime
from urllib.parse import urlparse
import socket
import hashlib
from base64 import encodebytes
import xml.sax

from connection import HTTPRequest,ConnectionPool, HTTPResponse
import utils
from exception import PleaseRetryException
from handler import XmlHandler

api_version_path = {
    'Feeds':             ('2009-01-01', 'Merchant', '/','MWSAuthToken'),
    'Reports':           ('2009-01-01', 'Merchant', '/','MWSAuthToken'),
    'Orders':            ('2013-09-01', 'SellerId', '/Orders/2013-09-01','MWSAuthToken'),
    'Products':          ('2011-10-01', 'SellerId', '/Products/2011-10-01','MWSAuthToken'),
    'Sellers':           ('2011-07-01', 'SellerId', '/Sellers/2011-07-01','MWSAuthToken'),
    'Inbound':           ('2010-10-01', 'SellerId',
                          '/FulfillmentInboundShipment/2010-10-01','MWSAuthToken'),
    'Outbound':          ('2010-10-01', 'SellerId',
                          '/FulfillmentOutboundShipment/2010-10-01','MWSAuthToken'),
    'Inventory':         ('2010-10-01', 'SellerId',
                          '/FulfillmentInventory/2010-10-01','MWSAuthToken'),
    'Recommendations':   ('2013-04-01', 'SellerId',
                          '/Recommendations/2013-04-01','MWSAuthToken'),
    'CustomerInfo':      ('2014-03-01', 'SellerId',
                          '/CustomerInformation/2014-03-01','MWSAuthToken'),
    'CartInfo':          ('2014-03-01', 'SellerId',
                          '/CartInformation/2014-03-01','MWSAuthToken'),
    'Subscriptions':     ('2013-07-01', 'SellerId',
                          '/Subscriptions/2013-07-01','MWSAuthToken'),
    'OffAmazonPayments': ('2013-01-01', 'SellerId',
                          '/OffAmazonPayments/2013-01-01','MWSAuthToken'),
}
content_md5 = lambda c: encodebytes(hashlib.md5(c).digest()).strip()
decorated_attrs = ('action', 'response', 'section',
                   'quota', 'restore', 'version')
api_call_map = {}

def api_action(section, quota, restore, *api):

    def decorator(func, quota=int(quota), restore=float(restore)):
        version, accesskey, path, MWSAuthToken = api_version_path[section]
        action = ''.join(api or map(str.capitalize, func.__name__.split('_')))

        def wrapper(self, *args, **kw):
            kw.setdefault(accesskey, getattr(self, accesskey, None))
            kw.setdefault(MWSAuthToken, getattr(self, MWSAuthToken, None))
            if kw[accesskey] is None:
                message = "{0} requires {1} argument. Set the " \
                          "MWSConnection.{2} attribute?" \
                          "".format(action, accesskey, accesskey)
                raise KeyError(message)
            kw['Action'] = action
            kw['Version'] = version
            response = self._response_factory(action, connection=self)
            request = dict(path=path, quota=quota, restore=restore)
            return func(self, request, response, *args, **kw)
        for attr in decorated_attrs:
            setattr(wrapper, attr, locals().get(attr))
        wrapper.__doc__ = "MWS {0}/{1} API call; quota={2} restore={3:.2f}\n" \
                          "{4}".format(action, version, quota, restore,
                                       func.__doc__)
        api_call_map[action] = func.__name__
        return wrapper
    return decorator

class MWSBasic(object):
    APIVersion = ''

    def __init__(self, port=None, proxy=None, proxy_port=None,
                 proxy_user=None, proxy_pass=None, host=None, path='/',):
        """
        :type port: int
        :param port: The port to use to connect

        :param str proxy: Address/hostname for a proxy server

        :type proxy_port: int
        :param proxy_port: The port to use when connecting over a proxy

        :type proxy_user: str
        :param proxy_user: The username to connect with on the proxy

        :type proxy_pass: str
        :param proxy_pass: The password to use when connection over a proxy.

        :type host: str
        :param host: The host to make the connection to

        :param path:
        """
        self.port = port
        # self.handle_proxy(proxy, proxy_port, proxy_user, proxy_pass)
        self.protocol = 'http'
        self.host = host
        self.path = path
        self.host_header = None
        self.use_proxy = (proxy is not None)
        self.num_retries = 6
        self._pool = ConnectionPool()
        self._connection = (self.host, self.port)
        # Timeout used to tell http_client how long to wait for socket timeouts.
        # Default is to leave timeout unchanged, which will in turn result in
        # the socket's default global timeout being used. To specify a
        # timeout, set http_socket_timeout in Boto config. Regardless,
        # timeouts will only be applied if Python is 2.6 or greater.
        self.http_connection_kwargs = {}
        self.http_connection_kwargs['timeout'] = 70
        self.http_exceptions = (http.client.HTTPException, socket.error,
                                socket.gaierror, http.client.BadStatusLine)
        self.request_hook = None
        # define subclasses of the above that are not retryable.
        self.http_unretryable_exceptions = []

    def get_path(self, path='/'):
        # The default behavior is to suppress consecutive slashes for reasons
        # discussed at
        # https://groups.google.com/forum/#!topic/boto-dev/-ft0XPUy0y8
        # You can override that behavior with the suppress_consec_slashes param.z
        pos = path.find('?')
        if pos >= 0:
            params = path[pos:]
            path = path[:pos]
        else:
            params = None
        if path[-1] == '/':
            need_trailing = True
        else:
            need_trailing = False
        path_elements = self.path.split('/')
        path_elements.extend(path.split('/'))
        path_elements = [p for p in path_elements if p]
        path = '/' + '/'.join(path_elements)
        if path[-1] != '/' and need_trailing:
            path += '/'
        if params:
            path = path + params
        return path

    def build_base_http_request(self, method, path, auth_path,
                                params=None, headers=None, data='', host=None):
        path = self.get_path(path)
        if auth_path is not None:
            auth_path = self.get_path(auth_path)
        if params is None:
            params = {}
        else:
            params = params.copy()
        if headers is None:
            headers = {}
        else:
            headers = headers.copy()
        headers['host'] = self.host_header
        host = host or self.host
        return HTTPRequest(method, self.protocol, host, self.port,
                           path, auth_path, params, headers, data)

    def get_http_connection(self, host, port):
        conn = self._pool.get_http_connection(host, port)
        if conn is not None:
            return conn
        else:
            return self.new_http_connection(host, port)

    def new_http_connection(self, host, port):
        # Make sure the host is really just the host, not including
        # the port number
        host = utils.parse_host(host)

        http_connection_kwargs = self.http_connection_kwargs.copy()

        # Connection factories below expect a port keyword argument
        http_connection_kwargs['port'] = port

        # # Override host with proxy settings if needed
        # if self.use_proxy and not is_secure and \
        #         not self.skip_proxy(host):
        #     host = self.proxy
        #     http_connection_kwargs['port'] = int(self.proxy_port)

        connection = http.client.HTTPConnection(host, **http_connection_kwargs)
        # self.connection must be maintained for backwards-compatibility
        # however, it must be dynamically pulled from the connection pool
        # set a private variable which will enable that
        if host.split(':')[0] == self.host:
            self._connection = (host, port)
        # Set the response class of the http connection to use our custom
        # class.
        connection.response_class = HTTPResponse
        return connection

    def set_host_header(self, request):
        try:
            request.headers['Host'] = \
                self._auth_handler.host_header(self.host, request)
        except AttributeError:
            request.headers['Host'] = self.host.split(':', 1)[0]

    def put_http_connection(self, host, port, connection):
        self._pool.put_http_connection(host, port,connection)

    def _mexe(self, request, sender=None, override_num_retries=None,
              retry_handler=None):
        """
        mexe - Multi-execute inside a loop, retrying multiple times to handle
               transient Internet errors by simply trying again.
               Also handles redirects.
        """
        response = None
        body = None
        ex = None
        if override_num_retries is None:
            num_retries = self.num_retries
        else:
            num_retries = override_num_retries
        i = 0
        connection = self.get_http_connection(request.host, request.port)
        # Convert body to bytes if needed
        if not isinstance(request.body, bytes) and hasattr(request.body,
                                                           'encode'):
            request.body = request.body.encode('utf-8')

        while i <= num_retries:
            # Use binary exponential backoff to desynchronize client requests.
            next_sleep = min(random.random() * (2 ** i),float(60))
            try:
                # we now re-sign each request before it is retried
                request.authorize(connection=self)
                if not request.headers.get('Host'):
                    self.set_host_header(request)
                request.start_time = datetime.now()
                if callable(sender):
                    response = sender(connection, request.method, request.path,
                                      request.body, request.headers)
                else:
                    connection.request(request.method, request.path,
                                       request.body, request.headers)
                    response = connection.getresponse()
                location = response.getheader('location')
                # -- gross hack --
                # http_client gets confused with chunked responses to HEAD requests
                # so I have to fake it out
                if request.method == 'HEAD' and getattr(response,
                                                        'chunked', False):
                    response.chunked = 0
                if callable(retry_handler):
                    status = retry_handler(response, i, next_sleep)
                    if status:
                        msg, i, next_sleep = status
                        time.sleep(next_sleep)
                        continue
                if response.status in [500, 502, 503, 504]:
                    msg = 'Received %d response.  ' % response.status
                    msg += 'Retrying in %3.1f seconds' % next_sleep
                    body = response.read()
                    if isinstance(body, bytes):
                        body = body.decode('utf-8')
                elif response.status < 300 or response.status >= 400 or \
                        not location:
                    # don't return connection to the pool if response contains
                    # Connection:close header, because the connection has been
                    # closed and default reconnect behavior may do something
                    # different than new_http_connection. Also, it's probably
                    # less efficient to try to reuse a closed connection.
                    conn_header_value = response.getheader('connection')
                    if conn_header_value == 'close':
                        connection.close()
                    else:
                        self.put_http_connection(request.host, request.port, connection)
                    return response
                else:
                    scheme, request.host, request.path, \
                    params, query, fragment = urlparse(location)
                    if query:
                        request.path += '?' + query
                    # urlparse can return both host and port in netloc, so if
                    # that's the case we need to split them up properly

                    connection = self.get_http_connection(request.host,
                                                          request.port)
                    response = None
                    continue
            except PleaseRetryException as e:
                connection = self.new_http_connection(request.host, request.port)
                response = e.response
                ex = e
            except self.http_exceptions as e:
                for unretryable in self.http_unretryable_exceptions:
                        raise
                connection = self.new_http_connection(request.host, request.por)
                ex = e
            time.sleep(next_sleep)
            i += 1
        # If we made it here, it's because we have exhausted our retries
        # and stil haven't succeeded.  So, if we have a response object,
        # use it to raise an exception.
        # Otherwise, raise the exception that must have already happened.
        if self.request_hook is not None:
            self.request_hook.handle_request_data(request, response, error=True)
        if response:
            raise (response.status, response.reason, body)
        elif ex:
            raise ex
        else:
            msg = 'Please report this exception!'
            raise (msg)

class MWSConnection(MWSBasic):

    """
    required parama:
    AWSAccessKeyId Type: xs:string
    MWSAuthToken Type: xs:string
    SellerId or Merchant Type: xs:string
    Action Type: xs:string
    Signature Type: xs:string
    SignatureMethod	HmacSHA256 (recommended) HmacSHA1 Type: xs:string
    SignatureVersion Type: xs:string
    Timestamp Type: xs:dateTime
    Version Type: xs:string
    optional parama:
    DateRangeEnd=2014-04-30T00%3A06%3A07.000Z
    DateRangeStart=2014-04-01T00%3A06%3A07.000Z
    DateRangeType=AssociatedDate
    MarketplaceId
    """
    def __init__(self, *args, **kw):
        kw.setdefault('host', 'mws.amazonservices.com')
        self.Merchant = kw.pop('Merchant', None) or kw.get('SellerId')
        self.SellerId = kw.pop('SellerId', None) or self.Merchant
        self.MWSAuthToken = kw.pop('MWSAuthToken')
        self.aws_access_key_id = kw.pop('aws_access_key_id')
        kw = self._setup_factories(kw.pop('factory_scopes', []), **kw)
        super(MWSConnection, self).__init__(*args, **kw)

    def _setup_factories(self, extrascopes, **kw):
        for factory, (scope, Default) in {
            'response_factory':
                (response, self.ResponseFactory),
            'response_error_factory':
                (exception, self.ResponseErrorFactory),
        }.items():
            if factory in kw:
                setattr(self, '_' + factory, kw.pop(factory))
            else:
                scopes = extrascopes + [scope]
                setattr(self, '_' + factory, Default(scopes=scopes))
        return kw

    def _post_request(self, request, params, parser, body='', headers=None):
        headers = headers or {}
        path = request['path']
        request = self.build_base_http_request('POST', path, None, data=body,
                                               params=params, headers=headers,
                                               host=self.host)
        response = self._mexe(request, override_num_retries=None)
        # TODO: exception factory
        digest = response.getheader('Content-MD5')
        if digest is not None:
            assert content_md5(body) == digest
        contenttype = response.getheader('Content-Type')
        return self._parse_response(parser, contenttype, body)

    def _parse_response(self, parser, contenttype, body):
        if not contenttype.startswith('text/xml'):
            return body
        handler = XmlHandler(parser, self)
        xml.sax.parseString(body, handler)
        return parser


    def show_example(self):
        request_exam = """POST /Feeds/2009-01-01 HTTP/1.1
            Content-Type: x-www-form-urlencoded
            Host: mws.amazonservices.com
            User-Agent: <Your User Agent Header>
            AWSAccessKeyId=0PExampleR2
            &Action=CancelFeedSubmissions
            &FeedSubmissionIdList.Id.1=1058369303
            &FeedTypeList.Type.1=_POST_PRODUCT_DATA_
            &FeedTypeList.Type.2=_POST_PRODUCT_PRICING_DATA_
            &MWSAuthToken=amzn.mws.4ea38b7b-f563-7709-4bae-87aeaEXAMPLE
            &Marketplace=ATExampleER
            &SellerId=A1ExampleE6
            &SignatureMethod=HmacSHA256
            &SignatureVersion=2
            &Timestamp=2009-02-04T17%3A34%3A14.203Z
            &Version=2009-01-01
            &Signature=0RExample0%3D"""
        response_exam = """
        <?xml version="1.0"?>
        <RequestReportResponse xmlns="http://mws.amazonservices.com/doc/2009-01-01/">
            <RequestReportResult>
                <ReportRequestInfo>
                    <ReportRequestId>2291326454</ReportRequestId>
                    <ReportType>_GET_MERCHANT_LISTINGS_DATA_</ReportType>
                    <StartDate>2009-01-21T02:10:39+00:00</StartDate>
                    <EndDate>2009-02-13T02:10:39+00:00</EndDate>
                    <Scheduled>false</Scheduled>
                    <SubmittedDate>2009-02-20T02:10:39+00:00</SubmittedDate>
                    <ReportProcessingStatus>_SUBMITTED_</ReportProcessingStatus>
                </ReportRequestInfo>
            </RequestReportResult>
            <ResponseMetadata>
                <RequestId>88faca76-b600-46d2-b53c-0c8c4533e43a</RequestId>
            </ResponseMetadata>
        </RequestReportResponse>
        """
        error_exam = """
        <ErrorResponse xmlns="http://mws.amazonservices.com/doc/2009-01-01/">
            <Error>
                <Type>Sender</Type>
                <Code>InvalidClientTokenId</Code>
                <Message> The AWS Access Key Id you provided does not exist in our records. </Message>
                <Detail>com.amazonservices.mws.model.Error$Detail@17b6643</Detail>
            </Error>
            <RequestID>b7afc6c3-6f75-4707-bcf4-0475ad23162c</RequestID>
        </ErrorResponse>"""

        return  f'request example: {request_exam}\n response example: {response_exam} \n error example: {error_exam}'

    @api_action('Orders', 2, 300, 'GetServiceStatus')
    def get_orders_service_status(self, request, response, **kw):
        """Returns the operational status of the Orders API section.
        """
        return self._post_request(request, kw, response)