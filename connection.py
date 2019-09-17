# _*_ coding:utf-8 _*_
__author__ = "JuneZhu"
__date__ = "2019/9/17 12:00"
from urllib.parse import quote
import threading
import time
import http.client
from . import UserAgent

class HostConnectionPool(object):

    """
    A pool of connections for one remote (host,port).

    When connections are added to the pool, they are put into a
    pending queue.  The _mexe method returns connections to the pool
    before the response body has been read, so these connections aren't
    ready to send another request yet.  They stay in the pending queue
    until they are ready for another request, at which point they are
    returned to the pool of ready connections.

    The pool of ready connections is an ordered list of
    (connection,time) pairs, where the time is the time the connection
    was returned from _mexe.  After a certain period of time,
    connections are considered stale, and discarded rather than being
    reused.  This saves having to wait for the connection to time out
    if AWS has decided to close it on the other end because of
    inactivity.

    Thread Safety:

        This class is used only from ConnectionPool while it's mutex
        is held.
    """

    def __init__(self):
        self.queue = []

    def size(self):
        """
        Returns the number of connections in the pool for this host.
        Some of the connections may still be in use, and may not be
        ready to be returned by get().
        """
        return len(self.queue)

    def put(self, conn):
        """
        Adds a connection to the pool, along with the time it was
        added.
        """
        self.queue.append((conn, time.time()))

    def get(self):
        """
        Returns the next connection in this pool that is ready to be
        reused.  Returns None if there aren't any.
        """
        # Discard ready connections that are too old.
        self.clean()

        # Return the first connection that is ready, and remove it
        # from the queue.  Connections that aren't ready are returned
        # to the end of the queue with an updated time, on the
        # assumption that somebody is actively reading the response.
        for _ in range(len(self.queue)):
            (conn, _) = self.queue.pop(0)
            if self._conn_ready(conn):
                return conn
            else:
                self.put(conn)
        return None

    def _conn_ready(self, conn):
        """
        There is a nice state diagram at the top of http_client.py.  It
        indicates that once the response headers have been read (which
        _mexe does before adding the connection to the pool), a
        response is attached to the connection, and it stays there
        until it's done reading.  This isn't entirely true: even after
        the client is done reading, the response may be closed, but
        not removed from the connection yet.

        This is ugly, reading a private instance variable, but the
        state we care about isn't available in any public methods.
        """
        response = getattr(conn, '_HTTPConnection__response', None)
        return (response is None) or response.isclosed()

    def clean(self):
        """
        Get rid of stale connections.
        """
        # Note that we do not close the connection here -- somebody
        # may still be reading from it.
        while len(self.queue) > 0 and self._pair_stale(self.queue[0]):
            self.queue.pop(0)

    def _pair_stale(self, pair):
        """
        Returns true of the (connection,time) pair is too old to be
        used.
        """
        (_conn, return_time) = pair
        now = time.time()
        return return_time + ConnectionPool.STALE_DURATION < now

class ConnectionPool(object):

    """
    A connection pool that expires connections after a fixed period of
    time.  This saves time spent waiting for a connection that AWS has
    timed out on the other end.

    This class is thread-safe.
    """
    #
    # The amout of time between calls to clean.
    #
    CLEAN_INTERVAL = 5.0
    #
    # How long before a connection becomes "stale" and won't be reused
    # again.  The intention is that this time is less that the timeout
    # period that AWS uses, so we'll never try to reuse a connection
    # and find that AWS is timing it out.
    #
    # Experimentation in July 2011 shows that AWS starts timing things
    # out after three minutes.  The 60 seconds here is conservative so
    # we should never hit that 3-minute timout.
    #
    STALE_DURATION = 60.0
    def __init__(self):
        # Mapping from (host,port,is_secure) to HostConnectionPool.
        # If a pool becomes empty, it is removed.
        self.host_to_pool = {}
        # The last time the pool was cleaned.
        self.last_clean_time = 0.0
        self.mutex = threading.Lock()
        ConnectionPool.STALE_DURATION = ConnectionPool.STALE_DURATION

    def get_http_connection(self, host, port, is_secure):
        """
        Gets a connection from the pool for the named host.  Returns
        None if there is no connection that can be reused. It's the caller's
        responsibility to call close() on the connection when it's no longer
        needed.
        """
        self.clean()
        with self.mutex:
            key = (host, port, is_secure)
            if key not in self.host_to_pool:
                return None
            return self.host_to_pool[key].get()

    def clean(self):
        """
        Clean up the stale connections in all of the pools, and then
        get rid of empty pools.  Pools clean themselves every time a
        connection is fetched; this cleaning takes care of pools that
        aren't being used any more, so nothing is being gotten from
        them.
        """
        with self.mutex:
            now = time.time()
            if self.last_clean_time + self.CLEAN_INTERVAL < now:
                to_remove = []
                for (host, pool) in self.host_to_pool.items():
                    pool.clean()
                    if pool.size() == 0:
                        to_remove.append(host)
                for host in to_remove:
                    del self.host_to_pool[host]
                self.last_clean_time = now

    def put_http_connection(self, host, port, conn):
        """
        Adds a connection to the pool of connections that can be
        reused for the named host.
        """
        with self.mutex:
            key = (host, port)
            if key not in self.host_to_pool:
                self.host_to_pool[key] = HostConnectionPool()
            self.host_to_pool[key].put(conn)


class HTTPRequest(object):

    def __init__(self, method, protocol, host, port, path, auth_path,
                 params, headers, body):
        """Represents an HTTP request.

        :type method: string
        :param method: The HTTP method name, 'GET', 'POST', 'PUT' etc.

        :type protocol: string
        :param protocol: The http protocol used, 'http' or 'https'.

        :type host: string
        :param host: Host to which the request is addressed. eg. abc.com

        :type port: int
        :param port: port on which the request is being sent. Zero means unset,
            in which case default port will be chosen.

        :type path: string
        :param path: URL path that is being accessed.

        :type auth_path: string
        :param path: The part of the URL path used when creating the
            authentication string.

        :type params: dict
        :param params: HTTP url query parameters, with key as name of
            the param, and value as value of param.

        :type headers: dict
        :param headers: HTTP headers, with key as name of the header and value
            as value of header.

        :type body: string
        :param body: Body of the HTTP request. If not present, will be None or
            empty string ('').
        """
        self.method = method
        self.protocol = protocol
        self.host = host
        self.port = port
        self.path = path
        if auth_path is None:
            auth_path = path
        self.auth_path = auth_path
        self.params = params
        # chunked Transfer-Encoding should act only on PUT request.
        if headers and 'Transfer-Encoding' in headers and \
                headers['Transfer-Encoding'] == 'chunked' and \
                self.method != 'PUT':
            self.headers = headers.copy()
            del self.headers['Transfer-Encoding']
        else:
            self.headers = headers
        self.body = body

    def __str__(self):
        return 'method:(%s) protocol:(%s) host(%s) port(%s) path(%s) ''params(%s) headers(%s) body(%s)' % \
               (self.method, self.protocol, self.host, self.port, self.path, self.params, self.headers, self.body)

    def authorize(self, connection, **kwargs):
        if not getattr(self, '_headers_quoted', False):
            for key in self.headers:
                val = self.headers[key]
                if isinstance(val, str):
                    safe = '!"#$%&\'()*+,/:;<=>?@[\\]^`{|}~ '
                    self.headers[key] = quote(val.encode('utf-8'), safe)
            setattr(self, '_headers_quoted', True)

        self.headers['User-Agent'] = UserAgent

        connection._auth_handler.add_auth(self, **kwargs)

        # I'm not sure if this is still needed, now that add_auth is
        # setting the content-length for POST requests.
        if 'Content-Length' not in self.headers:
            if 'Transfer-Encoding' not in self.headers or \
                    self.headers['Transfer-Encoding'] != 'chunked':
                self.headers['Content-Length'] = str(len(self.body))


class HTTPResponse(http.client.HTTPResponse):

    def __init__(self, *args, **kwargs):
        http.client.HTTPResponse.__init__(self, *args, **kwargs)
        self._cached_response = ''

    def read(self, amt=None):
        """Read the response.

        This method does not have the same behavior as
        http_client.HTTPResponse.read.  Instead, if this method is called with
        no ``amt`` arg, then the response body will be cached.  Subsequent
        calls to ``read()`` with no args **will return the cached response**.

        """
        if amt is None:
            # The reason for doing this is that many places in boto call
            # response.read() and except to get the response body that they
            # can then process.  To make sure this always works as they expect
            # we're caching the response so that multiple calls to read()
            # will return the full body.  Note that this behavior only
            # happens if the amt arg is not specified.
            if not self._cached_response:
                self._cached_response = http.client.HTTPResponse.read(self)
            return self._cached_response
        else:
            return http.client.HTTPResponse.read(self, amt)


