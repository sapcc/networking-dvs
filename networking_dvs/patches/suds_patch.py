import suds.version

if suds.version.__version__ < '0.7':
    import suds.mx.appender
    import suds.transport.http

    def _suds_mx_object_appender_append_workaround(self, parent, content):
        object = content.value
        child = self.node(content)
        parent.append(child)
        for item in object:
            cont = suds.mx.Content(tag=item[0], value=item[1])
            suds.mx.appender.Appender.append(self, child, cont)

    import gzip, cStringIO, urllib2, sys, httplib
    from suds.transport import *
    from logging import getLogger

    log = getLogger(__name__)

    def _http_transport_send(self, request):
        result = None
        url = self.__get_request_url(request)
        msg = request.message
        headers = request.headers
        try:
            print(len(msg))
            u2request = urllib2.Request(url, msg, headers)
            self.addcookies(u2request)
            self.proxy = self.options.proxy
            request.headers.update(u2request.headers)
            log.debug('sending:\n%s', request)
            fp = self.u2open(u2request)
            self.getcookies(fp, u2request)
            if sys.version_info < (3, 0):
                headers = fp.headers.dict
            else:
                headers = fp.headers
            result = Reply(httplib.OK, headers, fp.read())
            log.debug('received:\n%s', result)
        except urllib2.HTTPError, e:
            if e.code in (httplib.ACCEPTED, httplib.NO_CONTENT):
                result = None
            else:
                raise TransportError(e.msg, e.code, e.fp)
        return result


    suds.transport.http.HttpTransport.send = _http_transport_send

    def gzip_send(self, request, retry=1):
        try:
            if (request.headers['content-encoding'] == 'gzip'):
                ss = cStringIO.StringIO()
                gzip.GzipFile(fileobj=ss, mode='w').write(request.message)
                body = ss.getvalue()
            else:
                body = request.message
        except KeyError:
            pass

        h = httplib2.Http(".cache")
        log.debug('sending:\n%s', request)
        resp, content = h.request(request.url, method='POST', headers=request.headers, body=body)
        log.debug('received:\n%s', content)

        code = int(resp['status'])
        if code in (200, ):
            return Reply(code, request.headers, content)
        elif code in (202, 204):
            return Reply(code, request.headers, None)
        elif code in (500,) and retry:
            log.warning('Retry: {0}\n{1}'.format(retry, resp))
            time.sleep(0.5)
            return self.adpure_send(request, retry-1)
        else:
            raise TransportError(content, code, cStringIO.StringIO(content))


def patch():
    pass
