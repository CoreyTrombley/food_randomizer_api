from rest_framework_proxy.views import ProxyView

class YelpProxy(ProxyView):
    source = ''

    def get_source_path(self):
        extended = self.request.META.get('PATH_INFO')
        if self.source:
            return self.source % self.kwargs
        return extended

    def get_request_url(self, request):
        host = self.get_proxy_host()
        path = self.get_source_path()
        if path:
            return ''.join([host, path])
        return host

    def proxy(self, request, *args, **kwargs):
        url = self.get_request_url(request)
        headers = self.get_headers(request)
        return super(YelpProxy, self).proxy(request, *args, **kwargs)

    def get_headers(self, request):
        #import re
        #regex = re.compile('^HTTP_')
        #request_headers = dict((regex.sub('', header), value) for (header, value) in request.META.items() if header.startswith('HTTP_'))
        headers = self.get_default_headers(request)

        # Translate Accept HTTP field
        accept_maps = self.proxy_settings.ACCEPT_MAPS
        for old, new in accept_maps.items():
            headers['Accept'] = headers['Accept'].replace(old, new)

        username = self.proxy_settings.AUTH.get('user')
        password = self.proxy_settings.AUTH.get('password')
        if username and password:
            auth_token = '%s:%s' % (username, password)
            auth_token = base64.b64encode(auth_token.encode('utf-8')).decode()
            headers['Authorization'] = 'Basic %s' % auth_token
        else:
            auth_token = self.proxy_settings.AUTH.get('token')
            if auth_token:
                headers['Authorization'] = auth_token
        return headers
