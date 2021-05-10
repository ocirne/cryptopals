from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse


class TinyServer(BaseHTTPRequestHandler):
    """
    http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
    """

    # noinspection PyPep8Naming
    def do_GET(self):
        query = urlparse(self.path).query

        query_components = parse_qs(query)
        file_param = query_components["file"][0]
        signature_param = query_components["signature"][0]

        try:
            file_to_open = open(self.path[1:]).read()
            self.send_response(200)
        except Exception:
            file_to_open = "File not found"
            self.send_response(500)
        self.end_headers()


httpd = HTTPServer(('localhost', 9000), TinyServer)
httpd.serve_forever()


