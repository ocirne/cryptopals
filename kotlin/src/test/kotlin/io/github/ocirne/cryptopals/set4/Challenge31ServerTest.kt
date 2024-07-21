//import secrets
//import time
//from http.server import HTTPServer, BaseHTTPRequestHandler
//from urllib.parse import parse_qs, urlparse
//
//from cryptopals.digests import hmac_sha1
//
//SECRET_KEY = secrets.token_ByteArray(16)
//
//
//fun insecure_compare(s: str, r: str) {
//    if len(s) != len(r) {
//        return False
//    for c, d in zip(s, r) {
//        if c != d:
//            return False
//        // Challenge 31
//        // time.sleep(0.05)
//        // Challenge 32
//        time.sleep(0.001)
//    return True
//
//
//class TinyServer(BaseHTTPRequestHandler) {
//    """
//    e.g. http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
//    """
//
//    // noinspection PyPep8Naming
//    fun do_GET() {
//        query = urlparse(path).query
//
//        query_components = parse_qs(query)
//        file_param = query_components["file"][0]
//        signature_param = query_components["signature"][0]
//        // Use filename as file for simplicity
//        hmac = hmac_sha1(SECRET_KEY, file_param.encode())
//        print("hint:", hmac)
//        if insecure_compare(hmac, signature_param) {
//            send_response(200)
//        else:
//            send_response(500)
//        end_headers()
//
//
//if __name__ == "__main__":
//    httpd = HTTPServer(("localhost", 9000), TinyServer)
//    httpd.serve_forever()
