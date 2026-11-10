import contextlib
import io
import json
import re
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from mcp_sentinel.cli import main
from mcp_sentinel.discovery import DiscoveryError
from mcp_sentinel.engine import Inspector
from mcp_sentinel.web import create_server
from test_engine import ROOT, BENIGN, SUSPICIOUS


class InterfaceTests(unittest.TestCase):
    def test_cli_full_graph(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            code=main(['scan',str(ROOT/'examples/suspicious.json'),'--fail-on','high'])
        self.assertEqual(code,1)
        report=json.loads(output.getvalue())
        self.assertEqual(report['trace'][-1],'generate_report')
        self.assertEqual(len(report['findings']),5)

    def test_web_scan_review_and_request_protection(self):
        server=create_server(Inspector(),port=0)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        url=f'http://127.0.0.1:{server.server_port}'
        try:
            with urlopen(url) as response:
                page=response.read().decode()
                self.assertIn("script-src 'self'",response.headers['Content-Security-Policy'])
            token=re.search('name="sentinel-token" content="([^"]+)"',page)[1]
            def post(path, body, key=token):
                request=Request(url+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json','X-Sentinel-Token':key})
                with urlopen(request) as response: return json.load(response)
            with self.assertRaises(HTTPError) as denied:
                post('/api/scan',{'payload':BENIGN},key='wrong')
            self.assertEqual(denied.exception.code,403)
            denied.exception.close()
            report=post('/api/scan',{'payload':SUSPICIOUS,'review':True})
            self.assertEqual(report['status'],'awaiting_review')
            reviewed=post('/api/review',{'scan_id':report['scan_id'],'decisions':[
                {'finding_id':f['id'],'disposition':'needs_investigation','rationale':'Check implementation'} for f in report['findings']]})
            self.assertEqual(reviewed['status'],'complete')
            self.assertEqual(reviewed['trace'][-1],'generate_report')
            self.assertEqual(len(reviewed['decisions']),5)
            with patch('mcp_sentinel.web.discover', return_value=BENIGN) as discover:
                live = post('/api/scan', {'url': 'https://weather.example/mcp'})
                discover.assert_called_once_with('https://weather.example/mcp')
                self.assertEqual(live['snapshot_hash'], Inspector().inspect(BENIGN).snapshot_hash)
                for body in ({'url': 'https://weather.example/mcp', 'payload': BENIGN}, {},
                             {'url': 'https://weather.example/mcp', 'ai': True}):
                    discover.reset_mock()
                    with self.assertRaises(HTTPError) as invalid_source:
                        post('/api/scan', body)
                    self.assertEqual(invalid_source.exception.code, 400)
                    invalid_source.exception.close()
                    discover.assert_not_called()
            with patch('mcp_sentinel.web.discover', side_effect=DiscoveryError('MCP discovery timed out')):
                with self.assertRaises(HTTPError) as failed_discovery:
                    post('/api/scan', {'url': 'https://weather.example/mcp'})
                self.assertEqual(json.load(failed_discovery.exception)['error'], 'MCP discovery timed out')
                failed_discovery.exception.close()
            with self.assertRaises(HTTPError) as unavailable:
                post('/api/scan',{'payload':BENIGN,'ai':True})
            unavailable.exception.close()
            with self.assertRaises(HTTPError) as invalid_host:
                urlopen(Request(url,headers={'Host':'attacker.invalid'}))
            invalid_host.exception.close()
        finally:
            server.shutdown();server.server_close();thread.join()


if __name__=='__main__': unittest.main()
