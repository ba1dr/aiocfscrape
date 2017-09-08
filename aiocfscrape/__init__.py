#if tuple error - TypeError: 'tuple' object does not support item assignment, uncomment the 3 params
import re
import random
import asyncio
import logging

import aiohttp
import execjs

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0"
]

DEFAULT_USER_AGENT = random.choice(DEFAULT_USER_AGENTS)

BUG_REPORT = ("Cloudflare may have changed their technique, or there may be a bug in the script.\n\nPlease read " "https://github.com/Anorov/cloudflare-scrape#updates, then file a "
"bug report at https://github.com/Anorov/cloudflare-scrape/issues.")


class CloudflareScraper(aiohttp.ClientSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @asyncio.coroutine
    def _request(self, method, url, *args, allow_403=False, **kwargs):
        resp = yield from super()._request(method, url, *args, **kwargs)

        # Check if Cloudflare anti-bot is on
        if resp.status == 503 and resp.headers.get("Server") == "cloudflare-nginx":
            return (yield from self.solve_cf_challenge(resp, **kwargs))

        elif resp.status == 403 and resp.headers.get("Server") == "cloudflare-nginx" and not allow_403:
            resp.close()
            print("CloudFlare returned HTTP 403. Your IP could be banned on CF or reCAPTCHA appeared.")
            return
            #raise aiohttp.ClientError(message='CloudFlare returned HTTP 403. Your IP could be banned on CF '
            #                                          'or reCAPTCHA appeared. This error can be disabled with '
            #                                          'allow_403=True flag in request parameters e.g. '
            #                                          'session.get(url, allow_403=True).', headers=resp.headers)

        # Otherwise, no Cloudflare anti-bot detected
        return resp

    @asyncio.coroutine
    def solve_cf_challenge(self, resp, **kwargs):
        # https://pypi.python.org/pypi/cfscrape has been used as the solution.
        # The code below (with changes) has been inherited from mentioned lib.

        yield from asyncio.sleep(5, loop=self._loop)  # Cloudflare requires a delay before solving the challenge

        body = yield from resp.text()
        parsed_url = urlparse(str(resp.url))
        domain = parsed_url.netloc
        submit_url = '{}://{}/cdn-cgi/l/chk_jschl'.format(parsed_url.scheme, domain)

        params = kwargs.setdefault("params", {})
        headers = kwargs.setdefault("headers", {})
        headers["Referer"] = str(resp.url)

        data = kwargs.setdefault("data", {})
        timeout = kwargs.setdefault("timeout", {})
        proxy = kwargs.setdefault("proxy", {})

        try:
            #params["jschl_vc"] = re.search(r'name="jschl_vc" value="(\w+)"', body).group(1)
            #params["pass"] = re.search(r'name="pass" value="(.+?)"', body).group(1)
            params += (('jschl_vc', re.search(r'name="jschl_vc" value="(\w+)"', body).group(1)),)
            params += (('pass', re.search(r'name="pass" value="(.+?)"', body).group(1)),)

            # Extract the arithmetic operation
            #js = self.extract_js(body)

        except Exception:
            # Something is wrong with the page.
            # This may indicate Cloudflare has changed their anti-bot
            # technique. If you see this and are running the latest version,
            # please open a GitHub issue so I can update the code accordingly.
            logging.error("[!] Unable to parse Cloudflare anti-bots page. "
                          "Try upgrading cloudflare-scrape, or submit a bug report "
                          "if you are running the latest version. Please read "
                          "https://github.com/pavlodvornikov/aiocfscrape#updates "
                          "before submitting a bug report.")
            raise

        #params["jschl_answer"] = str(self.solve_challenge(body) + len(domain))
        params += (('jschl_answer', str(self.solve_challenge(body) + len(domain))),)
        kwargs = {}
        kwargs['data'] = data
        kwargs['timeout'] = timeout
        kwargs['headers'] = headers
        kwargs['proxy'] = proxy
        kwargs['params'] = params

        # Safely evaluate the Javascript expression
        #js = js.replace('return', '')
        #params["jschl_answer"] = str(int(js2py.eval_js(js)) + len(domain))
        resp.close()
        return (yield from self._request('GET', submit_url, **kwargs))

    def solve_challenge(self, body):
        try:
            js = re.search(r"setTimeout\(function\(\){\s+(var "
                        "s,t,o,p,b,r,e,a,k,i,n,g,f.+?\r?\n[\s\S]+?a\.value =.+?)\r?\n", body).group(1)
        except Exception:
            raise ValueError("Unable to identify Cloudflare IUAM Javascript on website. %s" % BUG_REPORT)

        js = re.sub(r"a\.value = (parseInt\(.+?\)).+", r"\1", js)
        js = re.sub(r"\s{3,}[a-z](?: = |\.).+", "", js)

        # Strip characters that could be used to exit the string context
        # These characters are not currently used in Cloudflare's arithmetic snippet
        js = re.sub(r"[\n\\']", "", js)

        if "parseInt" not in js:
            raise ValueError("Error parsing Cloudflare IUAM Javascript challenge. %s" % BUG_REPORT)

        # Use vm.runInNewContext to safely evaluate code
        # The sandboxed code cannot use the Node.js standard library
        js = "return require('vm').runInNewContext('%s', Object.create(null), {timeout: 5000});" % js

        try:
            node = execjs.get("Node")
        except Exception:
            raise EnvironmentError("Missing Node.js runtime. Node is required. Please read the cfscrape"
                " README's Dependencies section: https://github.com/Anorov/cloudflare-scrape#dependencies.")

        try:
            result = node.exec_(js)
        except Exception:
            logging.error("Error executing Cloudflare IUAM Javascript. %s" % BUG_REPORT)
            raise

        try:
            result = int(result)
        except Exception:
            raise ValueError("Cloudflare IUAM challenge returned unexpected value. %s" % BUG_REPORT)

        return result
