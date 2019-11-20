from prometheus_client.utils import INF, floatToGoString
from datetime import datetime
import argparse
import collections
import logging
import os
import prometheus_client
import prometheus_client.core
import prometheus_client.exposition
import prometheus_client.samples
import requests
import sys
import time


log = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(levelname)-5.5s %(message)s'


class Cloneable(object):

    def clone(self):
        return type(self)(
            self.name, self.documentation, labels=self._labelnames)


class Gauge(prometheus_client.core.GaugeMetricFamily, Cloneable):
    pass


class EventCollector:

    _cache_value = None
    _cache_updated_at = 0

    def configure(self, username, password, cache_ttl):
        self.username = username
        self.password = password
        self.cache_ttl = cache_ttl

    METRICS = {
        'http_requests_total': Gauge(
            'http_requests_total', 'HTTP requests',
            labels=['service', 'code']),
        'scrape_duration': Gauge(
            'audisto_scrape_duration_seconds',
            'Duration of Audisto API scrape'),
    }

    HTTP_STATUS = [
        200,
        301, 302, 303, 307,
        400, 401, 403, 404,
        500, 502, 503,
    ]

    def describe(self):
        return self.METRICS.values()

    def collect(self):
        start = time.time()

        if start - self._cache_updated_at <= self.cache_ttl:
            log.info('Returning cached result from %s',
                     datetime.fromtimestamp(self._cache_updated_at))
            return self._cache_value

        # Use a separate instance for each scrape request, to prevent
        # race conditions with simultaneous scrapes.
        metrics = {
            key: value.clone() for key, value in self.METRICS.items()}

        log.info('Retrieving data from Audisto API')

        # We assume crawls are ordered reverse chronologically
        seen = set()
        for crawl in self._request('/crawls/'):
            if crawl['status']['value'] != 'Finished':
                continue

            service = crawl['settings']['starting_point']
            if service in seen:  # We only look at the latest crawl
                continue
            seen.add(service)

            report = self._request('/crawls/%s/report' % crawl['id'])
            metrics['http_requests_total'].add_metric(
                [service], report['counters']['pages_crawled'])

            for status in self.HTTP_STATUS:
                report = self._request('/crawls/%s/report/httpstatus/%s' % (
                    crawl['id'], status), chunk=0, chunksize=0)
                metrics['http_requests_total'].add_metric(
                    [service, str(status)], report['total'])

        stop = time.time()
        metrics['scrape_duration'].add_metric((), stop - start)
        self._cache_value = metrics.values()
        self._cache_updated_at = stop
        return self._cache_value

    def _request(self, path, **params):
        url = 'https://api.audisto.com/1.0' + path
        r = requests.get(url, auth=(self.username, self.password),
                         params=params)
        r.raise_for_status()
        return r.json()


COLLECTOR = EventCollector()
# We don't want the `process_` and `python_` metrics, we're a collector,
# not an exporter.
REGISTRY = prometheus_client.core.CollectorRegistry()
REGISTRY.register(COLLECTOR)
APP = prometheus_client.make_wsgi_app(REGISTRY)


def main():
    parser = argparse.ArgumentParser(
        description='Export audisto crawl report as prometheus metrics')
    parser.add_argument('--username', help='Audisto API username')
    parser.add_argument('--password', help='Audisto API password')
    parser.add_argument('--host', default='', help='Listen host')
    parser.add_argument('--port', default=9307, type=int, help='Listen port')
    parser.add_argument('--ttl', default=600, type=int, help='Cache TTL')
    options = parser.parse_args()
    if not options.username:
        options.username = os.environ.get('AUDISTO_USERNAME')
    if not options.password:
        options.password = os.environ.get('AUDISTO_PASSWORD')

    if not (options.username and options.password):
        parser.print_help()
        raise SystemExit(1)
    logging.basicConfig(
        stream=sys.stdout, level=logging.INFO, format=LOG_FORMAT)

    COLLECTOR.configure(options.username, options.password, options.ttl)

    log.info('Listening on 0.0.0.0:%s', options.port)
    httpd = prometheus_client.exposition.make_server(
        options.host, options.port, APP,
        handler_class=prometheus_client.exposition._SilentHandler)
    httpd.serve_forever()
