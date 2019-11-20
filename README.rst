========================================
Prometheus Audisto error events exporter
========================================

This package exports `Audisto`_ web crawler report data as `Prometheus`_ metrics.

.. _`Audisto`: https://audisto.com
.. _`Prometheus`: https://prometheus.io


Usage
=====

Start HTTP service
------------------

Start the HTTP server like this::

    $ AUDISTO_USERNAME=APIUSER AUDISTO_PASSWORD=APISECRET audisto_exporter --host=127.0.0.1 --port=9307

Pass ``--ttl=SECONDS`` to cache API results for the given time or -1 to disable (default is 600).
Prometheus considers metrics stale after 300s, so that's the highest scrape_interval one should use.
However it's usually unnecessary to hit the API that often, since the information does not change that rapidly.


Configure Prometheus
--------------------

::

    scrape_configs:
      - job_name: 'audisto'
        scrape_interval: 300s
        static_configs:
          - targets: ['localhost:9307']

We export two metrics, firstly a gauge ``http_requests_total``
with labels ``{service="http://www.zeit.de/index",code="200"}``.
Status codes 601/602/603 are used for indexable/robots noindex/canonical.
Status codes 700/701/702/703 are used for duplicate title/description/body/similar urls.

Secondly we export a histogram ``response_time``,
with labels ``{service="http://www.zeit.de/index"}`` and buckets as determined by Audisto.

Additionally, a ``audisto_scrape_duration_seconds`` gauge is exported.
