"""Phase 1 collectors: everything that needs no browser.

Order matters. :class:`HttpCollector` runs first and stashes the fetched
document on the context; :class:`FingerprintCollector` reads it rather
than issuing a second request.
"""

from .base import (
    Collector,
    CollectorConfig,
    CollectorError,
    FetchedDocument,
    PageContext,
)
from .crux import CruxCollector, TokenBucket
from .crux_history import CruxHistoryCollector
from .lighthouse import (
    LighthouseCollector,
    LighthouseConfig,
    LighthouseError,
    LighthouseRunner,
)
from .fingerprint import FingerprintCollector
from .http_probe import HttpCollector, normalize_url
from .components import ComponentCollector
from .exposure import ExposureCollector
from .subresources import SubresourceCollector
from .tls_probe import TlsCollector

__all__ = [
    "Collector", "CollectorConfig", "CollectorError", "FetchedDocument",
    "PageContext", "HttpCollector", "TlsCollector", "FingerprintCollector",
    "CruxCollector", "TokenBucket", "normalize_url", "default_pipeline",
    "Pipeline", "LighthouseCollector", "LighthouseConfig", "LighthouseError",
    "LighthouseRunner", "SubresourceCollector", "ComponentCollector",
    "ExposureCollector", "CruxHistoryCollector",
]

#: A pipeline is a list of stages; collectors within a stage run concurrently,
#: stages run in order. This makes the "fingerprint needs the fetched document"
#: dependency explicit in data rather than implicit in list ordering.
Pipeline = list[list[Collector]]


def default_pipeline(crux_bucket: TokenBucket | None = None,
                     lighthouse_runner: "LighthouseRunner | None" = None,
                     *, vuln_db=None,
                     exposure: "ExposureCollector | None" = None,
                     crux_history: bool = True) -> Pipeline:
    """The collection pipeline.

    Stages 1 and 2 are Phase 1: no browser, seconds per site. Stage 3 is
    Lighthouse and is added only when a runner is supplied.

    Stage 3 is its own stage for a reason beyond ordering: the runner holds
    a private semaphore, so site-level concurrency can stay wide (the
    network collectors want that) while only `LighthouseConfig.concurrency`
    sites are inside Chrome at once. Sharing one cap between them is the
    contention mistake the roadmap warns about.
    """
    pipeline: Pipeline = [
        # Stage 1 fetches the document and stashes it on the context.
        [HttpCollector()],
        # Stage 2 is independent given that document.
        [FingerprintCollector(), TlsCollector(), CruxCollector(crux_bucket),
         SubresourceCollector()],
    ]
    if crux_history:
        # Same bucket as the point-in-time collector: the 150/min quota is
        # shared across both CrUX endpoints, so two independent limiters
        # would let a wide batch burst straight through it.
        pipeline[1].append(CruxHistoryCollector(crux_bucket))
    if exposure is not None and exposure.enabled:
        # Origin-scoped, so `core` runs it once per site however many pages
        # are audited. Probing fifteen paths twenty times would be twenty
        # times the noise in the client's access log for the same answer.
        pipeline[1].append(exposure)
    if lighthouse_runner is not None:
        pipeline.append([LighthouseCollector(lighthouse_runner)])
    # Last: component detection consumes the browser's view of the running
    # libraries, which does not exist until Lighthouse has run. It declares
    # `runs_last`, so `core.split_pipeline` puts it in its own final pass
    # rather than beside the collectors it depends on.
    pipeline.append([ComponentCollector(vuln_db)])
    return pipeline
