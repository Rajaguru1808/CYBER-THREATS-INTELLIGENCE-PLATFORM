"""
Threat correlation service.

Correlates a given IOC against the rest of the database (and optionally
MISP) to find related indicators - e.g. IOCs sharing the same value, the
same tags, or belonging to events already linked to that value. This is a
simplified, self-contained correlation engine appropriate for a mini-project;
it does not replace MISP's own correlation engine but complements it for
locally-added IOCs.
"""
from app.extensions import db
from app.models.ioc import IOCAttribute


def correlate_ioc(ioc: IOCAttribute):
    """
    Find IOCs correlated with the given IOC by:
      1. Exact value match (same indicator seen in multiple events)
      2. Shared tags (e.g. same malware family / campaign)

    Returns a list of related IOCAttribute objects (excluding itself).
    """
    related = set()

    # 1. Exact value matches (case-insensitive)
    value_matches = IOCAttribute.query.filter(
        IOCAttribute.id != ioc.id,
        db.func.lower(IOCAttribute.ioc_value) == ioc.ioc_value.lower()
    ).all()
    related.update(value_matches)

    # 2. Shared tags
    ioc_tags = set(ioc.tag_list())
    if ioc_tags:
        candidates = IOCAttribute.query.filter(
            IOCAttribute.id != ioc.id,
            IOCAttribute.tags.isnot(None)
        ).all()
        for candidate in candidates:
            if set(candidate.tag_list()) & ioc_tags:
                related.add(candidate)

    return list(related)


def update_correlation_flags(ioc: IOCAttribute):
    """Recompute and persist is_correlated / correlation_count for this IOC
    AND for every IOC correlated with it (mutual update). Without this, if
    IOC-B is added after IOC-A with the same value/tags, only IOC-B would
    show as correlated while IOC-A (added first) would incorrectly keep
    showing 'not correlated' until a full resync."""
    related = correlate_ioc(ioc)
    ioc.correlation_count = len(related)
    ioc.is_correlated = len(related) > 0

    for other in related:
        other_related = correlate_ioc(other)
        other.correlation_count = len(other_related)
        other.is_correlated = len(other_related) > 0

    db.session.commit()
    return related


def recompute_all_correlations():
    """Batch job: recompute correlation flags for every IOC in the database.
    Useful after a bulk import from external threat feeds."""
    updated = 0
    for ioc in IOCAttribute.query.all():
        related = correlate_ioc(ioc)
        new_count = len(related)
        new_flag = new_count > 0
        if ioc.correlation_count != new_count or ioc.is_correlated != new_flag:
            ioc.correlation_count = new_count
            ioc.is_correlated = new_flag
            updated += 1
    db.session.commit()
    return updated
