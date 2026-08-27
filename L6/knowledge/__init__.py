"""L6 SOP knowledge base: real incident-response guidance used to ground
next-step recommendations.

See ``L6/knowledge/build_sop_kb.py`` for how ``sop_kb.json`` was built (and
how to extend it). Queried via ``L4/knowledge/retriever.py``'s ``_KBIndex``
class, instantiated directly against this directory's ``sop_kb.json`` rather
than through that module's ``retrieve()``/``reload_index()`` singleton —
those two share one process-wide global index, and repointing it at this KB
would silently break L4's own malware-detection retrieval for the rest of a
long-lived process (e.g. the FastAPI server, where L4 and L6 both run). See
``L6/recommend.py``'s comment at the call site for the full reasoning.
"""
