# BugFlow Elite — Phase 2 Attack Surface Intelligence

## Objective

Build a persistent, provenance-bearing model of the observed attack surface and make change detection produce graph state rather than isolated alerts.

## Graph model

The graph stores normalized nodes such as domains, subdomains, URLs, JavaScript files, endpoints, parameters, IPs, cloud assets, repositories, and findings. Edges describe observed relationships and retain source/evidence metadata.

Node identity is tenant-scoped and based on `(node_type, canonical_key)`. Re-observing the same entity is idempotent. Attribute changes create a change record instead of creating duplicate nodes.

## Continuous change semantics

The existing content-change detector now feeds endpoint observations into the graph and defaults TLS certificate verification to enabled. A content change is an observation that can trigger targeted re-analysis; it is not itself a vulnerability verdict.

## JavaScript intelligence

Static JavaScript extraction normalizes endpoint-like references and query parameters without executing JavaScript. The normalized relationships are written to the graph so later API and vulnerability phases can correlate them with other observations.

## Safety boundary

The graph is not an authorization system. Scope, capability policy, approval, runtime isolation, and disclosure authority remain outside the graph and ultimately belong to the governed Tinlance execution boundary.
