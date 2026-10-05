# BugFlow Elite — Phase 8 Autonomous Research

## Objective

Add bounded planning and attack-path reasoning without allowing a planner to bypass execution governance.

## Planner boundary

The planner produces ResearchTask objects with action class, target, rationale, priority, prerequisites, and lifecycle state. It does not execute commands, approve scope, or submit reports.

Dependencies are resolved deterministically and cycles fail closed. Follow-up tasks are generated from change and finding signals and remain subject to the same scope and approval controls as manually requested work.

## Attack-path reasoning

Attack paths are graph reasoning over observed relationships. Enumeration is hop-bounded and cycle-safe; it does not exploit targets or generate automatic offensive actions.
