# Architecture

## Project status

This document describes the Phase 1 foundation of the Phishing URL & Email Analyzer. The current phase implements the Django project shell, navigation, forms, placeholder result/history pages, and dashboard zero states.

## Current architecture

The project is a Django monolith using Django templates, CSS3, minimal vanilla JavaScript, and SQLite configuration. The logical components are `core`, `scans`, `analysis`, and `dashboard`.

The presentation layer renders pages. Future scan services will coordinate input validation, local analysis, risk scoring, and persistence. The analysis layer is intentionally placeholder-only in Phase 1.

## Planned architecture

Later phases will add pure Python URL and email analyzers, a deterministic risk engine, scan models, indicators, recommendations, result persistence, and real dashboard statistics. Submitted URLs will remain strings only; no live URL requests are planned.

## Phase boundary

Phase 1 does not implement URL detection rules, email detection rules, score calculation, scan models, scan persistence, real history, real dashboard statistics, external APIs, machine learning, or live URL checks.
