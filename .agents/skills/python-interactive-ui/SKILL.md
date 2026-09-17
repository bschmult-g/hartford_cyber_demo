---
name: python-interactive-ui
description: Guides the design, implementation, and verification of modern Python backends and responsive, reactive interactive front-ends. Use when building Python web apps, dashboards, Streamlit/Gradio/FastHTML interfaces, FastAPI/Flask services with React, Vue, or HTMX, or when adding real-time streaming, WebSockets, or UI state management.
version: 1.0.0
---

# Python & Interactive Front-End Development Skill

## Purpose & Scope
This skill directs the agent to generate idiomatic, type-safe, production-ready Python backends paired with intuitive, reactive, and visually polished user interfaces.

## 1. Architectural Decision Matrix
| Use Case | Recommended Backend | Recommended Front-End | Communication / Protocol |
|---|---|---|---|
| Rapid Data/AI Prototypes | Python native | Streamlit / Gradio / Mesop | Native Component State |
| Lightweight Reactive UI | FastAPI | FastHTML / HTMX + Tailwind CSS | REST / Server-Sent Events (SSE) |
| Rich Dashboard / Full-Stack | FastAPI / Python 3.12+ | React / Next.js / Svelte | REST / WebSockets + JSON |
| High-Throughput Services | FastAPI + AsyncIO | Single Page App (Vite + React) | Async REST / WebSockets |

## 2. Python Backend Standards
- Target Python 3.11+ using modern typing (`type | None`, `list[str]`, `typing.Self`).
- Use Pydantic v2 or `dataclasses` for data modeling with strict validation.
- Manage dependencies via `pyproject.toml` (managed with `uv` or `poetry`).
- Prefer async handlers (`async def`) for I/O operations and token streaming.

## 3. Interactive Front-End Principles
- Visual Feedback: Always implement skeleton loaders, spinners, or progress indicators.
- Streaming: Stream AI token generations or updates via Server-Sent Events (SSE).
- Error Boundaries: Display inline error banners with retry mechanisms.
- Aesthetics: Use utility CSS (Tailwind) or structured component libraries (shadcn/ui).

## 4. Implementation Workflow
1. Requirements & Schemas: Define Pydantic request/response models.
2. Backend API: Build validated async endpoints with structured error responses.
3. Interactive UI: Build responsive components with reactive state handling.
4. Verification: Run `pytest` and verify interactive UI states via browser preview.
