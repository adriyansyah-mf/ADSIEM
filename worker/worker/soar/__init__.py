"""SOAR workflows: a small n8n-style node graph run per alert.

Pure modules (template, curl, graph) have no DB or network imports, so
server-api reuses them for validation and curl parsing.
"""
