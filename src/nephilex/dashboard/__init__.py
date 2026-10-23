"""Nephilex dashboard, an optional local web app for scan history and trends.

The dashboard stores every scan you send it (a Nephilex JSON report) in a small
SQLite database and shows projects, scan history, risk trends over time, and
findings. It is entirely optional and ships behind the ``dashboard`` extra:

    pip install "nephilex[dashboard]"
    nephilex dashboard          # then open http://127.0.0.1:8000

The base ``nephilex`` CLI and library never import this package, so installing Nephilex
stays lightweight for users who only need the scanner.
"""
