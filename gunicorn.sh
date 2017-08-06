#!/bin/bash
gunicorn \
        -b 0.0.0.0:8080 \
        app:flask_app \
        --access-logfile=/tmp/gunicorn.log \
        --pid /tmp/gunicorn.pid \
        -w 5 \
        --threads 1 \
        --timeout 900