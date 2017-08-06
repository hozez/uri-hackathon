import json
import logging
import logging.handlers
import traceback

import flask
import nlp

logger = logging.getLogger('nlp.flask')


def configure_logging():
    logger = logging.getLogger()

    logger.setLevel(logging.DEBUG)

    log_file_path = 'flask.log'
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_file_path,
        maxBytes=2**20 * 6,
        backupCount=3,
    )
    logger.addHandler(file_handler)

    gunicorn_access_logger = logging.getLogger('gunicorn.access')
    gunicorn_access_logger.propagate = True


configure_logging()

flask_app = flask.Flask(__name__)


@flask_app.errorhandler(Exception)
def error_handler(exception):
    response = {
        'success': False,
        'message': str(exception),
        'stacktrace': traceback.format_exc(),
    }

    logger.exception(str(exception))

    return (
        json.dumps(response),
        500,
    )


@flask_app.route('/analyze_sentence', methods=['POST', 'OPTIONS'])
def analyze_sentence():
    request = flask.request.json

    iocs = nlp.get_valid_iocs(request['text'])
    iocs_count = len(iocs)

    response = {
        'success': True,
        'iocs_count': iocs_count,
        'iocs': iocs,
    }

    return (
        json.dumps(response),
        200,
    )

@flask_app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,OPTIONS,DELETE')

    return response
