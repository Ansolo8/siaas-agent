# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - API routes
# By João Pedro Seara, 2022-2024

from __main__ import app
from flask import jsonify, request
import siaas_aux

SIAAS_VERSION = "1.0.1"

app.config['JSON_AS_ASCII'] = False
app.config['JSON_SORT_KEYS'] = False


@app.route('/', strict_slashes=False)
def index():
    """
    Agent API route - index
    """
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    ret_code = 200
    output = {
        'name': 'Intelligent System for Automation of Security Audits (SIAAS)',
        'module': 'Agent',
        'version': SIAAS_VERSION,
        'docs': request.url_root.rstrip('/')+"/docs"
    }
    return jsonify(
        {
            'output': output,
            'status': 'success',
            'total_entries': len(output),
            'time': siaas_aux.get_now_utc_str()
        }
    ), ret_code


@app.route('/siaas-agent', methods=['GET'], strict_slashes=False)
def siaas_agent():
    """
    Agent API route - agent information
    """
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    ret_code = 200
    module = request.args.get('module', default='*', type=str)
    all_existing_modules = "platform,neighborhood,portscanner,webscanner,metasploit,remediation,audit,config" #webscanner/metasploit/remediation/audit
    for m in module.split(','):
        if m.strip() == "*":
            module = all_existing_modules
    output = siaas_aux.merge_module_dicts(module)
    if type(output) == bool and output == False:
        status = "failure"
        ret_code = 500
        output = {}
    else:
        status = "success"
    try:
        for k in output["config"].keys():
            if k.endswith("_pwd") or k.endswith("_passwd") or k.endswith("_password"):
                output["config"][k] = '*' * 8
    except:
        pass
    return jsonify(
        {
            'output': output,
            'status': status,
            'total_entries': len(output),
            'time': siaas_aux.get_now_utc_str()
        }
    ), ret_code


@app.route('/siaas-agent/trigger/<module>', methods=['POST'], strict_slashes=False)
def siaas_agent_trigger(module):
    """
    Agent API route - manually trigger an immediate run of a module.

    The module's loop normally waits for its configured interval. This drops a
    trigger file that makes the loop wake up and run once on its next check
    (within a couple of seconds). Useful for an on-demand "Run now" button.
    Triggerable modules: portscanner, webscanner, metasploit, remediation, audit.
    """
    module = (module or "").strip().lower()
    if module not in siaas_aux.VALID_TRIGGER_MODULES:
        return jsonify(
            {
                'output': {
                    'module': module,
                    'message': 'Unknown or non-triggerable module.',
                    'triggerable_modules': siaas_aux.VALID_TRIGGER_MODULES,
                },
                'status': 'failure',
                'total_entries': 0,
                'time': siaas_aux.get_now_utc_str()
            }
        ), 400

    ok = siaas_aux.create_module_trigger(module)
    if ok:
        return jsonify(
            {
                'output': {
                    'module': module,
                    'message': "Manual run triggered. The module will run within a few seconds.",
                },
                'status': 'success',
                'total_entries': 1,
                'time': siaas_aux.get_now_utc_str()
            }
        ), 202

    return jsonify(
        {
            'output': {
                'module': module,
                'message': 'Could not create the trigger file.',
            },
            'status': 'failure',
            'total_entries': 0,
            'time': siaas_aux.get_now_utc_str()
        }
    ), 500
