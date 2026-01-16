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
    all_existing_modules = "platform,neighborhood,portscanner,webscanner,metasploit,config" #webscanner and metaploit added
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
