"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'start_investigations_1' block
    start_investigations_1(container=container)

    return

@phantom.playbook_block()
def start_investigations_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("start_investigations_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    name_formatted_string = phantom.format(
        container=container,
        template="""Phishing Email Investigation: {0}\n""",
        parameters=[
            "container:name"
        ])
    description_formatted_string = phantom.format(
        container=container,
        template="""Investigation created for the phishing email with subject: {0}\n""",
        parameters=[
            "container:name"
        ])

    name_value = container.get("name", None)

    parameters = []

    if name_formatted_string is not None:
        parameters.append({
            "name": name_formatted_string,
            "status": "",
            "description": description_formatted_string,
            "findings_data": [
            ],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("start investigations", parameters=parameters, name="start_investigations_1", assets=["builtin_mc_connector"], callback=update_finding_or_investigation_1)

    return


@phantom.playbook_block()
def update_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "id": "",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update finding or investigation", parameters=parameters, name="update_finding_or_investigation_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return