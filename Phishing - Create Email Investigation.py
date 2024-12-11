"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)

    return

@phantom.playbook_block()
def start_investigations_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("start_investigations_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    name_formatted_string = phantom.format(
        container=container,
        template="""Phishing Email Investigation: {0}\n""",
        parameters=[
            "filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.Subject"
        ])
    description_formatted_string = phantom.format(
        container=container,
        template="""Investigation created for the phishing email \nSubject: {0}\nRecipient: {1}\n""",
        parameters=[
            "filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.Subject",
            "filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.To"
        ])

    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.Subject","filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.To","filtered-data:filter_1:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'start_investigations_1' call
    for filtered_artifact_0_item_filter_1 in filtered_artifact_0_data_filter_1:
        if name_formatted_string is not None:
            parameters.append({
                "name": name_formatted_string,
                "status": "",
                "description": description_formatted_string,
                "findings_data": [
                ],
                "investigation_type": "email",
                "context": {'artifact_id': filtered_artifact_0_item_filter_1[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("start investigations", parameters=parameters, name="start_investigations_1", assets=["builtin_mc_connector"], callback=add_response_plan_1)

    return


@phantom.playbook_block()
def add_response_plan_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_response_plan_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    start_investigations_1_result_data = phantom.collect2(container=container, datapath=["start_investigations_1:action_result.data.*.id","start_investigations_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_response_plan_1' call
    for start_investigations_1_result_item in start_investigations_1_result_data:
        if start_investigations_1_result_item[0] is not None:
            parameters.append({
                "id": start_investigations_1_result_item[0],
                "response_template_id": "f927eaeb-fb05-4d6d-b79b-677f501fe2da",
                "context": {'artifact_id': start_investigations_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add response plan", parameters=parameters, name="add_response_plan_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.cef.emailHeaders.Subject", "!=", ""],
            ["artifact:*.cef.emailHeaders.To", "!=", ""]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        start_investigations_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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