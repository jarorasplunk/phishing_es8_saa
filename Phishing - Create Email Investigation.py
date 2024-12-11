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

    phantom.act("add response plan", parameters=parameters, name="add_response_plan_1", assets=["builtin_mc_connector"], callback=refresh_finding_or_investigation_1)

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
def refresh_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("refresh_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    start_investigations_1_result_data = phantom.collect2(container=container, datapath=["start_investigations_1:action_result.data.*.id","start_investigations_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'refresh_finding_or_investigation_1' call
    for start_investigations_1_result_item in start_investigations_1_result_data:
        if start_investigations_1_result_item[0] is not None:
            parameters.append({
                "id": start_investigations_1_result_item[0],
                "context": {'artifact_id': start_investigations_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("refresh finding or investigation", parameters=parameters, name="refresh_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=get_finding_or_investigation_1)

    return


@phantom.playbook_block()
def get_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_finding_or_investigation_1' call
    for refresh_finding_or_investigation_1_result_item in refresh_finding_or_investigation_1_result_data:
        if refresh_finding_or_investigation_1_result_item[0] is not None:
            parameters.append({
                "id": refresh_finding_or_investigation_1_result_item[0],
                "context": {'artifact_id': refresh_finding_or_investigation_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=filter_2)

    return


@phantom.playbook_block()
def reported_email_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("reported_email_details() called")

    template = """Email ingested from: {0}\n\nFrom: {1}\nTo: {2}\nSubject: {3}\nBody Text: {4}\nDate: {5}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.description",
        "",
        "",
        "",
        "",
        ""
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="reported_email_details")

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Email Artifact"]
        ],
        name="filter_2:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        reported_email_details(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Vault Artifact"]
        ],
        name="filter_2:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        vault_files_details(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def vault_files_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("vault_files_details() called")

    template = """{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        ""
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="vault_files_details")

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