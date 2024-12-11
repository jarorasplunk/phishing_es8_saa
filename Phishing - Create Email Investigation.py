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
            "subject_dedup:custom_function_result.data.*.item"
        ])
    description_formatted_string = phantom.format(
        container=container,
        template="""Investigation created for the phishing email \nSubject: {0}\nRecipient: {1}""",
        parameters=[
            "subject_dedup:custom_function_result.data.*.item",
            "recipient_dedup:custom_function_result.data.*.item"
        ])

    subject_dedup_data = phantom.collect2(container=container, datapath=["subject_dedup:custom_function_result.data.*.item"])
    recipient_dedup_data = phantom.collect2(container=container, datapath=["recipient_dedup:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'start_investigations_1' call
    for subject_dedup_data_item in subject_dedup_data:
        for recipient_dedup_data_item in recipient_dedup_data:
            if name_formatted_string is not None:
                parameters.append({
                    "name": name_formatted_string,
                    "status": "",
                    "description": description_formatted_string,
                    "findings_data": [
                    ],
                    "investigation_type": "email",
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
                "response_template_id": "7973ff21-8800-413c-8485-ca94f46a6bfd",
                "context": {'artifact_id': start_investigations_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add response plan", parameters=parameters, name="add_response_plan_1", assets=["builtin_mc_connector"], callback=get_finding_or_investigation_1)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Email Artifact"]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        subject_dedup(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def get_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    start_investigations_1_result_data = phantom.collect2(container=container, datapath=["start_investigations_1:action_result.data.*.id","start_investigations_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_finding_or_investigation_1' call
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

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=get_phase_id_1)

    return


@phantom.playbook_block()
def reported_email_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("reported_email_details() called")

    template = """\nReporting method: {0}\nFrom: {1}\nTo: {2}\nSubject: {3}\nBody Text: {4}\nDate: {5}\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:artifact:*.description",
        "filtered-data:filter_2:condition_1:artifact:*.cef.emailHeaders.From",
        "filtered-data:filter_2:condition_1:artifact:*.cef.emailHeaders.To",
        "filtered-data:filter_2:condition_1:artifact:*.cef.emailHeaders.Subject",
        "filtered-data:filter_2:condition_1:artifact:*.cef.bodyText",
        "filtered-data:filter_2:condition_1:artifact:*.cef.emailHeaders.Date"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="reported_email_details")

    add_task_note_1(container=container)

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
        soar_vault_details(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def get_phase_id_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_phase_id_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.name","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_phase_id_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
                "phase_name": "Ingestion",
                "response_template_name": get_finding_or_investigation_1_result_item[1],
                "context": {'artifact_id': get_finding_or_investigation_1_result_item[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get phase id", parameters=parameters, name="get_phase_id_1", assets=["builtin_mc_connector"], callback=get_task_id_1)

    return


@phantom.playbook_block()
def add_task_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""## Email Header Details:\n""",
        parameters=[])
    content_formatted_string = phantom.format(
        container=container,
        template="""\n{0}\n""",
        parameters=[
            "reported_email_details:formatted_data"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    reported_email_details = phantom.get_format_data(name="reported_email_details")

    parameters = []

    # build parameters list for 'add_task_note_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and title_formatted_string is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": title_formatted_string,
                        "content": content_formatted_string,
                        "task_id": get_task_id_1_result_item[0],
                        "phase_id": get_phase_id_1_result_item[0],
                        "response_plan_id": get_finding_or_investigation_1_result_item[1],
                        "context": {'artifact_id': get_finding_or_investigation_1_result_item[2]},
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_1", assets=["builtin_mc_connector"], callback=join_create_event_1)

    return


@phantom.playbook_block()
def get_task_id_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_task_id_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.name","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_task_id_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
                "task_name": "Review",
                "phase_name": "Ingestion",
                "response_template_name": get_finding_or_investigation_1_result_item[1],
                "context": {'artifact_id': get_finding_or_investigation_1_result_item[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get task id", parameters=parameters, name="get_task_id_1", assets=["builtin_mc_connector"], callback=filter_2)

    return


@phantom.playbook_block()
def join_create_event_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_create_event_1() called")

    if phantom.completed(action_names=["add_task_note_1", "add_task_note_2"]):
        # call connected block "create_event_1"
        create_event_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def create_event_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_event_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    id_value = container.get("id", None)
    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'create_event_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
                "pairs": [
                    { "name": "soar_event_id", "value": id_value },
                ],
                "context": {'artifact_id': get_finding_or_investigation_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create event", parameters=parameters, name="create_event_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def subject_dedup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("subject_dedup() called")

    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.Subject","filtered-data:filter_1:condition_1:artifact:*.id"])

    filtered_artifact_0__cef_emailheaders_subject = [item[0] for item in filtered_artifact_0_data_filter_1]

    parameters = []

    parameters.append({
        "input_list": filtered_artifact_0__cef_emailheaders_subject,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_deduplicate", parameters=parameters, name="subject_dedup", callback=recipient_dedup)

    return


@phantom.playbook_block()
def recipient_dedup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("recipient_dedup() called")

    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.To","filtered-data:filter_1:condition_1:artifact:*.id"])

    filtered_artifact_0__cef_emailheaders_to = [item[0] for item in filtered_artifact_0_data_filter_1]

    parameters = []

    parameters.append({
        "input_list": filtered_artifact_0__cef_emailheaders_to,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_deduplicate", parameters=parameters, name="recipient_dedup", callback=start_investigations_1)

    return


@phantom.playbook_block()
def soar_vault_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("soar_vault_details() called")

    template = """\nFile Name: {0}\nSOAR Vault ID: {1}\nFile SHA1: {2}\nFile SHA256: {3}\n\n## SOAR Container/Event link: [SOAR]({4})\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_2:artifact:*.cef.fileName",
        "filtered-data:filter_2:condition_2:artifact:*.cef.vaultId",
        "filtered-data:filter_2:condition_2:artifact:*.cef.fileHashSha1",
        "filtered-data:filter_2:condition_2:artifact:*.cef.fileHashSha256",
        "container:url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="soar_vault_details")

    add_task_note_2(container=container)

    return


@phantom.playbook_block()
def add_task_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""## Email Attachments/Files Details:\n""",
        parameters=[])
    content_formatted_string = phantom.format(
        container=container,
        template="""\n{0}\n\n""",
        parameters=[
            "soar_vault_details:formatted_data"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    soar_vault_details = phantom.get_format_data(name="soar_vault_details")

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and title_formatted_string is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": title_formatted_string,
                        "content": content_formatted_string,
                        "task_id": get_task_id_1_result_item[0],
                        "phase_id": get_phase_id_1_result_item[0],
                        "response_plan_id": get_finding_or_investigation_1_result_item[1],
                        "context": {'artifact_id': get_finding_or_investigation_1_result_item[2]},
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_2", assets=["builtin_mc_connector"], callback=join_create_event_1)

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