"""
Leverages Splunk technologies to determine if a .eml or .msg file in the vault is malicious, whether or not it contained suspect URLs or Files, and who may have interacted with the IoCs (email, URLs, or Files).
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_finding_or_investigation_1' block
    get_finding_or_investigation_1(container=container)

    return

@phantom.playbook_block()
def splunk_attack_analyzer(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("splunk_attack_analyzer() called")

    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:fiter_email_items:condition_1:get_emails_from_vault:custom_function_result.data.vault_id"])

    filtered_cf_result_0_data_vault_id = [item[0] for item in filtered_cf_result_0]

    inputs = {
        "url": [],
        "vault_id": filtered_cf_result_0_data_vault_id,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Splunk_Attack_Analyzer_Dynamic_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Splunk_Attack_Analyzer_Dynamic_Analysis", container=container, name="splunk_attack_analyzer", callback=splunk_attack_analyzer_callback, inputs=inputs)

    return


@phantom.playbook_block()
def splunk_attack_analyzer_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("splunk_attack_analyzer_callback() called")

    
    high_score_indicator_decision(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def get_emails_from_vault(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_emails_from_vault() called")

    soar_event_id_data = phantom.collect2(container=container, datapath=["soar_event_id:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'get_emails_from_vault' call
    for soar_event_id_data_item in soar_event_id_data:
        parameters.append({
            "vault_id": None,
            "file_name": None,
            "container_id": soar_event_id_data_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/vault_list", parameters=parameters, name="get_emails_from_vault", callback=fiter_email_items)

    return


@phantom.playbook_block()
def fiter_email_items(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("fiter_email_items() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            [".eml", "in", "get_emails_from_vault:custom_function_result.data.file_name"],
            [".msg", "in", "get_emails_from_vault:custom_function_result.data.file_name"]
        ],
        name="fiter_email_items:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        splunk_attack_analyzer(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def who_interacted_with_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("who_interacted_with_urls() called")

    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:filter_malicious_indicators:condition_1:split_related_observables:custom_function_result.data.output.value"])

    filtered_cf_result_0_data_output_value = [item[0] for item in filtered_cf_result_0]

    inputs = {
        "ip": [],
        "url": filtered_cf_result_0_data_output_value,
        "file": [],
        "domain": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Splunk_Identifier_Activity_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Splunk_Identifier_Activity_Analysis", container=container, name="who_interacted_with_urls", callback=join_who_received_email, inputs=inputs)

    return


@phantom.playbook_block()
def high_score_indicator_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("high_score_indicator_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["splunk_attack_analyzer:playbook_output:observable.related_observables.*.reputation.score_id", ">", 5]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        split_related_observables(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["splunk_attack_analyzer:playbook_output:observable.reputation.score_id", ">", 5]
        ],
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        join_who_received_email(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 3
    format_analyst_note(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def join_who_received_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_who_received_email() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_who_received_email_called"):
        return

    if phantom.completed(playbook_names=["splunk_attack_analyzer"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_who_received_email_called", value="who_received_email")

        # call connected block "who_received_email"
        who_received_email(container=container, handle=handle)

    return


@phantom.playbook_block()
def who_received_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("who_received_email() called")

    notable_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.emailHeaders.Message-ID"], scope="all")

    notable_artifact_fields_item_0 = [item[0] for item in notable_artifact_data]

    inputs = {
        "sender": [],
        "subject": [],
        "message_id": notable_artifact_fields_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Splunk_Message_Identifier_Activity_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Splunk_Message_Identifier_Activity_Analysis", container=container, name="who_received_email", callback=who_received_email_callback, inputs=inputs)

    return


@phantom.playbook_block()
def who_received_email_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("who_received_email_callback() called")

    
    convert_to_artifacts_0(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    merge_playbook_reports(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def add_artifacts_0(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_artifacts_0() called")

    soar_event_id_data = phantom.collect2(container=container, datapath=["soar_event_id:custom_function_result.data.*.item"])
    convert_to_artifacts__json = json.loads(_ if (_ := phantom.get_run_data(key="convert_to_artifacts:json")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'add_artifacts_0' call
    for soar_event_id_data_item in soar_event_id_data:
        parameters.append({
            "name": None,
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "container": soar_event_id_data_item[0],
            "input_json": convert_to_artifacts__json,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    for artifact_json in convert_to_artifacts__json:

        parameters.append({
            "name": "Interaction with phish indicators",
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "container": soar_event_id_data_item[0],
            "input_json": artifact_json,
            "cef_data_type": None,
            "run_automation": None,
        })


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="add_artifacts_0", callback=add_task_note_2)

    return


@phantom.playbook_block()
def convert_to_artifacts_0(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("convert_to_artifacts_0() called")

    who_received_email_output_observable = phantom.collect2(container=container, datapath=["who_received_email:playbook_output:observable"])
    who_interacted_with_urls_output_observable = phantom.collect2(container=container, datapath=["who_interacted_with_urls:playbook_output:observable"])
    who_interacted_with_files_output_observable = phantom.collect2(container=container, datapath=["who_interacted_with_files:playbook_output:observable"])
    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:filter_malicious_indicators:condition_1:split_related_observables:custom_function_result.data.output"])
    filtered_cf_result_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_malicious_indicators:condition_2:split_related_observables:custom_function_result.data.output"])
    splunk_attack_analyzer_output_observable = phantom.collect2(container=container, datapath=["splunk_attack_analyzer:playbook_output:observable"])

    who_received_email_output_observable_values = [item[0] for item in who_received_email_output_observable]
    who_interacted_with_urls_output_observable_values = [item[0] for item in who_interacted_with_urls_output_observable]
    who_interacted_with_files_output_observable_values = [item[0] for item in who_interacted_with_files_output_observable]
    filtered_cf_result_0_data_output = [item[0] for item in filtered_cf_result_0]
    filtered_cf_result_1_data_output = [item[0] for item in filtered_cf_result_1]
    splunk_attack_analyzer_output_observable_values = [item[0] for item in splunk_attack_analyzer_output_observable]

    convert_to_artifacts_0__json = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    aggregate_data__json = []
    suspect_urls = filtered_cf_result_0_data_output
    suspect_files = filtered_cf_result_1_data_output
    suspect_emails = [item for item in splunk_attack_analyzer_output_observable_values if item]
    url_activity_list = [item for item in who_interacted_with_urls_output_observable_values if item]
    file_activity_list = [item for item in who_interacted_with_files_output_observable_values if item]
    message_activity_list = [item for item in who_received_email_output_observable_values if item]
    
    # Change labels here based on desired artifact labeling.
    # By default, the label is based on the vendor technology and IoC involved.
    email_interaction_label = "splunk_email_interaction"
    file_interaction_label = "splunk_file_interaction"
    url_interaction_label = "splunk_url_interaction"
    suspect_url_label = "saa_url_report"
    suspect_file_label = "saa_file_report"
    suspect_email_label = "saa_email_report"

    for email in suspect_emails:
        email.pop('related_observables', None)
        artifact = {'cef': email, 'name': f'{email["source"]} reputation', 'label': suspect_email_label, 'cef_types': {'value': [email['type']]} }
        aggregate_data__json.append(artifact)  
    
    for url in suspect_urls:
        artifact = {'cef': url, 'name': f'{url["source"]} reputation', 'label': suspect_url_label, 'cef_types': {'value': [url['type']]}}
        aggregate_data__json.append(artifact)  
    
    for file in suspect_files:
        artifact = {'cef': file, 'name': f'{file["source"]} reputation', 'label': suspect_file_label, 'cef_types': {'value': [file['type']]} }
        aggregate_data__json.append(artifact)  

    for message_activity in message_activity_list:
        aggregate_data__json.append({'cef': message_activity, 'label': email_interaction_label, 'name': 'Received suspect email', 'cef_types': {'value': [message_activity['type']]}})
        
    for url_act in url_activity_list:
        artifact = {'label': url_interaction_label, 'name': 'Interaction with suspect url', 'cef_types': {'value': [url_act['type']]}}
        identifier_activity = url_act.pop('identifier_activity', [])
        url_act.pop('total_count', None)
        artifact['cef'] = url_act
        # future proofing in case the identifier_activity changes type to dict
        if isinstance(identifier_activity, list):
            for item in identifier_activity:
                sub_artifact = artifact.copy()
                sub_artifact['cef']['identifier_activity'] = item
                aggregate_data__json.append(sub_artifact)  
        else:
            artifact['cef']['identifier_activity'] = identifier_activity
            aggregate_data__json.append(artifact) 
    
    for file_act in file_activity_list:
        artifact = {'label': file_interaction_label, 'name': 'Interaction with suspect file', 'cef_types': {'value': [file_act['type']]}}
        identifier_activity = file_act.pop('identifier_activity', [])
        file_act.pop('total_count', None)
        artifact['cef'] = file_act
        # future proofing in case the identifier_activity changes type to dict
        if isinstance(identifier_activity, list):
            for item in identifier_activity:
                sub_artifact = artifact.copy()
                sub_artifact['cef']['identifier_activity'] = item
                aggregate_data__json.append(sub_artifact)  
        else:
            artifact['cef']['identifier_activity'] = identifier_activity
            aggregate_data__json.append(artifact) 
        
    convert_to_artifacts__json = aggregate_data__json
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="convert_to_artifacts_0:json", value=json.dumps(convert_to_artifacts_0__json))

    add_artifacts_0(container=container)

    return


@phantom.playbook_block()
def filter_malicious_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_malicious_indicators() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["split_related_observables:custom_function_result.data.output.type", "==", "url"],
            ["split_related_observables:custom_function_result.data.output.reputation.score_id", ">", 5]
        ],
        name="filter_malicious_indicators:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        who_interacted_with_urls(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["split_related_observables:custom_function_result.data.output.type", "==", "file"],
            ["split_related_observables:custom_function_result.data.output.reputation.score_id", ">", 5]
        ],
        name="filter_malicious_indicators:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        who_interacted_with_files(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def who_interacted_with_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("who_interacted_with_files() called")

    split_related_observables__result = phantom.collect2(container=container, datapath=["split_related_observables:custom_function_result.data.output.attributes.sha256"])

    split_related_observables_data_output_attributes_sha256 = [item[0] for item in split_related_observables__result]

    inputs = {
        "ip": [],
        "url": [],
        "file": split_related_observables_data_output_attributes_sha256,
        "domain": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Splunk_Identifier_Activity_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Splunk_Identifier_Activity_Analysis", container=container, name="who_interacted_with_files", callback=join_who_received_email, inputs=inputs)

    return


@phantom.playbook_block()
def split_related_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("split_related_observables() called")

    splunk_attack_analyzer_output_observable = phantom.collect2(container=container, datapath=["splunk_attack_analyzer:playbook_output:observable.related_observables"])

    parameters = []

    # build parameters list for 'split_related_observables' call
    for splunk_attack_analyzer_output_observable_item in splunk_attack_analyzer_output_observable:
        parameters.append({
            "input_list": splunk_attack_analyzer_output_observable_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="split_related_observables", callback=filter_malicious_indicators)

    return


@phantom.playbook_block()
def merge_playbook_reports(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("merge_playbook_reports() called")

    template = """%%\n{0}\n%%\n\n&nbsp;\n&nbsp;\n\n%%\n{1}\n%%\n\n&nbsp;\n&nbsp;\n\n%%\n{2}\n%%\n\n&nbsp;\n&nbsp;\n\n%%\n{3}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "splunk_attack_analyzer:playbook_output:report",
        "who_interacted_with_urls:playbook_output:markdown_report",
        "who_interacted_with_files:playbook_output:markdown_report",
        "who_received_email:playbook_output:markdown_report"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="merge_playbook_reports", drop_none=True)

    add_task_note_3(container=container)

    return


@phantom.playbook_block()
def format_analyst_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_analyst_note() called")

    template = """%%\n{0}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "splunk_attack_analyzer:playbook_output:report"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_analyst_note", drop_none=True)

    add_task_note_1(container=container)

    return


@phantom.playbook_block()
def get_events_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_events_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_events_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get events", parameters=parameters, name="get_events_1", assets=["builtin_mc_connector"], callback=soar_event_id)

    return


@phantom.playbook_block()
def soar_event_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("soar_event_id() called")

    get_events_1_result_data = phantom.collect2(container=container, datapath=["get_events_1:action_result.data.*.events.*.soar_event_id","get_events_1:action_result.parameter.context.artifact_id"], action_results=results)

    get_events_1_result_item_0 = [item[0] for item in get_events_1_result_data]

    parameters = []

    parameters.append({
        "input_list": get_events_1_result_item_0,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_deduplicate", parameters=parameters, name="soar_event_id", callback=get_emails_from_vault)

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
                "phase_name": "Investigation",
                "response_template_name": get_finding_or_investigation_1_result_item[1],
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
def get_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id"])

    parameters = []

    # build parameters list for 'get_finding_or_investigation_1' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None:
            parameters.append({
                "id": finding_data_item[0],
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
                "task_name": "Detonate_and_Analyze",
                "phase_name": "Investigation",
                "response_template_name": get_finding_or_investigation_1_result_item[1],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get task id", parameters=parameters, name="get_task_id_1", assets=["builtin_mc_connector"], callback=get_events_1)

    return


@phantom.playbook_block()
def add_task_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""# Final analysis\n""",
        parameters=[])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    format_analyst_note = phantom.get_format_data(name="format_analyst_note")

    parameters = []

    # build parameters list for 'add_task_note_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and title_formatted_string is not None and format_analyst_note is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": title_formatted_string,
                        "content": format_analyst_note,
                        "task_id": get_task_id_1_result_item[0],
                        "phase_id": get_phase_id_1_result_item[0],
                        "response_plan_id": get_finding_or_investigation_1_result_item[1],
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def add_task_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""# SOAR Artifacts added\n""",
        parameters=[])
    content_formatted_string = phantom.format(
        container=container,
        template="""Artifact IDs: {0}\n\nDetails: \n{1}""",
        parameters=[
            "add_artifacts_0:custom_function_result.data.artifact_id",
            "convert_to_artifacts:custom_function:json"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    add_artifacts_0__result = phantom.collect2(container=container, datapath=["add_artifacts_0:custom_function_result.data.artifact_id"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    convert_to_artifacts__json = json.loads(_ if (_ := phantom.get_run_data(key="convert_to_artifacts:json")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for add_artifacts_0__result_item in add_artifacts_0__result:
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
                        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_2", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def add_task_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""# Analysis report\n""",
        parameters=[])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    merge_playbook_reports = phantom.get_format_data(name="merge_playbook_reports")

    parameters = []

    # build parameters list for 'add_task_note_3' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and title_formatted_string is not None and merge_playbook_reports is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": title_formatted_string,
                        "content": merge_playbook_reports,
                        "task_id": get_task_id_1_result_item[0],
                        "phase_id": get_phase_id_1_result_item[0],
                        "response_plan_id": get_finding_or_investigation_1_result_item[1],
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_3", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def debug_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_3() called")

    splunk_attack_analyzer_output_observable = phantom.collect2(container=container, datapath=["splunk_attack_analyzer:playbook_output:observable.related_observables"])
    filtered_output_0_splunk_attack_analyzer_output_observable = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:splunk_attack_analyzer:playbook_output:observable.related_observables"])

    splunk_attack_analyzer_output_observable_related_observables = [item[0] for item in splunk_attack_analyzer_output_observable]
    filtered_output_0_splunk_attack_analyzer_output_observable_related_observables = [item[0] for item in filtered_output_0_splunk_attack_analyzer_output_observable]

    parameters = []

    parameters.append({
        "input_1": splunk_attack_analyzer_output_observable_related_observables,
        "input_2": filtered_output_0_splunk_attack_analyzer_output_observable_related_observables,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_3")

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            [None, "not in", "splunk_attack_analyzer:playbook_output:observable.related_observables"]
        ],
        name="filter_2:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        debug_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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