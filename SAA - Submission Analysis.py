"""

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

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=check_job_id)

    return


@phantom.playbook_block()
def job_type(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("job_type() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["get_job_summary_1:action_result.data.*.Submission.MD5", "==", ""],
            ["get_job_summary_1:action_result.data.*.Submission.SHA256", "==", ""],
            ["http", "in", "get_job_summary_1:action_result.data.*.Submission.Name"]
        ],
        conditions_dps=[
            ["get_job_summary_1:action_result.data.*.Submission.MD5", "==", ""],
            ["get_job_summary_1:action_result.data.*.Submission.SHA256", "==", ""],
            ["http", "in", "get_job_summary_1:action_result.data.*.Submission.Name"]
        ],
        name="job_type:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        image_base64(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["get_job_summary_1:action_result.data.*.Submission.MD5", "!=", ""],
            ["get_job_summary_1:action_result.data.*.Submission.SHA256", "!=", ""]
        ],
        conditions_dps=[
            ["get_job_summary_1:action_result.data.*.Submission.MD5", "!=", ""],
            ["get_job_summary_1:action_result.data.*.Submission.SHA256", "!=", ""]
        ],
        name="job_type:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return


@phantom.playbook_block()
def get_job_summary_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_job_summary_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.SAA_JOB_ID","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_job_summary_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None:
            parameters.append({
                "job_id": get_finding_or_investigation_1_result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get job summary", parameters=parameters, name="get_job_summary_1", assets=["splunk_attack_analyzer"], callback=get_job_forensics_1)

    return


@phantom.playbook_block()
def get_job_forensics_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_job_forensics_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.SAA_JOB_ID","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_job_forensics_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None:
            parameters.append({
                "job_id": get_finding_or_investigation_1_result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get job forensics", parameters=parameters, name="get_job_forensics_1", assets=["splunk_attack_analyzer"], callback=get_job_screenshots_1)

    return


@phantom.playbook_block()
def get_job_screenshots_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_job_screenshots_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.SAA_JOB_ID","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_job_screenshots_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None:
            parameters.append({
                "job_id": get_finding_or_investigation_1_result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get job screenshots", parameters=parameters, name="get_job_screenshots_1", assets=["splunk_attack_analyzer"], callback=job_type)

    return


@phantom.playbook_block()
def debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_2() called")

    parameters = []

    parameters.append({
        "input_1": ["container:id"],
        "input_2": None,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_2", callback=add_finding_or_investigation_note_4)

    return


@phantom.playbook_block()
def format_summary_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_summary_report() called")

    template = """Splunk Attack Analyzer - Job Summary:\n\n| Submission | Normalized Score | Score Id  | Classifications | Report Link | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| {0}:`{1}` | {2} | {3} | {4} | {5} | Splunk Attack Analyzer (SAA) |\n%%\n\nScreenshots associated with the detonation are shown below (if available):\n\n{6{6}}"""

    # parameter list for template variable replacement
    parameters = [
        "get_job_summary_1:action_result.data.*.ResourcesType",
        "get_job_summary_1:action_result.data.*.Resources.Name",
        "get_job_summary_1:action_result.data.*.Resources.Score",
        "get_job_summary_1:action_result.data.*.Resources.DisplayScore",
        "get_job_summary_1:action_result.data.*.Verdict",
        "get_job_summary_1:action_result.summary.AppURL",
        "file_screenshot_formatting:custom_function:report"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_summary_report")

    return


@phantom.playbook_block()
def file_screenshot_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("file_screenshot_formatting() called")

    filtered_result_0_data_job_type = phantom.collect2(container=container, datapath=["filtered-data:job_type:condition_2:get_job_summary_1:action_result.data.*.Submission.Name","filtered-data:job_type:condition_2:get_job_summary_1:action_result.summary.Job ID"])
    get_job_screenshots_1_result_data = phantom.collect2(container=container, datapath=["get_job_screenshots_1:action_result.parameter.job_id","get_job_screenshots_1:action_result.data.*.file_name","get_job_screenshots_1:action_result.data.*.id"], action_results=results)

    filtered_result_0_data___submission_name = [item[0] for item in filtered_result_0_data_job_type]
    filtered_result_0_summary_job_id = [item[1] for item in filtered_result_0_data_job_type]
    get_job_screenshots_1_parameter_job_id = [item[0] for item in get_job_screenshots_1_result_data]
    get_job_screenshots_1_result_item_1 = [item[1] for item in get_job_screenshots_1_result_data]
    get_job_screenshots_1_result_item_2 = [item[2] for item in get_job_screenshots_1_result_data]

    file_screenshot_formatting__report = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    file_screenshot_formatting__report = ""
    
    for file, job_id in zip(filtered_result_0_data___submission_name, filtered_result_0_summary_job_id):
        file_screenshot_formatting__report += f"#### {file}\n"
        for screenshot_job, screenshot_name, screenshot_id in zip(get_job_screenshots_1_parameter_job_id, get_job_screenshots_1_result_item_1, get_job_screenshots_1_result_item_2):
            if job_id == screenshot_job:
                file_screenshot_formatting__report += f"![{screenshot_name}](/view?id={screenshot_id})\n"

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="file_screenshot_formatting__inputs:0:filtered-data:job_type:condition_2:get_job_summary_1:action_result.data.*.Submission.Name", value=json.dumps(filtered_result_0_data___submission_name))
    phantom.save_block_result(key="file_screenshot_formatting__inputs:1:filtered-data:job_type:condition_2:get_job_summary_1:action_result.summary.Job ID", value=json.dumps(filtered_result_0_summary_job_id))
    phantom.save_block_result(key="file_screenshot_formatting__inputs:2:get_job_screenshots_1:action_result.parameter.job_id", value=json.dumps(get_job_screenshots_1_parameter_job_id))
    phantom.save_block_result(key="file_screenshot_formatting__inputs:3:get_job_screenshots_1:action_result.data.*.file_name", value=json.dumps(get_job_screenshots_1_result_item_1))
    phantom.save_block_result(key="file_screenshot_formatting__inputs:4:get_job_screenshots_1:action_result.data.*.id", value=json.dumps(get_job_screenshots_1_result_item_2))

    phantom.save_block_result(key="file_screenshot_formatting:report", value=json.dumps(file_screenshot_formatting__report))

    debug_2(container=container)

    return


@phantom.playbook_block()
def add_finding_or_investigation_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_finding_or_investigation_note_4() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.finding_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_job_screenshots_1_result_data = phantom.collect2(container=container, datapath=["get_job_screenshots_1:action_result.data.*.id","get_job_screenshots_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_finding_or_investigation_note_4' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_job_screenshots_1_result_item in get_job_screenshots_1_result_data:
            if get_finding_or_investigation_1_result_item[0] is not None:
                parameters.append({
                    "id": get_finding_or_investigation_1_result_item[0],
                    "files": [
                        get_job_screenshots_1_result_item[0],
                    ],
                    "title": "Splunk Attack Analyzer Report",
                    "content": "test",
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add finding or investigation note", parameters=parameters, name="add_finding_or_investigation_note_4", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.SAA_JOB_ID","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    get_finding_or_investigation_1_result_item_0 = [item[0] for item in get_finding_or_investigation_1_result_data]

    parameters = []

    parameters.append({
        "input_1": get_finding_or_investigation_1_result_item_0,
        "input_2": None,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

    return


@phantom.playbook_block()
def check_job_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_job_id() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.SAA_JOB_ID", "!=", ""]
        ],
        conditions_dps=[
            ["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.SAA_JOB_ID", "!=", ""]
        ],
        name="check_job_id:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        get_job_summary_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def playbook_get_container_id_and_vault_list_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_get_container_id_and_vault_list_1() called")

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id"], action_results=results)

    get_finding_or_investigation_1_result_item_0 = [item[0] for item in get_finding_or_investigation_1_result_data]

    inputs = {
        "finding_id": get_finding_or_investigation_1_result_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/get container id and vault list", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/get container id and vault list", container=container, name="playbook_get_container_id_and_vault_list_1", callback=playbook_get_container_id_and_vault_list_1_callback, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_get_container_id_and_vault_list_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_get_container_id_and_vault_list_1_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


@phantom.playbook_block()
def image_base64(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("image_base64() called")

    playbook_get_container_id_and_vault_list_1_output_vault_list = phantom.collect2(container=container, datapath=["playbook_get_container_id_and_vault_list_1:playbook_output:vault_list"])

    playbook_get_container_id_and_vault_list_1_output_vault_list_values = [item[0] for item in playbook_get_container_id_and_vault_list_1_output_vault_list]

    image_base64__image_base64 = None
    image_base64__status = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    image_base64__image_base64 = []
    image_base64__status = []
    import base64
    phantom.debug(type(playbook_get_container_id_and_vault_list_1_output_vault_list_values))
    phantom.debug(playbook_get_container_id_and_vault_list_1_output_vault_list_values)
    for i in range(len(playbook_get_container_id_and_vault_list_1_output_vault_list_values)):            
        image_path = playbook_get_container_id_and_vault_list_1_output_vault_list_values[i]
        phantom.debug(image_path)            
        with open(image_path, "rb") as image_file:        
            encoded_string = base64.b64encode(image_file.read()).decode('utf-8')                
        image_base64__image_base64.append(encoded_string)
        image_base64__status.append("success")
        phantom.debug(image_base64__image_base64)            
        phantom.debug(image_base64__status)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="image_base64__inputs:0:playbook_get_container_id_and_vault_list_1:playbook_output:vault_list", value=json.dumps(playbook_get_container_id_and_vault_list_1_output_vault_list_values))

    phantom.save_block_result(key="image_base64:image_base64", value=json.dumps(image_base64__image_base64))
    phantom.save_block_result(key="image_base64:status", value=json.dumps(image_base64__status))

    add_investigation_file_2(container=container)

    return


@phantom.playbook_block()
def add_investigation_file_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_investigation_file_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id"])
    image_base64__image_base64 = json.loads(_ if (_ := phantom.get_run_data(key="image_base64:image_base64")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'add_investigation_file_2' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None and image_base64__image_base64 is not None:
            parameters.append({
                "id": finding_data_item[0],
                "data": image_base64__image_base64,
                "file_name": "Screenshot",
                "source_type": "Note",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add investigation file", parameters=parameters, name="add_investigation_file_2", assets=["builtin_mc_connector"], callback=format_screenshots)

    return


@phantom.playbook_block()
def format_screenshots(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_screenshots() called")

    template = """Screenshots from the SAA detonation job has been added to to the \"Files\" section below."""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_screenshots")

    add_finding_or_investigation_note_3(container=container)

    return


@phantom.playbook_block()
def add_finding_or_investigation_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_finding_or_investigation_note_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    format_screenshots = phantom.get_format_data(name="format_screenshots")

    parameters = []

    # build parameters list for 'add_finding_or_investigation_note_3' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None and format_screenshots is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
                "title": "Splunk Attack Analyzer Screenshots",
                "content": format_screenshots,
                "files": [
                ],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add finding or investigation note", parameters=parameters, name="add_finding_or_investigation_note_3", assets=["builtin_mc_connector"])

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