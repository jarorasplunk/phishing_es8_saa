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

    finding_data = phantom.collect2(container=container, datapath=["finding:finding_id"])

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

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=filter_saa_jobid)

    return


@phantom.playbook_block()
def filter_saa_jobid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_saa_jobid() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.SAA_JOB_ID", "!=", ""]
        ],
        conditions_dps=[
            ["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.SAA_JOB_ID", "!=", ""]
        ],
        name="filter_saa_jobid:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_job_summary_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def get_job_summary_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_job_summary_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "job_id": "c7ea2dd6-a577-4bf2-a94a-b6b1eb8e5f91",
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

    parameters = []

    parameters.append({
        "job_id": "c7ea2dd6-a577-4bf2-a94a-b6b1eb8e5f91",
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

    parameters = []

    parameters.append({
        "job_id": "c7ea2dd6-a577-4bf2-a94a-b6b1eb8e5f91",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get job screenshots", parameters=parameters, name="get_job_screenshots_1", assets=["splunk_attack_analyzer"], callback=debug_1)

    return


@phantom.playbook_block()
def debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_2() called")

    get_job_summary_1_result_data = phantom.collect2(container=container, datapath=["get_job_summary_1:action_result.data.*.ResourceTree.Children.*.Children.*.Children.*.Type","get_job_summary_1:action_result.parameter.context.artifact_id"], action_results=results)

    get_job_summary_1_result_item_0 = [item[0] for item in get_job_summary_1_result_data]

    parameters = []

    parameters.append({
        "input_1": get_job_summary_1_result_item_0,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_2")

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

    add_finding_or_investigation_note_4(container=container)

    return


@phantom.playbook_block()
def file_screenshot_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("file_screenshot_formatting() called")

    get_job_summary_1_result_data = phantom.collect2(container=container, datapath=["get_job_summary_1:action_result.data.*.Parameters.*.Value","get_job_summary_1:action_result.parameter.job_id"], action_results=results)
    get_job_screenshots_1_result_data = phantom.collect2(container=container, datapath=["get_job_screenshots_1:action_result.parameter.job_id","get_job_screenshots_1:action_result.data.*.file_name","get_job_screenshots_1:action_result.data.*.id"], action_results=results)

    get_job_summary_1_result_item_0 = [item[0] for item in get_job_summary_1_result_data]
    get_job_summary_1_parameter_job_id = [item[1] for item in get_job_summary_1_result_data]
    get_job_screenshots_1_parameter_job_id = [item[0] for item in get_job_screenshots_1_result_data]
    get_job_screenshots_1_result_item_1 = [item[1] for item in get_job_screenshots_1_result_data]
    get_job_screenshots_1_result_item_2 = [item[2] for item in get_job_screenshots_1_result_data]

    file_screenshot_formatting__report = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    file_screenshot_formatting__report = ""
    
    for file, job_id in zip(get_job_summary_1_result_item_0, get_job_summary_1_parameter_job_id):
        file_screenshot_formatting__report += f"#### {file}\n"
        for screenshot_job, screenshot_name, screenshot_id in zip(get_job_screenshots_1_parameter_job_id, get_job_screenshots_1_result_item_1, get_job_screenshots_1_result_item_2):
            if job_id == screenshot_job:
                file_screenshot_formatting__report += f"![{screenshot_name}](/view?id={screenshot_id})\n"

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="file_screenshot_formatting__inputs:0:get_job_summary_1:action_result.data.*.Parameters.*.Value", value=json.dumps(get_job_summary_1_result_item_0))
    phantom.save_block_result(key="file_screenshot_formatting__inputs:1:get_job_summary_1:action_result.parameter.job_id", value=json.dumps(get_job_summary_1_parameter_job_id))
    phantom.save_block_result(key="file_screenshot_formatting__inputs:2:get_job_screenshots_1:action_result.parameter.job_id", value=json.dumps(get_job_screenshots_1_parameter_job_id))
    phantom.save_block_result(key="file_screenshot_formatting__inputs:3:get_job_screenshots_1:action_result.data.*.file_name", value=json.dumps(get_job_screenshots_1_result_item_1))
    phantom.save_block_result(key="file_screenshot_formatting__inputs:4:get_job_screenshots_1:action_result.data.*.id", value=json.dumps(get_job_screenshots_1_result_item_2))

    phantom.save_block_result(key="file_screenshot_formatting:report", value=json.dumps(file_screenshot_formatting__report))

    format_summary_report(container=container)

    return


@phantom.playbook_block()
def add_finding_or_investigation_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_finding_or_investigation_note_4() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.finding_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    format_summary_report = phantom.get_format_data(name="format_summary_report")

    parameters = []

    # build parameters list for 'add_finding_or_investigation_note_4' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None and format_summary_report is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
                "title": "Splunk Attack Analyzer Report",
                "content": format_summary_report,
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

    get_job_screenshots_1_result_data = phantom.collect2(container=container, datapath=["get_job_screenshots_1:action_result.data.*.file_name","get_job_screenshots_1:action_result.parameter.context.artifact_id"], action_results=results)

    get_job_screenshots_1_result_item_0 = [item[0] for item in get_job_screenshots_1_result_data]

    parameters = []

    parameters.append({
        "input_1": get_job_screenshots_1_result_item_0,
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