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

    filtered_result_0_data_filter_saa_jobid = phantom.collect2(container=container, datapath=["filtered-data:filter_saa_jobid:condition_1:get_finding_or_investigation_1:action_result.data.*.consolidated_findings.SAA_JOB_ID"])

    parameters = []

    # build parameters list for 'get_job_summary_1' call
    for filtered_result_0_item_filter_saa_jobid in filtered_result_0_data_filter_saa_jobid:
        if filtered_result_0_item_filter_saa_jobid[0] is not None:
            parameters.append({
                "job_id": filtered_result_0_item_filter_saa_jobid[0],
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

    filtered_result_0_data_filter_saa_jobid = phantom.collect2(container=container, datapath=["filtered-data:filter_saa_jobid:condition_1:get_finding_or_investigation_1:action_result.data.*.consolidated_findings.SAA_JOB_ID"])

    parameters = []

    # build parameters list for 'get_job_forensics_1' call
    for filtered_result_0_item_filter_saa_jobid in filtered_result_0_data_filter_saa_jobid:
        if filtered_result_0_item_filter_saa_jobid[0] is not None:
            parameters.append({
                "job_id": filtered_result_0_item_filter_saa_jobid[0],
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

    filtered_result_0_data_filter_saa_jobid = phantom.collect2(container=container, datapath=["filtered-data:filter_saa_jobid:condition_1:get_finding_or_investigation_1:action_result.data.*.consolidated_findings.SAA_JOB_ID"])

    parameters = []

    # build parameters list for 'get_job_screenshots_1' call
    for filtered_result_0_item_filter_saa_jobid in filtered_result_0_data_filter_saa_jobid:
        if filtered_result_0_item_filter_saa_jobid[0] is not None:
            parameters.append({
                "job_id": filtered_result_0_item_filter_saa_jobid[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get job screenshots", parameters=parameters, name="get_job_screenshots_1", assets=["splunk_attack_analyzer"])

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