"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_screenshot_1' block
    get_screenshot_1(container=container)

    return

@phantom.playbook_block()
def get_screenshot_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_screenshot_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:consolidated_findings.url"])

    parameters = []

    # build parameters list for 'get_screenshot_1' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None:
            parameters.append({
                "url": finding_data_item[0],
                "delay": 200,
                "filename": "screenshot",
                "dimension": "1024xfull",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get screenshot", parameters=parameters, name="get_screenshot_1", assets=["screenshotmachine"], callback=image_base64)

    return


@phantom.playbook_block()
def image_base64(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("image_base64() called")

    get_screenshot_1_result_data = phantom.collect2(container=container, datapath=["get_screenshot_1:action_result.summary.vault_file_path"], action_results=results)

    get_screenshot_1_summary_vault_file_path = [item[0] for item in get_screenshot_1_result_data]

    image_base64__image_base64 = None
    image_base64__status = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import base64
    
    try:            
        image_path = get_screenshot_1_summary_vault_file_path[0]
        phantom.debug(image_path)            
        with open(image_path, "rb") as image_file:        
            encoded_string = base64.b64encode(image_file.read()).decode('utf-8')                
        image_base64__image_base64 = encoded_string
        image_base64__status = "success"
        phantom.debug(image_base64__image_base64)            
        phantom.debug(image_base64__status)
    except:
        image_base64__status = "failed"
        phantom.debug(image_base64__status)                
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="image_base64__inputs:0:get_screenshot_1:action_result.summary.vault_file_path", value=json.dumps(get_screenshot_1_summary_vault_file_path))

    phantom.save_block_result(key="image_base64:image_base64", value=json.dumps(image_base64__image_base64))
    phantom.save_block_result(key="image_base64:status", value=json.dumps(image_base64__status))

    decision_1(container=container)

    return


@phantom.playbook_block()
def add_investigation_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_investigation_file_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:id"])
    image_base64__image_base64 = json.loads(_ if (_ := phantom.get_run_data(key="image_base64:image_base64")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'add_investigation_file_1' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None and image_base64__image_base64 is not None:
            parameters.append({
                "id": finding_data_item[0],
                "data": image_base64__image_base64,
                "file_name": "screenshot",
                "source_type": "Note",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add investigation file", parameters=parameters, name="add_investigation_file_1", assets=["builtin_mc_connector"], callback=format_file)

    return


@phantom.playbook_block()
def add_finding_or_investigation_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_finding_or_investigation_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:id"])
    format_file = phantom.get_format_data(name="format_file")

    parameters = []

    # build parameters list for 'add_finding_or_investigation_note_2' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None and format_file is not None:
            parameters.append({
                "id": finding_data_item[0],
                "files": [
                ],
                "title": "Notes go here ...",
                "content": format_file,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add finding or investigation note", parameters=parameters, name="add_finding_or_investigation_note_2", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def format_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_file() called")

    template = """![python.org.jpg](/en-US/splunkd/__raw/servicesNS/nobody/missioncontrol/v1/incidents/{0}/files/{1}/download)"""

    # parameter list for template variable replacement
    parameters = [
        "finding:id",
        "add_investigation_file_1:action_result.data.*.id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file")

    add_finding_or_investigation_note_2(container=container)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["image_base64:custom_function:status", "==", "success"]
        ],
        conditions_dps=[
            ["image_base64:custom_function:status", "==", "success"]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_investigation_file_1(action=action, success=success, container=container, results=results, handle=handle)
        return

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