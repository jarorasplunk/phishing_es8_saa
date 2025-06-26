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

    playbook_input_investigation_id = phantom.collect2(container=container, datapath=["playbook_input:investigation_id"])

    parameters = []

    # build parameters list for 'get_finding_or_investigation_1' call
    for playbook_input_investigation_id_item in playbook_input_investigation_id:
        if playbook_input_investigation_id_item[0] is not None:
            parameters.append({
                "id": playbook_input_investigation_id_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=vault_list_2)

    return


@phantom.playbook_block()
def vault_list_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("vault_list_2() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "container_id": id_value,
        "vault_id": None,
        "file_name": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/vault_list", parameters=parameters, name="vault_list_2")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    id_value = container.get("id", None)
    vault_list_2__result = phantom.collect2(container=container, datapath=["vault_list_2:custom_function_result.data.path"])

    vault_list_2_data_path = [item[0] for item in vault_list_2__result]

    output = {
        "container": id_value,
        "vault_location": vault_list_2_data_path,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return