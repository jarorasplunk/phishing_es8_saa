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

    phantom.act("get job summary", parameters=parameters, name="get_job_summary_1", assets=["saa"], callback=get_job_forensics_1)

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

    phantom.act("get job forensics", parameters=parameters, name="get_job_forensics_1", assets=["saa"], callback=get_job_screenshots_1)

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

    phantom.act("get job screenshots", parameters=parameters, name="get_job_screenshots_1", assets=["saa"], callback=playbook_get_container_id_and_vault_list_1)

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
def image_base64(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("image_base64() called")

    playbook_get_container_id_and_vault_list_1_output_vault_location = phantom.collect2(container=container, datapath=["playbook_get_container_id_and_vault_list_1:playbook_output:vault_location"])

    playbook_get_container_id_and_vault_list_1_output_vault_location_values = [item[0] for item in playbook_get_container_id_and_vault_list_1_output_vault_location]

    image_base64__image_base64 = None
    image_base64__status = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    SomeException = str()
    image_base64__image_base64 = []
    image_base64__status = []
    import base64
    phantom.debug(type(playbook_get_container_id_and_vault_list_1_output_vault_location_values))
    phantom.debug(playbook_get_container_id_and_vault_list_1_output_vault_location_values)
    for i in range(len(playbook_get_container_id_and_vault_list_1_output_vault_location_values)):
        image_path = playbook_get_container_id_and_vault_list_1_output_vault_location_values[i]
        if open(image_path, "rb"):
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

    phantom.save_block_result(key="image_base64__inputs:0:playbook_get_container_id_and_vault_list_1:playbook_output:vault_location", value=json.dumps(playbook_get_container_id_and_vault_list_1_output_vault_location_values))

    phantom.save_block_result(key="image_base64:image_base64", value=json.dumps(image_base64__image_base64))
    phantom.save_block_result(key="image_base64:status", value=json.dumps(image_base64__status))

    add_investigation_file_2(container=container)

    return


@phantom.playbook_block()
def add_investigation_file_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_investigation_file_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    image_base64__image_base64 = json.loads(_ if (_ := phantom.get_run_data(key="image_base64:image_base64")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'add_investigation_file_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None and image_base64__image_base64 is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
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

    phantom.act("add investigation file", parameters=parameters, name="add_investigation_file_2", assets=["builtin_mc_connector"], callback=normalized_file_summary_output)

    return


@phantom.playbook_block()
def add_finding_or_investigation_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_finding_or_investigation_note_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    format_file_report = phantom.get_format_data(name="format_file_report")

    parameters = []

    # build parameters list for 'add_finding_or_investigation_note_3' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None and format_file_report is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
                "files": [
                ],
                "title": "Splunk Attack Analyzer Report",
                "content": format_file_report,
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
def normalized_file_summary_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("normalized_file_summary_output() called")

    get_job_summary_1_result_data = phantom.collect2(container=container, datapath=["get_job_summary_1:action_result.data.*.Submission.Name","get_job_summary_1:action_result.data.*.ID","get_job_summary_1:action_result.parameter.job_id","get_job_summary_1:action_result.summary.Score","get_job_summary_1:action_result.data.*.Resources","get_job_summary_1:action_result.data.*.Verdict","get_job_summary_1:action_result.data.*.Tasks"], action_results=results)

    get_job_summary_1_result_item_0 = [item[0] for item in get_job_summary_1_result_data]
    get_job_summary_1_result_item_1 = [item[1] for item in get_job_summary_1_result_data]
    get_job_summary_1_parameter_job_id = [item[2] for item in get_job_summary_1_result_data]
    get_job_summary_1_summary_score = [item[3] for item in get_job_summary_1_result_data]
    get_job_summary_1_result_item_4 = [item[4] for item in get_job_summary_1_result_data]
    get_job_summary_1_result_item_5 = [item[5] for item in get_job_summary_1_result_data]
    get_job_summary_1_result_item_6 = [item[6] for item in get_job_summary_1_result_data]

    normalized_file_summary_output__file_score_object = None
    normalized_file_summary_output__scores = None
    normalized_file_summary_output__categories = None
    normalized_file_summary_output__score_id = None
    normalized_file_summary_output__file = None
    normalized_file_summary_output__job_id = None
    normalized_file_summary_output__classifications = None
    normalized_file_summary_output__file_name = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(get_job_summary_1_result_item_0)
    phantom.debug(get_job_summary_1_result_item_1)
    phantom.debug(get_job_summary_1_parameter_job_id)
    phantom.debug(get_job_summary_1_summary_score)
    phantom.debug(get_job_summary_1_result_item_4)
    phantom.debug(get_job_summary_1_result_item_5)
    phantom.debug(get_job_summary_1_result_item_6)
    
    score_table = {
        "0":"Unknown",
        "1":"Very_Safe",
        "2":"Safe",
        "3":"Probably_Safe",
        "4":"Leans_Safe",
        "5":"May_not_be_Safe",
        "6":"Exercise_Caution",
        "7":"Suspicious_or_Risky",
        "8":"Possibly_Malicious",
        "9":"Probably_Malicious",
        "10":"Malicious"
    }

    classification_ids = {
        "Unknown": 0,
        "Adware": 1,
        "Backdoor": 2,
        "Bot": 3,
        "Bootkit": 4,
        "DDOS": 5,
        "Downloader": 6,
        "Dropper": 7,
        "Exploit-Kit": 8,
        "Keylogger": 9,
        "Ransomware": 10,
        "Remote-Access-Trojan": 11,
        "Resource-Exploitation": 13,
        "Rogue-Security-Software": 14,
        "Rootkit": 15,
        "Screen-Capture": 16,
        "Spyware": 17,
        "Trojan": 18,
        "Virus": 19,
        "Webshell": 20,
        "Wiper": 21,
        "Worm": 22,
        "Other": 99
    }

    normalized_file_summary_output__file_score_object = []
    normalized_file_summary_output__scores = []
    normalized_file_summary_output__categories = []
    normalized_file_summary_output__score_id = []
    normalized_file_summary_output__file = []
    normalized_file_summary_output__job_id = []
    normalized_file_summary_output__classifications = []
    normalized_file_summary_output__file_name = []
    
    
    def find_sha1_details(target_id, task_list):
        '''
        Attempt to find the detail object with a sha1
        '''
        for task in task_list:
            if (target_id == task.get('ResourceID')
                and task.get('Results',{}).get('Details', {}).get('sha1')):
                task_result_details = task['Results']['Details']
                task_result_details.pop('RootTaskID', None)
                return task_result_details
        return None

        
    ## pair forensic job results with url detonated
    job_file_dict = {}
    for orig_file, orig_job, filtered_job in zip(get_job_summary_1_result_item_0, get_job_summary_1_result_item_1, get_job_summary_1_parameter_job_id):
        if orig_job == filtered_job:
            job_file_dict[filtered_job] = orig_file
    
    for job, file_name, score_num, resources, verdict, tasks in zip(
        get_job_summary_1_parameter_job_id, 
        get_job_summary_1_result_item_0, 
        get_job_summary_1_summary_score, 
        get_job_summary_1_result_item_4, 
        get_job_summary_1_result_item_5,
        get_job_summary_1_result_item_6
    ):
        
        ## translate scores
        score_id = int(score_num/10) if score_num > 0 else 0
        score = score_table[str(score_id)]
        file = job_file_dict[job]
        attributes = {}
        
        ## build.a sub dictionary of high priority related observables
        related_observables = []
        for sub_observ in resources:
            if sub_observ['Name'] != file_name:
                        
                details = find_sha1_details(sub_observ['ID'], tasks)
                second_num = sub_observ['DisplayScore']
                second_num_id = int(second_num/10) if second_num > 0 else 0
                sub_observ_dict = {
                    'value': sub_observ['Name'],
                    'type': sub_observ['Type'].lower(),
                    'reputation': {
                        'score': score_table[str(second_num_id)],
                        'orig_score': second_num,
                        'score_id': second_num_id
                    },
                    'source': 'Splunk Attack Analyzer'
                }
                if details:
                    details['name'] = sub_observ['Name']
                    details.pop('exiftool', None)
                    sub_observ_dict['attributes'] = details
                # check if observ is already in related_observables
                skip_observ = False
                for idx, item in enumerate(related_observables):
                    if (sub_observ.get('FileMetadata', {}).get('SHA256', 'null_one') 
                        == item.get('attributes', {}).get('sha256', 'null_two')
                        and sub_observ['DisplayScore'] > item['reputation']['orig_score']):
                        related_observables[idx] = sub_observ_dict
                        skip_observ = True
                    elif sub_observ['Name'] == item['value']:
                        skip_observ = True
                if not skip_observ:
                    related_observables.append(sub_observ_dict)
            elif sub_observ['Name'] == file_name:
                details = find_sha1_details(sub_observ['ID'], tasks)
                if details:
                    details.pop('exiftool', None)
                    details['name'] = file_name
                    attributes = details
                else:
                    file_metadata = sub_observ.get('FileMetadata', {})
                    attributes = {
                        'name': file_name,
                        'sha256': file_metadata.get('SHA256'),
                        'md5': file_metadata.get('MD5'),
                        'size': file_metadata.get('Size')
                    }
                    if file_metadata.get('MimeType'):
                        attributes['mime_type'] = file_metadata['MimeType']
        
        normalized_file_summary_output__file_score_object.append({
            'value': file, 
            'orig_score': score_num, 
            'score': score, 
            'score_id': score_id, 
            'classifications': [verdict if verdict else "Unknown"],
            'classification_ids': [classification_ids.get(verdict, 99) if verdict else 0],
            'related_observables': related_observables,
            'attributes': attributes
                
        })
        normalized_file_summary_output__scores.append(score)
        normalized_file_summary_output__score_id.append(score_id)
        normalized_file_summary_output__file.append(file)
        normalized_file_summary_output__file_name.append(file_name)
        normalized_file_summary_output__job_id.append(job)
        normalized_file_summary_output__classifications.append([verdict if verdict else "Unknown"])
    
    phantom.debug(normalized_file_summary_output__scores)
    phantom.debug(normalized_file_summary_output__score_id)
    phantom.debug(normalized_file_summary_output__file)
    phantom.debug(normalized_file_summary_output__file_name)
    phantom.debug(normalized_file_summary_output__job_id)
    phantom.debug(normalized_file_summary_output__classifications)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="normalized_file_summary_output__inputs:0:get_job_summary_1:action_result.data.*.Submission.Name", value=json.dumps(get_job_summary_1_result_item_0))
    phantom.save_block_result(key="normalized_file_summary_output__inputs:1:get_job_summary_1:action_result.data.*.ID", value=json.dumps(get_job_summary_1_result_item_1))
    phantom.save_block_result(key="normalized_file_summary_output__inputs:2:get_job_summary_1:action_result.parameter.job_id", value=json.dumps(get_job_summary_1_parameter_job_id))
    phantom.save_block_result(key="normalized_file_summary_output__inputs:3:get_job_summary_1:action_result.data.*.Submission.Name", value=json.dumps(get_job_summary_1_result_item_0))
    phantom.save_block_result(key="normalized_file_summary_output__inputs:4:get_job_summary_1:action_result.summary.Score", value=json.dumps(get_job_summary_1_summary_score))
    phantom.save_block_result(key="normalized_file_summary_output__inputs:5:get_job_summary_1:action_result.data.*.Resources", value=json.dumps(get_job_summary_1_result_item_4))
    phantom.save_block_result(key="normalized_file_summary_output__inputs:6:get_job_summary_1:action_result.data.*.Verdict", value=json.dumps(get_job_summary_1_result_item_5))
    phantom.save_block_result(key="normalized_file_summary_output__inputs:7:get_job_summary_1:action_result.data.*.Tasks", value=json.dumps(get_job_summary_1_result_item_6))

    phantom.save_block_result(key="normalized_file_summary_output:file_score_object", value=json.dumps(normalized_file_summary_output__file_score_object))
    phantom.save_block_result(key="normalized_file_summary_output:scores", value=json.dumps(normalized_file_summary_output__scores))
    phantom.save_block_result(key="normalized_file_summary_output:categories", value=json.dumps(normalized_file_summary_output__categories))
    phantom.save_block_result(key="normalized_file_summary_output:score_id", value=json.dumps(normalized_file_summary_output__score_id))
    phantom.save_block_result(key="normalized_file_summary_output:file", value=json.dumps(normalized_file_summary_output__file))
    phantom.save_block_result(key="normalized_file_summary_output:job_id", value=json.dumps(normalized_file_summary_output__job_id))
    phantom.save_block_result(key="normalized_file_summary_output:classifications", value=json.dumps(normalized_file_summary_output__classifications))
    phantom.save_block_result(key="normalized_file_summary_output:file_name", value=json.dumps(normalized_file_summary_output__file_name))
    
    format_file_report(container=container)

    return

@phantom.playbook_block()
def format_file_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_file_report() called")

    template = """The table below shows a summary of the information gathered by Splunk Attack Analyzer:\n\n| File Name | Normalized Score | Score Id  | Classifications | Report Link | Source |\n| --- | --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | {3} | {5} | Splunk Attack Analyzer (SAA) |\n%%\n\nScreenshots associated with the detonated Files are attached in the \"Files\" section below.\n"""

    # parameter list for template variable replacement
    parameters = [
        "normalized_file_summary_output:custom_function:file_name",
        "normalized_file_summary_output:custom_function:scores",
        "normalized_file_summary_output:custom_function:score_id",
        "normalized_file_summary_output:custom_function:classifications",
        "normalized_file_summary_output:custom_function:job_id",
        "get_job_summary_1:action_result.summary.AppURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_report")

    add_finding_or_investigation_note_3(container=container)

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
def playbook_get_container_id_and_vault_list_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_get_container_id_and_vault_list_1() called")

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id"], action_results=results)

    get_finding_or_investigation_1_result_item_0 = [item[0] for item in get_finding_or_investigation_1_result_data]

    inputs = {
        "investigation_id": get_finding_or_investigation_1_result_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "phishing_es8_saa/get container id and vault list", returns the playbook_run_id
    playbook_run_id = phantom.playbook("phishing_es8_saa/get container id and vault list", container=container, name="playbook_get_container_id_and_vault_list_1", callback=image_base64, inputs=inputs)

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