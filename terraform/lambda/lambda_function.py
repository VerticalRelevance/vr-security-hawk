import base64
import json

print('Loading function')

def flatten_json(y):
    out = {}
 
    def flatten(x, name=''):
 
        # If the Nested key-value
        # pair is of dict type
        if type(x) is dict:
 
            for a in x:
                flatten(x[a], name + a + '_')
 
        # If the Nested key-value
        # pair is of list type
        elif type(x) is list:
 
            i = 0
 
            for a in x:
                flatten(a, name + str(i) + '_')
                i += 1
        else:
            out[name[:-1]] = x
 
    flatten(y)
    return out

def lambda_handler(event, context):

    output = []
    
    wanted_keys = [
        "AwsAccountId",
        "CreatedAt",
        "Description",
        "Resources_0_Id",
        "Resources_0_Type",
        "Resources_0_Region",
        "FindingProviderFields_Severity_Label",
        "Title",
        "UpdatedAt",
        "Compliance_Status",
        "LastObservedAt",
        "Workflow_Status",
        "FirstObservedAt"
    ]

    for record in event['records']:
        payload = base64.b64decode(record['data']).decode('utf-8')
        
        data = json.loads(payload)
        
        finding = data['detail']['findings'][0]
        finding_id = finding["Id"].split('/')[-1]

        flat_dict = flatten_json(finding)
        print(flat_dict)
        
        trimmed_dict = {k:v for k, v in flat_dict.items() if k in wanted_keys}
        # changing keys of dictionary
        trimmed_dict['Resource_Id'] = trimmed_dict.pop('Resources_0_Id') 
        trimmed_dict['Region'] = trimmed_dict.pop('Resources_0_Region') 
        trimmed_dict['Resource_Type'] = trimmed_dict.pop('Resources_0_Type')
        trimmed_dict['Severity_Label'] = trimmed_dict.pop('FindingProviderFields_Severity_Label')
        trimmed_dict["Id"] = finding_id

        trimmed_str = json.dumps(trimmed_dict) + "\n" # New line is crucial for parsing data
        
        output_record = {
            'recordId': record['recordId'],
            'result': 'Ok',
            'data': base64.b64encode(trimmed_str.encode('utf-8')).decode('utf-8')
        }
        output.append(output_record)

    print('Successfully processed {} records.'.format(len(event['records'])))

    return {'records': output}
