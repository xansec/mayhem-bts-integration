import argparse
import os
import sys
import requests
import csv
import datetime as dt
import json
import logging
import subprocess
import base64
import uuid
from enum import Enum, auto
from requests.auth import HTTPBasicAuth

def testAPI(url, headers):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    logging.info('Testing API connection...')
    try:
        session.request('GET', url + '/api/', headers=headers)
    except requests.exceptions.SSLError as e:
        logging.error('SSL error. Try running with --insecure or adding the invalid cert to your keystore.')
        logging.error(e)
        sys.exit(1)
    except BaseException as e:
        logging.error('Error validating API. Check your Mayhem url or token.')
        logging.error(e)
        sys.exit(1)
    return

def getTestcaseReport(api, headers, workspace, project, target, defect_id):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    base = api['mayhem']['url'] + '/api/v2/owner/' + workspace + '/project/' + project + '/target/' + target
    endpoint = base + '/defect/' + defect_id + '/testcase_report?per_page=10'
    try:
        response = session.request('GET', endpoint, headers=headers)
        result = response.json()
        if 'message' in result:
            raise ValueError(result['message'])
    except ValueError as e:
        logging.error('Error getting testcase report.')
        logging.error(e)
        sys.exit(1)
    except BaseException as e:
        logging.error('Error getting testcase report.')
        logging.error(e)
        sys.exit(1)
    if result['count'] == 0:
        logging.warn('No testcase reports found for defect ' + str(defect_id))
        return None
    return result['testcase_reports']

def getDefect(api, headers, workspace, project, target, defect_id):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    base = api['mayhem']['url'] + '/api/v2/owner/' + workspace + '/project/' + project + '/target/' + target
    endpoint = base + '/defect/' + defect_id
    try:
        response = session.request('GET', endpoint, headers=headers)
        result = response.json()
        if 'message' in result:
            raise ValueError(result['message'])
    except ValueError as e:
        logging.error('Error getting defect.')
        logging.error(e)
        sys.exit(1)
    except BaseException as e:
        logging.error('Error getting defect.')
        logging.error(e)
        sys.exit(1)
    testcase_reports = getTestcaseReport(api, headers, workspace, project, target, defect_id)
    if testcase_reports:
        result['examples'] = testcase_reports
    return [result]

def getDefectsForRun(api, headers, workspace, project, target, run_id, severity=None, offset=0):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    base = api['mayhem']['url'] + '/api/v2/owner/' + workspace + '/project/' + project + '/target/' + target
    endpoint = base + '/run/' + str(run_id) + '/defect?per_page=' + str(ELEMENTS) + '&offset=' + str(offset)
    if severity:
        endpoint = endpoint + '&severity=' + str(severity)
    try:
        response = session.request('GET', endpoint, headers=headers)
        results = response.json()
        if len(results['defects']) == ELEMENTS:
            results['defects'] += (getDefectsForRun(api, headers, workspace, project, target, run_id, severity, (offset + ELEMENTS)))
    except KeyError as e:
        logging.error('KeyError:' + str(e) + ', check your parameters.')
        sys.exit(1)
    return results['defects']

def getMapiIssue(api, headers, workspace, project, defect_id):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    base = api['mayhem']['url'] + '/api/v2/owner/' + workspace + '/project/' + project
    endpoint = base + '/api/rest/issue/' + defect_id
    try:
        response = session.request('GET', endpoint, headers=headers)
        result = response.json()
    except BaseException as e:
        logging.error('Error getting mapi defect.')
        logging.error(e)
        sys.exit(1)
    return result

def exportToJira(api, headers, issue_data, dry_run):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    endpoint = api['jira']['url'] + '/rest/api/2/issue/'
    auth = HTTPBasicAuth(api['jira']['username'], api['jira']['token'])
    if dry_run:
        logging.debug(issue_data)
        return endpoint
    else:
        try:
            response = session.request('POST', endpoint, headers=headers, json=issue_data, auth=auth)
            resp_dict = json.loads(response.text)
            print('Issue ' + str(resp_dict['key']) + ' created.')
        except KeyError as e:
            logging.error('Issue not created, check your permssions and parameters.')
            logging.error(e)
            logging.error(resp_dict)
            sys.exit(1)
    return api['jira']['url'] + '/browse/' + str(resp_dict['key'])

def exportToGitlab(api, headers, issue_data, dry_run):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    endpoint = api['gitlab']['url'] + '/api/v4/projects/' + str(api['gitlab']['project-id']) + '/issues/'
    if dry_run:
        logging.debug(issue_data)
        return endpoint
    else:
        try:
            response = session.request('POST', endpoint, headers=headers, json=issue_data)
            resp_dict = json.loads(response.text)
            print('Issue ' + str(resp_dict['iid']) + ' created.')
        except KeyError as e:
            logging.error('Issue not created, check your permssions and parameters.')
            logging.error(e)
            logging.error(resp_dict)
            sys.exit(1)
    return resp_dict['web_url']

def exportToAzure(api, headers, issue_data, dry_run):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    endpoint = api['azure']['url'] + '/' + str(api['azure']['organization']) + '/' + str(api['azure']['project']) + '/_apis/wit/workitems/$' + str(api['azure']['type']) + '?api-version=' + str(api['azure']['api-version'])
    auth = ('', api['azure']['token'])
    if dry_run:
        logging.debug(issue_data)
        return endpoint
    else:
        try:
            response = session.request('POST', endpoint, headers=headers, json=issue_data, auth=auth)
            resp_dict = json.loads(response.text)
            print('Issue ' + str(resp_dict['id']) + ' created.')
        except KeyError as e:
            logging.error('Issue not created, check your permssions and parameters.')
            logging.error(e)
            logging.error(resp_dict)
            sys.exit(1)
    return api['azure']['url'] + '/' + api['azure']['organization'] + '/' + api['azure']['project'] + '/_workitems/edit/' + str(resp_dict['id'])

def exportToSentry(api, headers, issue_data, dry_run):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    endpoint = api['sentry']['url'] + '/api/' + str(api['sentry']['project-id']) + '/envelope/'
    if dry_run:
        logging.debug(issue_data)
        return endpoint
    else:
        try:
            response = session.request('POST', endpoint, headers=headers, data=issue_data)
            resp_dict = json.loads(response.text)
            print('Issue ' + str(resp_dict['id']) + ' created.')
        except KeyError as e:
            logging.error('Issue not created, check your permssions and parameters.')
            logging.error(e)
            logging.error(resp_dict)
            sys.exit(1)
    return resp_dict['id']

#this endpoint also creates the ticket, should just combine with createJira
# def updateMayhem(api, headers, workspace, project, target, defect_id, jira_url, jira_id):
#     logging.debug('Entering ' + sys._getframe().f_code.co_name)
#     endpoint = api['mayhem']['url'] + '/api/v2/owner/' + workspace + '/project/' + project + '/target/' + target + '/defect/' + defect_id + '/jira-issue'
#     issue_data = '{ "jira_issue_id": "' + str(jira_id) + '", "jira_issue_url": "' + str(jira_url) + '" }'
#     if dry_run:
#         logging.debug(issue_data)
#         return endpoint
#     else:
#         try:
#             response = session.request('POST', endpoint, headers=headers, json=issue_data)
#         except KeyError as e:
#             logging.error('Issue not created, check your permssions and parameters.')
#             logging.error(e)
#             sys.exit(1)
#     return

OFFSET = 0
ELEMENTS = 20
# --todo-- Add additional fields as needed here

JIRA_FORMAT = '''
{
    "fields": {
        "project":{
            "key": ""
        },
        "summary": "",
        "description": "",
        "issuetype": {
            "name": ""
        }
    }
}
'''

GITLAB_FORMAT = '''
{
    "title": "",
    "description": ""
}
'''

AZURE_FORMAT = '''
[
    {
        "op": "add",
        "path": "/fields/System.Title",
        "from": null,
        "value": ""
    },
    {
        "op": "add",
        "path": "/fields/System.Description",
        "from": null,
        "value": ""
    }
]
'''

SENTRY_FORMAT = '''
[
    {
        "event_id": "",
        "sent_at": "",
        "dsn": ""
    },
    {   
        "type": "event"
    },
    {
        "exception": {
            "values": [
                {
                    "type": "Mayhem Defect",
                    "value":"",
                    "mechanism": {
                        "type": "",
                        "description": "",
                        "exception_id": ""
                    },
                    "stacktrace": {}
                }
            ]
        }
    }
]
'''

if __name__ == '__main__':

    if(sys.version_info.major < 3):
        print('Please use Python 3.x or higher')
        sys.exit(1)

    parser = argparse.ArgumentParser()

    parser.add_argument('--workspace', required=True, type=str, help='The workspace for the project')
    parser.add_argument('--project', required=True, type=str, help='The name of the project')
    parser.add_argument('--target', required=True, type=str, help='The name of the target')
    parser.add_argument('--bts', required=True, type=str, help='The type of BTS you want to export to (choices: \'jira\', \'gitlab\', \'azure\', \'sentry\')')
    parser.add_argument('--defect', type=str, help='The defect number to export (exports a single defect)')
    parser.add_argument('--run', type=str, help='The run number to export (exports all defects in a run)')
    parser.add_argument('--severity', type=str, help='Severity level to export (i.e. "high"; defaults to all defects)')
    parser.add_argument('--output-csv', action='store_true', help='Output results in CSV format instead')
    parser.add_argument('--bts-config', type=str, default='bts.config', help='The BTS configuration file (defaults to \'bts.config\')')
    parser.add_argument('--mayhem-config', type=str, default='mayhem.config', help='The Mayhem configuration file (defaults to \'mayhem.config\')')
    parser.add_argument('--use-pass', action='store_true', help='Use CLI credential tool to retrieve secret instead of hardcoded tokens')
    parser.add_argument('--log', type=str, default='warn', help='Log level (choose from debug, info, warning, error and critical)')
    parser.add_argument('--insecure', action='store_true', help='Ignore SSL certificate errors')
    parser.add_argument('--dry-run', action='store_true', help='Dry run')



    args = parser.parse_args()


    levels = {
        'critical': logging.CRITICAL,
        'error': logging.ERROR,
        'warn': logging.WARNING,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG
    }

    class BTS(Enum):
        jira = auto()
        gitlab = auto()
        azure = auto()
        sentry = auto()

    session = requests.Session()
    if args.insecure:
        logging.warning('Setting urllib3 session to ignore insecure connections.')
        session.verify = False
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    loglevel = args.log.lower() if (args.log.lower() in levels) else 'warn'
    logging.basicConfig(stream=sys.stderr, level=levels[loglevel], format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    workspace = args.workspace
    project = args.project
    target = args.target
    bts_config = args.bts_config
    mayhem_config = args.mayhem_config
    use_pass = args.use_pass
    dry_run = args.dry_run
    output_csv = args.output_csv
    severity = args.severity
    if args.bts in BTS.__members__:
        bts = BTS[args.bts]
    else:
        print('You must provide a BTS type with the --bts flag (choices: \'jira\', \'gitlab\', \'azure\', \'sentry\')')
        print(parser.print_help())
        sys.exit(1)

    with open(bts_config, 'r') as config_file:
        config_data = config_file.read()
    bts_api = json.loads(config_data)
    if use_pass:
        token_name = bts_api[bts.name]['token']
        cmd = ["op", "item", "get", token_name, "--format", "json", "--fields", "password"]
        op_output = subprocess.check_output(cmd).strip().decode('utf-8')
        bts_api[bts.name]['token'] = json.loads(op_output)['value'].strip()
    bts_headers = {
        'Content-Type': 'application/json'
    }

    with open(mayhem_config, 'r') as config_file:
        config_data = config_file.read()
    mayhem_api = json.loads(config_data)
    if use_pass:
        token_name = mayhem_api['mayhem']['token']
        cmd = ["op", "item", "get", token_name, "--format", "json", "--fields", "password"]
        op_output = subprocess.check_output(cmd).strip().decode('utf-8')
        mayhem_api['mayhem']['token'] = json.loads(op_output)['value'].strip()
    mayhem_headers = {
        'Content-Type': 'application/json',
        'X-Mayhem-Token': ('token ' + mayhem_api['mayhem']['token'])
    }

    #Ensure API is correct
    testAPI(mayhem_api['mayhem']['url'], mayhem_headers)

    if output_csv:
        f = open('defects.csv', 'w', newline='')
        writer = csv.writer(f)
    if bts.name == 'jira':
        ticket = json.loads(JIRA_FORMAT)
        ticket['fields']['project']['key'] = bts_api['jira']['project-key']
        ticket['fields']['issuetype']['name'] = bts_api['jira']['issue-type']
        if output_csv:
            writer.writerow(['Project', 'Summary', 'Severity', 'Description'])
        if args.defect:
            defect_id = str(args.defect)
            defects = getDefect(mayhem_api, mayhem_headers, workspace, project, target, defect_id)
        elif args.run:
            run_id = str(args.run)
            defects = getDefectsForRun(mayhem_api, mayhem_headers, workspace, project, target, run_id, severity)
        else:
            print('Must provide either --defect <id> or --run <id>')
        for defect in defects:
            ticket['fields']['summary'] = '[Mayhem] ' + str(defect['defect_number']) + ' in ' + project +'/' + target + ': ' + str(defect['title'])
            ticket['fields']['description'] = str(defect['description']) + '\n\n' \
                + '*CWE*: ' + str(defect['cwe_number']) + ' ' + str(defect['cwe_link']) + '\n' \
                + '*Target*: ' + workspace + '/' + project + '/' + target + '\n' \
                + '*Discovered on*: ' + str(defect['created_at']) + '\n'
            if 'examples' in defect:
                if 'backtrace' in defect['examples'][0]:
                    ticket['fields']['description'] += '*Backtrace*: \n```\n' + str(defect['examples'][0]['backtrace']) + '```\n'
            if defect['type'] in ['mapi', 'zap']:
                mapiIssue = getMapiIssue(mayhem_api, mayhem_headers, workspace, project, str(defect['defect_number']))
                ticket['fields']['description'] += '*Error*: ' + str(mapiIssue['issue_rule_id']) + '\n'
                ticket['fields']['description'] += '*Endpoint*: ' + str(mapiIssue['method']) + ' ' + str(mapiIssue['path']) + '\n'
                ticket['fields']['description'] += '*Sample Request*: \n```\n ' + base64.b64decode(mapiIssue['request']).decode('utf-8') + ' ```\n'
                ticket['fields']['description'] += '*Sample Response*: \n```\n ' + base64.b64decode(mapiIssue['response']).decode('utf-8') + ' ```\n'
            # --todo-- Can set more fields here - example: severity
            if output_csv:
                writer.writerow([ticket['fields']['project']['key'], ticket['fields']['summary'], defect['severity'], ticket['fields']['description']])
            else:
                link = exportToJira(bts_api, bts_headers, ticket, dry_run)
                print('Link to newly created JIRA issue: ' + str(link))
                # --todo-- Update Mayhem
    if bts.name == 'gitlab':
        ticket = json.loads(GITLAB_FORMAT)
        bts_headers['PRIVATE-TOKEN'] = bts_api['gitlab']['token']
        if output_csv:
            writer.writerow(['Title', 'Description'])
        if args.defect:
            defect_id = str(args.defect)
            defects = getDefect(mayhem_api, mayhem_headers, defect_id)
        elif args.run:
            run_id = str(args.run)
            defects = getDefectsForRun(mayhem_api, mayhem_headers, run_id)
        else:
            print('Must provide either --defect <id> or --run <id>')
        for defect in defects:
            ticket['title'] = '[Mayhem] ' + str(defect['defect_number']) + ' in ' + project +'/' + target + ': ' + str(defect['title'])
            ticket['description'] = str(defect['description']) + '\n\n' \
                + '*CWE*: ' + str(defect['cwe_number']) + ' ' + str(defect['cwe_link']) + '\n' \
                + '*Target*: ' + workspace + '/' + project + '/' + target + '\n' \
                + '*Discovered on*: ' + str(defect['created_at']) + '\n'
            if 'examples' in defect:
                if 'backtrace' in defect['examples'][0]:
                    ticket['description'] += '*Backtrace*: \n```\n' + str(defect['examples'][0]['backtrace']) + '```\n'
            if defect['type'] in ['mapi', 'zap']:
                mapiIssue = getMapiIssue(mayhem_api, mayhem_headers, workspace, project, str(defect['defect_number']))
                ticket['description'] += '*Error*: ' + str(mapiIssue['issue_rule_id']) + '\n'
                ticket['description'] += '*Endpoint*: ' + str(mapiIssue['method']) + ' ' + str(mapiIssue['path']) + '\n'
                ticket['description'] += '*Sample Request*: \n```\n ' + base64.b64decode(mapiIssue['request']).decode('utf-8') + ' ```\n'
                ticket['description'] += '*Sample Response*: \n```\n ' + base64.b64decode(mapiIssue['response']).decode('utf-8') + ' ```\n'
            # --todo-- Can set more fields here
            if output_csv:
                writer.writerow([ticket['title'], ticket['description']])
            else:
                link = exportToGitlab(bts_api, bts_headers, ticket, dry_run)
                print('Link to newly created Gitlab issue: ' + str(link))
                # --todo-- Update Mayhem
    if bts.name == 'azure':
        ticket = json.loads(AZURE_FORMAT)
        bts_headers['Content-Type'] = 'application/json-patch+json'
        bts_headers['Authorization'] = 'Basic ' + base64.b64encode((bts_api['azure']['username'] + ':' + bts_api['azure']['token']).encode('utf-8')).decode('utf-8')
        if output_csv:
            writer.writerow(['Title', 'Description'])
        if args.defect:
            defect_id = str(args.defect)
            defects = getDefect(mayhem_api, mayhem_headers, workspace, project, target, defect_id)
        elif args.run:
            run_id = str(args.run)
            defects = getDefectsForRun(mayhem_api, mayhem_headers, workspace, project, target, run_id, severity)
        else:
            print('Must provide either --defect <id> or --run <id>')
        for defect in defects:
            ticket[0]['value'] = '[Mayhem] ' + str(defect['defect_number']) + ' in ' + project +'/' + target + ': ' + str(defect['title'])
            ticket[1]['value'] = str(defect['description']) + '<br><br>' \
                + '<b>CWE</b>: ' + str(defect['cwe_number']) + ' ' + str(defect['cwe_link']) + '<br>' \
                + '<b>Target</b>: ' + workspace + '/' + project + '/' + target + '<br>' \
                + '<b>Discovered on</b>: ' + str(defect['created_at']) + '<br>'
            if 'examples' in defect:
                if 'backtrace' in defect['examples'][0]:
                    ticket[1]['value'] += '<b>Backtrace</b>: <br><br><code>' + str(defect['examples'][0]['backtrace']) + '</code><br><br>'
            if defect['type'] in ['mapi', 'zap']:
                mapiIssue = getMapiIssue(mayhem_api, mayhem_headers, workspace, project, str(defect['defect_number']))
                ticket[1]['value'] += '<b>Error</b>: ' + str(mapiIssue['issue_rule_id']) + '<br>'
                ticket[1]['value'] += '<b>Endpoint</b>: ' + str(mapiIssue['method']) + ' ' + str(mapiIssue['path']) + '<br>'
                ticket[1]['value'] += '<b>Sample Request</b>: <br><br><code>' + base64.b64decode(mapiIssue['request']).decode('utf-8').replace('\n', '<br>') + '</code><br><br>'
                ticket[1]['value'] += '<b>Sample Response</b>: <br><br><code>' + base64.b64decode(mapiIssue['response']).decode('utf-8').replace('\n', '<br>') + '</code><br><br>'
            # --todo-- Can set more fields here
            if output_csv:
                writer.writerow([ticket[0]['value'], ticket[1]['value']])
            else:
                link = exportToAzure(bts_api, bts_headers, ticket, dry_run)
                print('Link to newly created Azure issue: ' + str(link))
    if bts.name == 'sentry':
        ticket = json.loads(SENTRY_FORMAT)
        bts_headers['Content-Type'] = 'application/x-sentry-envelope'
        bts_headers['X-Sentry-Auth'] = f'Sentry sentry_version={bts_api["sentry"]["version"]}, sentry_key={bts_api["sentry"]["public-key"]}, sentry_client=mayhem/1.0'
        if output_csv:
            writer.writerow(['Event ID', 'Exception Value', 'Description', 'Exception ID', 'Stacktrace'])
        if args.defect:
            defect_id = str(args.defect)
            defects = getDefect(mayhem_api, mayhem_headers, workspace, project, target, defect_id)
        elif args.run:
            run_id = str(args.run)
            defects = getDefectsForRun(mayhem_api, mayhem_headers, workspace, project, target, run_id, severity)
        else:
            print('Must provide either --defect <id> or --run <id>')
        for defect in defects:
            ticket[0]['event_id'] = uuid.uuid4().hex
            ticket[0]['sent_at'] = dt.datetime.now(dt.UTC).isoformat()
            ticket[0]['dsn'] = f'https://{bts_api["sentry"]["public-key"]}@{bts_api["sentry"]["dsn-id"]}.ingest.us.sentry.io/{bts_api["sentry"]["project-id"]}'
            ticket[2]['exception']['values'][0]['value'] = '[Mayhem] ' + str(defect['defect_number']) + ' in ' + project +'/' + target + ': ' + str(defect['title'])
            ticket[2]['exception']['values'][0]['mechanism']['type'] = bts_api['sentry']['mechanism-type']
            ticket[2]['exception']['values'][0]['mechanism']['description'] = str(defect['description']) + '\n\n' \
                + '*CWE*: ' + str(defect['cwe_number']) + ' ' + str(defect['cwe_link']) + '\n' \
                + '*Target*: ' + workspace + '/' + project + '/' + target + '\n' \
                + '*Discovered on*: ' + str(defect['created_at']) + '\n'
            ticket[2]['exception']['values'][0]['mechanism']['exception_id'] = str(defect['defect_number'])
            if 'examples' in defect:
                if 'parsed_backtrace' in defect['examples'][0]:
                    ticket[2]['exception']['values'][0]['stacktrace'] = {
                        "frames": []
                    }
                    for line in defect['examples'][0]['parsed_backtrace']:
                        ticket[2]['exception']['values'][0]['stacktrace']['frames'].append({
                            "filename": line['src'].split(':')[0] if line['src'] else '<unknown>',
                            "function": line['fn'] if line['fn'] else '<unknown>',
                            "lineno": line['src'].split(':')[1] if line['src'] else 0
                        })
            # --todo-- Can set more fields here
            if output_csv:
                writer.writerow([ticket[0]['event_id'], ticket[2]['exception']['values'][0]['value'], ticket[2]['exception']['values'][0]['mechanism']['description'], ticket[2]['exception']['values'][0]['mechanism']['exception_id'], json.dumps(ticket[2]['exception']['values'][0]['stacktrace'])])
            else:
                envelope = "\n".join(json.dumps(section) for section in ticket)
                event_id = exportToSentry(bts_api, bts_headers, envelope, dry_run)
                print('Sentry Event ID: ' + str(event_id))
    if output_csv:
        f.close()
        print('CSV file created: defects.csv')
    else:
        print('Export complete.')
            


