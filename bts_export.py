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
from enum import Enum, auto
from requests.auth import HTTPBasicAuth

def testAPI(url, headers):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    logging.info('Testing API connection...')
    try:
        session.request('GET', url + '/api', headers=headers)
    except requests.exceptions.SSLError as e:
        logging.error('SSL error. Try running with --insecure or adding the invalid cert to your keystore.')
        logging.error(e)
        sys.exit(1)
    except BaseException as e:
        logging.error('Error validating API. Check your Mayhem url or token.')
        logging.error(e)
        sys.exit(1)
    return

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
    return [result]

def getDefectsForRun(api, headers, workspace, project, target, run_id, offset=0):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    base = api['mayhem']['url'] + '/api/v2/owner/' + workspace + '/project/' + project + '/target/' + target
    endpoint = base + '/run/' + run_id + '/defect?per_page=' + str(ELEMENTS) + '&offset=' + str(offset)
    try:
        response = session.request('GET', endpoint, headers=headers)
        results = response.json()
        if len(results['defects']) == ELEMENTS:
            results['defects'].append(getDefectsForRun(api, headers, workspace, project, target, run_id, (offset + ELEMENTS)))
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

def updateMayhem(api, headers, workspace, project, target, defect_id, jira_url, jira_id):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    endpoint = api['mayhem']['url'] + '/api/v2/owner/' + workspace + '/project/' + project + '/target/' + target + '/defect/' + defect_id
    issue_data = '{ "jira_issue_id": "' + str(jira_id) + '", "jira_issue_url": "' + str(jira_url) + '" }'
    if dry_run:
        logging.debug(issue_data)
        return endpoint
    else:
        try:
            response = session.request('PUT', endpoint, headers=headers, json=issue_data, auth=auth)
        except KeyError as e:
            logging.error('Issue not created, check your permssions and parameters.')
            logging.error(e)
            sys.exit(1)
    return

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
            "name": "Bug"
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
if __name__ == '__main__':

    if(sys.version_info.major < 3):
        print('Please use Python 3.x or higher')
        sys.exit(1)

    parser = argparse.ArgumentParser()

    parser.add_argument('--workspace', required=True, type=str, help='The workspace for the project')
    parser.add_argument('--project', required=True, type=str, help='The name of the project')
    parser.add_argument('--target', required=True, type=str, help='The name of the target')
    parser.add_argument('--bts', required=True, type=str, help='The type of BTS you want to export to (choices: \'jira\', \'gitlab\')')
    parser.add_argument('--defect', type=str, help='The defect number to export (exports a single defect)')
    parser.add_argument('--run', type=str, help='The run number to export (exports all defects in a run)')
    parser.add_argument('--output-csv', action='store_true', help='Output results in CSV format instead')
    parser.add_argument('--bts-config', type=str, default='bts.config', help='The BTS configuration file (defaults to \'bts.config\')')
    parser.add_argument('--mayhem-config', type=str, default='mayhem.config', help='The Mayhem configuration file (defaults to \'mayhem.config\')')
    parser.add_argument('--use-pass', action='store_true', help='Use UNIX password store instead of hardcoded tokens')
    parser.add_argument('--log', type=str, default='warn', help='Log level (choose from debug, info, warning, error and critical)')
    parser.add_argument('--insecure', action='store_true', help='Disable SSL verification')
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
    if args.bts in BTS.__members__:
        bts = BTS[args.bts]
    else:
        print('You must provide a BTS type with the --bts flag (choices: \'jira\', \'gitlab\')')
        print(parser.print_help())
        sys.exit(1)

    with open(bts_config, 'r') as config_file:
        config_data = config_file.read()
    bts_api = json.loads(config_data)
    if use_pass:
        bts_api[bts.name]['token'] = subprocess.check_output(bts_api[bts.name]['token']).strip().decode('utf-8')
    bts_headers = {
        'Content-Type': 'application/json'
    }

    with open(mayhem_config, 'r') as config_file:
        config_data = config_file.read()
    mayhem_api = json.loads(config_data)
    if use_pass:
        mayhem_api['mayhem']['token'] = subprocess.check_output(mayhem_api['mayhem']['token']).strip().decode('utf-8')
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
        if output_csv:
            writer.writerow(['Project', 'Summary', 'Description'])
        if args.defect:
            defect_id = str(args.defect)
            defects = getDefect(mayhem_api, mayhem_headers, workspace, project, target, defect_id)
        elif args.run:
            run_id = str(args.run)
            defects = getDefectsForRun(mayhem_api, mayhem_headers, workspace, project, target, run_id)
        else:
            print('Must provide either --defect <id> or --run <id>')
        for defect in defects:
            ticket['fields']['summary'] = '[Mayhem] ' + str(defect['defect_number']) + ' in ' + project +'/' + target + ': ' + str(defect['title'])
            ticket['fields']['description'] = str(defect['description']) + '\n\n' \
                + '*CWE*: ' + str(defect['cwe_number']) + ' ' + str(defect['cwe_description']) + '\n' \
                + '*Target*: ' + workspace + '/' + project + '/' + target + '\n' \
                + '*Discovered on*: ' + str(defect['created_at']) + '\n'
            if 'examples' in defect:
                if 'backtrace' in defect['examples'][0]:
                    ticket['fields']['description'] += '*Backtrace*: \n```\n' + str(defect['examples'][0]['backtrace']) + '```\n'
            if defect['type'] in ['mapi', 'zap']:
                mapiIssue = getMapiIssue(mayhem_api, mayhem_headers, workspace, project, str(defect['defect_number']))
                ticket['fields']['description'] += '*Error*: ' + str(mapiIssue['issue_rule_id']) + '\n'
                ticket['fields']['description'] += '*Endpoint*: ' + str(mapiIssue['method']) + ' ' + str(mapiIssue['path']) + '\n'
                ticket['fields']['description'] += '*Sample Request*: \n```\n ' + str(base64.b64decode(mapiIssue['request'])) + ' ```\n'
                ticket['fields']['description'] += '*Sample Response*: \n```\n ' + str(base64.b64decode(mapiIssue['response'])) + ' ```\n'
            # --todo-- Can set more fields here
            if output_csv:
                writer.writerow([ticket['fields']['project']['key'], ticket['fields']['summary'], ticket['fields']['description']])
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
                + '*CWE*: ' + str(defect['cwe_number']) + ' ' + str(defect['cwe_description']) + '\n' \
                + '*Target*: ' + workspace + '/' + project + '/' + target + '\n' \
                + '*Discovered on*: ' + str(defect['created_at']) + '\n'
            if 'examples' in defect:
                if 'backtrace' in defect['examples'][0]:
                    ticket['description'] += '*Backtrace*: \n```\n' + str(defect['examples'][0]['backtrace']) + '```\n'
            if defect['type'] in ['mapi', 'zap']:
                mapiIssue = getMapiIssue(mayhem_api, mayhem_headers, workspace, project, str(defect['defect_number']))
                ticket['description'] += '*Error*: ' + str(mapiIssue['issue_rule_id']) + '\n'
                ticket['description'] += '*Endpoint*: ' + str(mapiIssue['method']) + ' ' + str(mapiIssue['path']) + '\n'
                ticket['description'] += '*Sample Request*: \n```\n ' + str(base64.b64decode(mapiIssue['request'])) + ' ```\n'
                ticket['description'] += '*Sample Response*: \n```\n ' + str(base64.b64decode(mapiIssue['response'])) + ' ```\n'
            # --todo-- Can set more fields here
            if output_csv:
                writer.writerow([ticket['title'], ticket['description']])
            else:
                link = exportToGitlab(bts_api, bts_headers, ticket, dry_run)
                print('Link to newly created Gitlab issue: ' + str(link))
                # --todo-- Update Mayhem
