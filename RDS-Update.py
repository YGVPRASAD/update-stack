"""
This Module is to update RDS Stack
Author: Hitachi Vantara
Contributor: Vara
Date: 18-10-2021
"""
import json
import argparse
import sys
import time
from os import environ
import logging
import boto3
import botocore
from botocore.exceptions import ClientError
LOGGER = logging.getLogger(__name__)
LOGFORMAT = "%(levelname)s: %(message)s"
LOGGER = logging.getLogger("Update RDS CFT")
LOGLEVEL = environ.get("logLevel", "INFO")
logging.basicConfig(format=LOGFORMAT, level=LOGLEVEL)
LOGGER.setLevel(logging.getLevelName(LOGLEVEL))
# read from cmd args
PARSER = argparse.ArgumentParser(description="This Module is to update RDS")
PARSER.add_argument("-a", "--action", help='stack actions(update,status)', required=True)
PARSER.add_argument("-r", "--region", required=True)
PARSER.add_argument("-s", "--stack_name", required=True)
PARSER.add_argument("-e", "--enhancedMonitorRoleARN")
ARGS = PARSER.parse_args()
STACK_REGION = ARGS.region
STACK_NAME = ARGS.stack_name
ENHANCED_ROLE = ARGS.enhancedMonitorRoleARN
DB_INSTANCE_ID = environ['DBInstanceID']
DB_NAME = environ['DBName']
DB_INSTANCE_CLASS = environ['DBInstanceClass']
DB_ALLOCATED_STORAGE = environ['DBAllocatedStorage']
DB_USERNAME = environ['DBUsername']
DB_PASSWORD = environ['DBPassword']
DELETE_PROTECTION = environ['DeletionProtection']
ct = boto3.client('cloudformation', STACK_REGION)
def rds_client(resource_type, session_name):
    """
    Function to get the aws credentials
    Args:
       resource_type (str): Resource type to initilize (Ex: ec2, s3)
       session_name(obj): contains assume role object
    """
    if "aws_role_name" in environ:
        client = boto3.client('sts')
        response = client.assume_role(RoleArn=environ['aws_role_name'],
                                      RoleSessionName=session_name)
        service_client = boto3.client(
            resource_type, region_name=STACK_REGION,
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
            )
    else:
        service_client = boto3.client(resource_type, STACK_REGION)
    return service_client
def rds_resource(resource_type, session_name):
    """
    Function to get the aws credentials
    Args:
       resource_type (str): Resource type to initilize (Ex: ec2, s3)
       session_name(obj): contains assume role object
    """
    if "aws_role_name" in environ:
        client = boto3.client('sts')
        response = client.assume_role(RoleArn=environ['aws_role_name'],
                                      RoleSessionName=session_name)
        service_resource = boto3.resource(
            resource_type, region_name=STACK_REGION,
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
            )
    else:
        service_resource = boto3.resource(resource_type, STACK_REGION)
    return service_resource

def _parse_template(template):
    with open(template) as template_fileobj:
        template_data = template_fileobj.read()
    ct.validate_template(TemplateBody=template_data)
    return template_data


def _parse_parameters(parameters):
    with open(parameters) as parameter_fileobj:
        parameter_data = json.load(parameter_fileobj)
    return parameter_data

def stack_updation():
    """
    updateStack function.
    """
    try:
        stack_updation_status = False
        cft_client = rds_client('cloudformation', 'rdsStack')
        
        response = ct.get_template(
            StackName=STACK_NAME,
            TemplateStage='Original'
        )
        print(response)
        with open(STACK_NAME+".json", 'w') as outfile:
            json.dump(response, outfile, indent=4)
        stack_base_template = open(STACK_NAME+".json")
        base_template = json.load(stack_base_template)
        json_data = json.dumps(base_template, indent=4)
        if ENHANCED_ROLE is not None:
            stack_params = [{'ParameterKey': 'DBInstanceID', 'ParameterValue': DB_INSTANCE_ID}, {'ParameterKey': 'DBName', 'ParameterValue': DB_NAME},
                            {'ParameterKey': 'DBInstanceClass', 'ParameterValue': DB_INSTANCE_CLASS}, {'ParameterKey': 'DBAllocatedStorage', 'ParameterValue': DB_ALLOCATED_STORAGE},
                            {'ParameterKey': 'DBUsername', 'ParameterValue': DB_USERNAME}, {'ParameterKey': 'DBPassword', 'ParameterValue': DB_PASSWORD},
                            {'ParameterKey': 'DeletionProtection', 'ParameterValue': DELETE_PROTECTION}]
        else:
            stack_params = [{'ParameterKey': 'DBInstanceID', 'ParameterValue': DB_INSTANCE_ID}, {'ParameterKey': 'DBName', 'ParameterValue': DB_NAME},
                            {'ParameterKey': 'DBInstanceClass', 'ParameterValue': DB_INSTANCE_CLASS}, {'ParameterKey': 'DBAllocatedStorage', 'ParameterValue': DB_ALLOCATED_STORAGE},
                            {'ParameterKey': 'DBUsername', 'ParameterValue': DB_USERNAME}, {'ParameterKey': 'DBPassword', 'ParameterValue': DB_PASSWORD},
                            {'ParameterKey': 'DeletionProtection', 'ParameterValue': DELETE_PROTECTION}]
        status = ct.describe_stacks(
                    StackName=STACK_NAME
            )
        stackstatus = status['Stacks'][0]['StackStatus']
        if stackstatus == 'CREATE_COMPLETE' or 'UPDATE_COMPLETE':  

            template_data = _parse_template(STACK_NAME+".json")
            parameter_data = _parse_parameters(stack_params)

            params = {
                'StackName': STACK_NAME,
                'TemplateBody': template_data,
                'Parameters': parameter_data,
            }

            response = ct.update_stack(**params)
            return True
        else:
            LOGGER.info('{} Stack does not exist'.format(STACK_NAME))
    except botocore.exceptions.ClientError as ex:
        error_message = ex.response['Error']['Message']
        if error_message == 'No updates are to be performed.':
            LOGGER.info("No changes")
            LOGGER.info("Updation of stack failed "+str(err))
            stack_updation_status = False
        else:
            raise
    #except Exception as err:
        #error_message = err.response['Error']['Message']
        #if error_message == 'No updates are to be performed.':
            #LOGGER.info("No changes")
            #LOGGER.info("Updation of stack failed "+str(err))
            #stack_updation_status = False
        #else:
            #raise
def get_status():
    """
    updateStack function.
    """
    try:
        stack_updaion_status = False
        cft_resource = rds_resource('cloudformation', 'rdsStack')
        valid_state = ["CREATE_IN_PROGRESS", "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"]
        stack_fail = ["CREATE_FAILED", "ROLLBACK_IN_PROGRESS", "ROLLBACK_FAILED", "ROLLBACK_COMPLETE", "DELETE_IN_PROGRESS", "DELETE_FAILED", "DELETE_COMPLETE"]
        while True:
            rds_stack = cft_resource.Stack(STACK_NAME)
            stack_state = rds_stack.stack_status
            if stack_state == "CREATE_COMPLETE":
                LOGGER.info("Stack "+STACK_NAME+" is updated successfully")
                stack_output = rds_stack.outputs
                LOGGER.info("The Following are the RDS Stack Outputs")
                LOGGER.info("------------------------------------")
                for output in stack_output:
                    rds_output = [output[k] for k in ['OutputKey', 'OutputValue']]
                    LOGGER.info(rds_output)
                describe_stack = rds_stack.parameters
                with open("update-"+STACK_NAME+"-params.json", "w") as rds_param:
                    json.dump(describe_stack, rds_param, indent=4)
                stack_updation_status = True
                break
            elif stack_state in valid_state:
                LOGGER.info("Stack is in: "+stack_state+" state")
                time.sleep(300)
                stack_updation_status = False
                continue
            elif stack_state in stack_fail:
                LOGGER.info("Stack is in: "+stack_state+" state")
                stack_updation_status = False
                break
            else:
                LOGGER.info("updation of stack failed")
                stack_updation_status = False
                break
        return stack_updation_status
    except Exception as err:
        LOGGER.info("Failed to get the stack status "+str(err))
        stack_updation_status = False
        return stack_updation_status
def main():
    """
    Main Function:
    """
    if ARGS.action == "update":
        LOGGER.info("stack updation started: "+ STACK_NAME)
        response = stack_updation()
    elif ARGS.action == "status":
        response = get_status()
    else:
        LOGGER.info("Failed to run the selected action. Please choose supported action types")
        response = False
    return response
if __name__ == "__main__":
    STATUS = main()
    if not STATUS:
        sys.exit(1)
