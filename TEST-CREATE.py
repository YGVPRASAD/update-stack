"""
This Module is to launch RDS Stack
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


LOGGER = logging.getLogger(__name__)
LOGFORMAT = "%(levelname)s: %(message)s"
LOGGER = logging.getLogger("Launch RDS CFT")
LOGLEVEL = environ.get("logLevel", "INFO")
logging.basicConfig(format=LOGFORMAT, level=LOGLEVEL)
LOGGER.setLevel(logging.getLevelName(LOGLEVEL))

# read from cmd args
PARSER = argparse.ArgumentParser(description="This Module is to create RDS")

PARSER.add_argument("-a", "--action", help='stack actions(create,status)', required=True)
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
DB_VERSION = environ['DBEngineVersion']
DB_ENG_TYPE = environ['DBEnginetype']
DB_USERNAME = environ['DBUsername']
DB_PASSWORD = environ['DBPassword']
DELETE_PROTECTION = environ['DeletionProtection']



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


def stack_creation():
    """
    createStack function.
    """
    try:
        stack_creation_status = False
        cft_client = rds_client('cloudformation', 'rdsStack')
        stack_base_template = open("RDS-TEST.json")
        base_template = json.load(stack_base_template)
        json_data = json.dumps(base_template, indent=4)

        if ENHANCED_ROLE is not None:
            stack_params = [{'ParameterKey': 'DBInstanceID', 'ParameterValue': DB_INSTANCE_ID}, {'ParameterKey': 'DBName', 'ParameterValue': DB_NAME},
                            {'ParameterKey': 'DBInstanceClass', 'ParameterValue': DB_INSTANCE_CLASS}, {'ParameterKey': 'DBAllocatedStorage', 'ParameterValue': DB_ALLOCATED_STORAGE},
                            {'ParameterKey': 'DBEngineVersion', 'ParameterValue': DB_VERSION}, {'ParameterKey': 'DBEnginetype', 'ParameterValue': DB_ENG_TYPE}, {'ParameterKey': 'DBUsername', 'ParameterValue': DB_USERNAME}, {'ParameterKey': 'DBPassword', 'ParameterValue': DB_PASSWORD},
                            {'ParameterKey': 'DeletionProtection', 'ParameterValue': DELETE_PROTECTION}]
        else:
            stack_params = [{'ParameterKey': 'DBInstanceID', 'ParameterValue': DB_INSTANCE_ID}, {'ParameterKey': 'DBName', 'ParameterValue': DB_NAME},
                            {'ParameterKey': 'DBInstanceClass', 'ParameterValue': DB_INSTANCE_CLASS}, {'ParameterKey': 'DBAllocatedStorage', 'ParameterValue': DB_ALLOCATED_STORAGE},
                            {'ParameterKey': 'DBEngineVersion', 'ParameterValue': DB_VERSION}, {'ParameterKey': 'DBEnginetype', 'ParameterValue': DB_ENG_TYPE}, {'ParameterKey': 'DBUsername', 'ParameterValue': DB_USERNAME}, {'ParameterKey': 'DBPassword', 'ParameterValue': DB_PASSWORD},
                            {'ParameterKey': 'DeletionProtection', 'ParameterValue': DELETE_PROTECTION}]

        cft_client.create_stack(StackName=STACK_NAME,
                                TemplateBody=json_data, Parameters=stack_params)
        return True
    except Exception as err:
        if err.response['Error']['Code'] == 'AlreadyExistsException':
            LOGGER.info('RDS Stack Already Exists')
            stack_creation_status = True
        else:
            LOGGER.info("Creation of stack failed "+str(err))
            stack_creation_status = False
        return stack_creation_status


def get_status():
    """
    createStack function.
    """
    try:
        stack_creation_status = False
        cft_resource = rds_resource('cloudformation', 'rdsStack')
        valid_state = ["CREATE_IN_PROGRESS", "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"]
        stack_fail = ["CREATE_FAILED", "ROLLBACK_IN_PROGRESS", "ROLLBACK_FAILED", "ROLLBACK_COMPLETE", "DELETE_IN_PROGRESS", "DELETE_FAILED", "DELETE_COMPLETE"]
        while True:
            rds_stack = cft_resource.Stack(STACK_NAME)
            stack_state = rds_stack.stack_status
            if stack_state == "CREATE_COMPLETE":
                LOGGER.info("Stack "+STACK_NAME+" is created successfully")
                stack_output = rds_stack.outputs
                
                LOGGER.info(stack_output)
                LOGGER.info("The Following are the RDS Stack Outputs")
                LOGGER.info("------------------------------------")
                for output in stack_output:
                    rds_output = [output[k] for k in ['OutputKey', 'OutputValue']]
                    LOGGER.info(rds_output)
                describe_stack = rds_stack.parameters
                with open(STACK_NAME+"-params.json", "w") as rds_param:
                    json.dump(describe_stack, rds_param, indent=4)
                stack_creation_status = True
                break
            elif stack_state in valid_state:
                LOGGER.info("Stack is in: "+stack_state+" state")
                time.sleep(300)
                stack_creation_status = False
                continue
            elif stack_state in stack_fail:
                LOGGER.info("Stack is in: "+stack_state+" state")
                stack_creation_status = False
                break
            else:
                LOGGER.info("creation of stack failed")
                stack_creation_status = False
                break
        return stack_creation_status
    except Exception as err:
        LOGGER.info("Failed to get the stack status "+str(err))
        stack_creation_status = False
        return stack_creation_status


def main():
    """
    Main Function:
    """
    if ARGS.action == "create":
        LOGGER.info("stack creation started: "+ STACK_NAME)
        response = stack_creation()
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
