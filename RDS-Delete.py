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

PARSER.add_argument("-r", "--region", required=True)
PARSER.add_argument("-s", "--stack_name", required=True)
PARSER.add_argument("-e", "--enhancedMonitorRoleARN")

ARGS = PARSER.parse_args()

STACK_REGION = ARGS.region
STACK_NAME = ARGS.stack_name
ENHANCED_ROLE = ARGS.enhancedMonitorRoleARN

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

def _stack_exists(STACK_NAME):
    client = boto3.client('cloudformation', region_name=STACK_REGION)
    stacks = client.list_stacks()['StackSummaries']
    for stack in stacks:
        if stack['StackStatus'] == 'DELETE_COMPLETE':
            continue
        if STACK_NAME == stack['StackName']:
            return True
    return False


def main():
    """
    Main Function:
    """
    client = boto3.client('cloudformation', region_name=STACK_REGION)
    try:
        stack_updation_status = False
        cft_client = rds_client('cloudformation', 'rdsStack')
        stack_base_template = open("RDS-TEST.json")
        base_template = json.load(stack_base_template)
        json_data = json.dumps(base_template, indent=4)
        
        if ENHANCED_ROLE is not None:
            stack_params = [{'ParameterKey': 'DeletionProtection', 'ParameterValue': DELETE_PROTECTION}]
        else:
            stack_params = [{'ParameterKey': 'DeletionProtection', 'ParameterValue': DELETE_PROTECTION}]
        LOGGER.info(stack_params)
        

        status = client.describe_stacks(                    
            StackName=STACK_NAME            
        )              
        key = status['Stacks'][0]['Parameters']   
        LOGGER.info(key)        
        item = 'DeletionProtection'        
        def search_value(name):            
            for keyval in key:                
                if name.lower() == keyval['ParameterKey'].lower():                    
                    return keyval['ParameterValue']        
        if (search_value(item) != None):
            LOGGER.info(search_value(item))
        else:            
            LOGGER.info("Item is not found")        
        if (search_value(item) == 'true'):
            cftresource = rds_resource('cloudformation', 'rdsStack')
            rdsstack = cftresource.Stack(STACK_NAME)
            stackstatus = rdsstack.stack_status
            if stackstatus == 'CREATE_COMPLETE' or 'UPDATE_COMPLETE':
                cft_client.update_stack(StackName=STACK_NAME,
                                TemplateBody=json_data, Parameters=stack_params)
                stackstatus = "UPDATE_IN_PROGRESS"
                while (stackstatus == "UPDATE_IN_PROGRESS"):
                    LOGGER.info("UPDATE IN PROGRESS")
                    status = client.describe_stacks(
                        StackName=STACK_NAME
                    )
                    stackstatus = status['Stacks'][0]['StackStatus']
                LOGGER.info("Updated {}".format(STACK_NAME))
                return True
    except botocore.exceptions.ClientError as ex:
        LOGGER.info('{} Stack does not exist'.format(STACK_NAME))
        raise

    ###delete stack###
    
    if _stack_exists(STACK_NAME):
        LOGGER.info("Deleting {}".format(STACK_NAME))
        response = client.delete_stack(
            StackName=STACK_NAME
        )
        try:
            stackstatus = "DELETE_IN_PROGRESS"
            while (stackstatus == "DELETE_IN_PROGRESS"):
                LOGGER.info("DELETE IN PROGRESS")
                status = client.describe_stacks(
                    StackName=STACK_NAME
                )
                stackstatus = status['Stacks'][0]['StackStatus']
        except ClientError as error:
            LOGGER.info("Deleted {}".format(STACK_NAME))  
    else:
        raise Exception("{} Stack Name does not exist".format(STACK_NAME))


if __name__ == "__main__":
    STATUS = main()
    if not STATUS:
        sys.exit(1)
