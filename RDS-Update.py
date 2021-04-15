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
VPC = environ['VPC']
SUBNET_GROUP = environ['SubnetGroup']
DB_IDENTIFIER = environ['DBIdentifier']
MASTER_USER = environ['MasterUserName']
MASTER_PASSWORD = environ['MasterPassword']
DB_CLASS = environ['DBInstanceClass']
SECURITY_GROUP = environ['SecurityGroup']
DB_PARAM = environ['DBParameterGroupName']
DB_OPTION_GROUP = environ['DBOptionGroupName']
KMS_ARN = environ['KMSARN']
MULTI_AZ_DB = environ['MultiAZDatabase']
PERFORM_INSIGHT_KMS = environ['PerformanceInsightsKMSKeyId']
ENHANCED_MONITOR = environ['EnhancedMonitoringInterval']
REPLICA_DB = environ['ReplicaDBIdentifier']
ENABLE_REPLICA = environ['EnableReadReplica']
ALLOWED_MAJOR = environ['AllowMajorVersionUpgrade']
MAX_STORAGE = environ['MaxAllocatedStorage']
STORAGE_TYPE = environ['StorageType']
STORAGE_SIZE = environ['StorageSize']
IOPS = environ['IOPS']
COPY_TAGS_SNAPHOT = environ['CopyTagsToSnapshot']
MNT_WINDOW = environ['MaintenanceWindow']
BCK_UP_WINDOW = environ['BackupWindow']
BCK_RTN = environ['BackupRetentionPeriod']
DB_VERSION = environ['DBEngineVersion']
DB_ENG_TYPE = environ['DBEnginetype']
PUBLIC_ACCESS = environ['PublicAccess']
ALLOWED_MINOR = environ['AllowAutoMinorVersionUpgrade']
DELETE_PROTECTION = environ['DeletionProtection']
DELETE_AUTOMATED = environ['DeleteAutomatedBackups']
ENABLE_PRF = environ['EnablePerformanceInsights']
PRF_RTN = environ['PerformanceInsightsRetentionPeriod']


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


def stack_updation():
    """
    updateStack function.
    """
    try:
        stack_updation_status = False
        cft_client = rds_client('cloudformation', 'rdsStack')
        stack_base_template = open("RDS-TEST.json")
        base_template = json.load(stack_base_template)
        json_data = json.dumps(base_template, indent=4)
        ct = boto3.client('cloudformation', STACK_REGION)

        if ENHANCED_ROLE is not None:
            stack_params = [{'ParameterKey': 'VPC', 'ParameterValue': VPC}, {'ParameterKey': 'SubnetGroup', 'ParameterValue': SUBNET_GROUP},
                            {'ParameterKey': 'DBIdentifier', 'ParameterValue': DB_IDENTIFIER}, {'ParameterKey': 'MasterUserName', 'ParameterValue': MASTER_USER},
                            {'ParameterKey': 'MasterPassword', 'ParameterValue': MASTER_PASSWORD}, {'ParameterKey': 'DBInstanceClass', 'ParameterValue': DB_CLASS},
                            {'ParameterKey': 'SecurityGroup', 'ParameterValue': SECURITY_GROUP}, {'ParameterKey': 'DBParameterGroupName', 'ParameterValue': DB_PARAM},
                            {'ParameterKey': 'DBOptionGroupName', 'ParameterValue': DB_OPTION_GROUP}, {'ParameterKey': 'KMSARN', 'ParameterValue': KMS_ARN},
                            {'ParameterKey': 'MultiAZDatabase', 'ParameterValue': MULTI_AZ_DB}, {'ParameterKey': 'PerformanceInsightsKMSKeyId', 'ParameterValue': PERFORM_INSIGHT_KMS},
                            {'ParameterKey': 'EnhancedMonitoringInterval', 'ParameterValue': ENHANCED_MONITOR}, {'ParameterKey': 'EnhancedMonitorRoleARN', 'ParameterValue': ENHANCED_ROLE},
                            {'ParameterKey': 'ReplicaDBIdentifier', 'ParameterValue': REPLICA_DB}, {'ParameterKey': 'EnableReadReplica', 'ParameterValue': ENABLE_REPLICA},
                            {'ParameterKey': 'AllowMajorVersionUpgrade', 'ParameterValue': ALLOWED_MAJOR}, {'ParameterKey': 'MaxAllocatedStorage', 'ParameterValue': MAX_STORAGE},
                            {'ParameterKey': 'StorageType', 'ParameterValue': STORAGE_TYPE}, {'ParameterKey': 'StorageSize', 'ParameterValue': STORAGE_SIZE},
                            {'ParameterKey': 'IOPS', 'ParameterValue': IOPS}, {'ParameterKey': 'CopyTagsToSnapshot', 'ParameterValue': COPY_TAGS_SNAPHOT},
                            {'ParameterKey': 'MaintenanceWindow', 'ParameterValue': MNT_WINDOW}, {'ParameterKey': 'BackupWindow', 'ParameterValue': BCK_UP_WINDOW},
                            {'ParameterKey': 'BackupRetentionPeriod', 'ParameterValue': BCK_RTN}, {'ParameterKey': 'DBEngineVersion', 'ParameterValue': DB_VERSION},
                            {'ParameterKey': 'DBEnginetype', 'ParameterValue': DB_ENG_TYPE}, {'ParameterKey': 'PublicAccess', 'ParameterValue': PUBLIC_ACCESS},
                            {'ParameterKey': 'AllowAutoMinorVersionUpgrade', 'ParameterValue': ALLOWED_MINOR}, {'ParameterKey': 'DeletionProtection', 'ParameterValue': DELETE_PROTECTION},
                            {'ParameterKey': 'DeleteAutomatedBackups', 'ParameterValue': DELETE_AUTOMATED}, {'ParameterKey': 'EnablePerformanceInsights', 'ParameterValue': ENABLE_PRF},
                            {'ParameterKey': 'PerformanceInsightsRetentionPeriod', 'ParameterValue': PRF_RTN}, {'ParameterKey': 'BillingContact', 'ParameterValue': environ['BillingContact']},
                            {'ParameterKey': 'ClarityID', 'ParameterValue': environ['ClarityID']}, {'ParameterKey': 'CostCenter', 'ParameterValue': environ['CostCenter']},
                            {'ParameterKey': 'Environment', 'ParameterValue': environ['Environment']}, {'ParameterKey': 'Owner', 'ParameterValue': environ['Owner']},
                            {'ParameterKey': 'SchedulerID', 'ParameterValue': environ['SchedulerID']}, {'ParameterKey': 'APPType', 'ParameterValue': environ['APPType']},
                            {'ParameterKey': 'OSType', 'ParameterValue': environ['OSType']}, {'ParameterKey': 'Name', 'ParameterValue': environ['Name']}]
        else:
            stack_params = [{'ParameterKey': 'VPC', 'ParameterValue': VPC}, {'ParameterKey': 'SubnetGroup', 'ParameterValue': SUBNET_GROUP},
                            {'ParameterKey': 'DBIdentifier', 'ParameterValue': DB_IDENTIFIER}, {'ParameterKey': 'MasterUserName', 'ParameterValue': MASTER_USER},
                            {'ParameterKey': 'MasterPassword', 'ParameterValue': MASTER_PASSWORD}, {'ParameterKey': 'DBInstanceClass', 'ParameterValue': DB_CLASS},
                            {'ParameterKey': 'SecurityGroup', 'ParameterValue': SECURITY_GROUP}, {'ParameterKey': 'DBParameterGroupName', 'ParameterValue': DB_PARAM},
                            {'ParameterKey': 'DBOptionGroupName', 'ParameterValue': DB_OPTION_GROUP}, {'ParameterKey': 'KMSARN', 'ParameterValue': KMS_ARN},
                            {'ParameterKey': 'MultiAZDatabase', 'ParameterValue': MULTI_AZ_DB}, {'ParameterKey': 'PerformanceInsightsKMSKeyId', 'ParameterValue': PERFORM_INSIGHT_KMS},
                            {'ParameterKey': 'EnhancedMonitoringInterval', 'ParameterValue': ENHANCED_MONITOR}, {'ParameterKey': 'ReplicaDBIdentifier', 'ParameterValue': REPLICA_DB},
                            {'ParameterKey': 'EnableReadReplica', 'ParameterValue': ENABLE_REPLICA}, {'ParameterKey': 'AllowMajorVersionUpgrade', 'ParameterValue': ALLOWED_MAJOR},
                            {'ParameterKey': 'MaxAllocatedStorage', 'ParameterValue': MAX_STORAGE}, {'ParameterKey': 'StorageType', 'ParameterValue': STORAGE_TYPE},
                            {'ParameterKey': 'StorageSize', 'ParameterValue': STORAGE_SIZE}, {'ParameterKey': 'IOPS', 'ParameterValue': IOPS},
                            {'ParameterKey': 'CopyTagsToSnapshot', 'ParameterValue': COPY_TAGS_SNAPHOT}, {'ParameterKey': 'MaintenanceWindow', 'ParameterValue': MNT_WINDOW},
                            {'ParameterKey': 'BackupWindow', 'ParameterValue': BCK_UP_WINDOW}, {'ParameterKey': 'BackupRetentionPeriod', 'ParameterValue': BCK_RTN},
                            {'ParameterKey': 'DBEngineVersion', 'ParameterValue': DB_VERSION}, {'ParameterKey': 'DBEnginetype', 'ParameterValue': DB_ENG_TYPE},
                            {'ParameterKey': 'PublicAccess', 'ParameterValue': PUBLIC_ACCESS}, {'ParameterKey': 'AllowAutoMinorVersionUpgrade', 'ParameterValue': ALLOWED_MINOR},
                            {'ParameterKey': 'DeletionProtection', 'ParameterValue': DELETE_PROTECTION}, {'ParameterKey': 'DeleteAutomatedBackups', 'ParameterValue': DELETE_AUTOMATED},
                            {'ParameterKey': 'EnablePerformanceInsights', 'ParameterValue': ENABLE_PRF}, {'ParameterKey': 'PerformanceInsightsRetentionPeriod', 'ParameterValue': PRF_RTN},
                            {'ParameterKey': 'BillingContact', 'ParameterValue': environ['BillingContact']}, {'ParameterKey': 'ClarityID', 'ParameterValue': environ['ClarityID']},
                            {'ParameterKey': 'CostCenter', 'ParameterValue': environ['CostCenter']}, {'ParameterKey': 'Environment', 'ParameterValue': environ['Environment']},
                            {'ParameterKey': 'Owner', 'ParameterValue': environ['Owner']}, {'ParameterKey': 'SchedulerID', 'ParameterValue': environ['SchedulerID']},
                            {'ParameterKey': 'APPType', 'ParameterValue': environ['APPType']}, {'ParameterKey': 'OSType', 'ParameterValue': environ['OSType']},
                            {'ParameterKey': 'Name', 'ParameterValue': environ['Name']}]

        status = ct.describe_stacks(
                    StackName=STACK_NAME
            )
        stackstatus = status['Stacks'][0]['StackStatus']
        if stackstatus == 'CREATE_COMPLETE' or 'UPDATE_COMPLETE':
            cft_client.update_stack(StackName=STACK_NAME,
                                TemplateBody=json_data, Parameters=stack_params)
            return True
    except botocore.exceptions.ClientError as ex:
        LOGGER.info('{} Stack does not exist'.format(STACK_NAME))
        raise
    
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
            if stack_state == "UPDATE_COMPLETE":
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