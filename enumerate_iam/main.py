"""
IAM Account Enumerator

This code provides a mechanism to attempt to validate the permissions assigned
to a given set of AWS tokens.

Initial code from:

    https://gist.github.com/darkarnium/1df59865f503355ef30672168063da4e

Improvements:
    * Complete refactoring
    * Results returned in a programmatic way
    * Threads
    * Improved logging
    * Increased API call coverage
    * Export as a library
"""
import re
import json
import logging
import boto3
import botocore
import random

from botocore.client import Config
from botocore.endpoint import MAX_POOL_CONNECTIONS
from multiprocessing.dummy import Pool as ThreadPool

from enumerate_iam.utils.remove_metadata import remove_metadata
from enumerate_iam.utils.json_utils import json_encoder
from enumerate_iam.bruteforce_tests import BRUTEFORCE_TESTS

MAX_THREADS = 25
CLIENT_POOL = {}


def random_user_agent():
    uas = [
        "aws-cli/1.15.10 Python/2.7.9 Windows/8 botocore/1.10.10",
        "aws-cli/1.16.145 Python/3.6.7 Linux/4.15.0-45-generic botocore/1.12.135",
        "aws-cli/1.16.145 Python/3.6.7 Linux/4.15.0-45-generic botocore/1.12.168",
        "aws-cli/1.16.157 Python/3.7.3 Darwin/18.6.0 botocore/1.12.147",
        "aws-cli/1.16.166 Python/3.6.7 Linux/4.15.0-48-generic botocore/1.12.156",
        "aws-cli/1.16.170 Python/2.7.10 Linux/4.4.11-23.53.amzn1.x86_64 botocore/1.12.160cwlogs/1.4.4",
        "aws-cli/1.16.178 Python/3.6.7 Linux/4.15.0-45-generic botocore/1.12.168",
        "aws-cli/1.16.178 Python/3.7.0 Windows/10 botocore/1.12.168",
        "aws-cli/1.16.190 Python/3.7.0 Windows/10 botocore/1.12.180",
        "aws-cli/1.16.198 Python/3.7.3 Linux/4.9.125-linuxkit botocore/1.12.188",
        "aws-cli/1.16.198 Python/3.8.0b2 Linux/4.9.125-linuxkit botocore/1.12.188",
        "aws-cli/1.16.198 Python/3.8.0b2 Linux/4.9.184-linuxkit botocore/1.12.188",
        "aws-cli/1.16.219 Python/3.7.0 Windows/10 botocore/1.12.209",
        "aws-cli/1.16.284 Python/3.7.4 Windows/10 botocore/1.13.20",
        "aws-cli/1.17.1 Python/3.6.9 Linux/4.4.0-18362-Microsoft botocore/1.14.2",
        "aws-cli/1.18.2 Python/2.7.16 Linux/4.14.165-103.209.amzn1.x86_64 botocore/1.15.2",
        "aws-cli/1.18.39 Python/3.7.7 Windows/10 botocore/1.15.39",
        "aws-cli/1.18.40 Python/3.8.2 Windows/10 botocore/1.15.40",
        "aws-cli/2.0.0dev3 Python/3.7.3 Linux/4.19.76-linuxkit botocore/2.0.0dev2",
        "aws-sdk-go/1.1.0 (go1.5.2; darwin; amd64)",
        "aws-sdk-go/1.1.2 (go1.6; darwin; amd64) terraform/0.6.13",
        "aws-sdk-go/1.12.8 (go1.10.8; linux; amd64)",
        "aws-sdk-go/1.13.32 (go1.9.2; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.11.7",
        "aws-sdk-go/1.19.42 (go1.12.5; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.1",
        "aws-sdk-go/1.20.17 (go1.12.6; linux; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.2",
        "aws-sdk-go/1.21.3 (go1.12.6; linux; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.5",
        "aws-sdk-go/1.21.7 (go1.12.6; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.5 Waiter",
        "aws-sdk-go/1.21.7 (go1.12.6; linux; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.5",
        "aws-sdk-go/1.25.41 (go1.12.11; windows; amd64) amazon-ssm-agent/",
        "aws-sdk-go/1.4.10 (go1.7.4; linux; amd64)",
        "aws-sdk-go/1.4.10 (go1.8.3; linux; amd64)",
        "aws-sdk-go/1.4.22 (go1.7.4; linux; amd64)",
        "aws-sdk-java/2.0.0-preview-9-SNAPSHOT Mac_OS_X/10.11.6 Java_HotSpot_TM__64-Bit_Server_VM/25.151-b12 Java/1.8.0_151",
        "aws-sdk-nodejs/2.586.0 darwin/v13.2.0 promise",
        "Boto3/1.10.2 Python/3.8.0 Linux/4.14.138-99.102.amzn2.x86_64 exec-env/AWS_Lambda_python3.8 Botocore/1.13.2",
        "Boto3/1.10.27 Python/3.7.4 Windows/10 Botocore/1.13.20",
        "Boto3/1.4.7 Python/2.7.0 Java/1.8.0_112 Botocore/1.7.21",
        "Boto3/1.5.8 Python/3.6.3 Windows/10 Botocore/1.8.22",
        "Boto3/1.5.8 Python/3.6.5 Windows/10 Botocore/1.10.4",
        "Boto3/1.7.14 Python/3.6.1 Linux/4.9.93-41.60.amzn1.x86_64 Botocore/1.10.14",
        "Boto3/1.7.24 Python/3.6.5 Darwin/16.7.0 Botocore/1.10.24",
        "Boto3/1.7.24 Python/3.6.5 Windows/10 Botocore/1.10.24",
        "Boto3/1.7.24 Python/3.6.5 Windows/10 Botocore/1.10.24 Resource",
        "Boto3/1.7.30 Python/3.6.1 Linux/4.9.93-41.60.amzn1.x86_64 Botocore/1.10.30",
        "Boto3/1.7.45 Python/3.6.5 Windows/10 Botocore/1.10.45",
        "Boto3/1.7.48 Python/3.5.0 Windows/ Botocore/1.10.48",
        "Boto3/1.7.48 Python/3.6.5 Windows/10 Botocore/1.10.48",
        "Boto3/1.7.48 Python/3.7.0 Windows/10 Botocore/1.10.48",
        "Boto3/1.7.48 Python/3.7.3 Linux/4.9.184-linuxkit Botocore/1.10.48",
        "Boto3/1.7.61 Python/3.5.0 Windows/ Botocore/1.10.62",
        "Boto3/1.7.62 Python/3.5.2 Linux/4.4.0-130-generic Botocore/1.10.62",
        "Boto3/1.7.62 Python/3.7.0 Windows/10 Botocore/1.10.62",
        "Boto3/1.9.106 Python/3.6.7 Linux/4.15.0-48-generic Botocore/1.12.156",
        "Boto3/1.9.125 Python/3.7.3 Darwin/18.6.0 Botocore/1.12.147",
        "Boto3/1.9.149 Python/3.7.0 Windows/10 Botocore/1.12.168",
        "Boto3/1.9.168 Python/3.6.7 Linux/4.15.0-45-generic Botocore/1.12.168",
        "Boto3/1.9.211 Python/3.7.0 Windows/10 Botocore/1.12.211",
        "Boto3/1.9.69 Python/3.7.4 Linux/4.14.133-97.112.amzn2.x86_64 exec-env/AWS_Lambda_python3.7 Botocore/1.12.243",
        "console.amazonaws.com",
        "signin.amazonaws.com",
    ]
    return random.choice(uas)


def report_arn(candidate):
    """
    Attempt to extract and slice up an ARN from the input string
    """
    logger = logging.getLogger()

    arn_search = re.search(r'.*(arn:aws:.*?) .*', candidate)

    if arn_search:
        arn = arn_search.group(1)

        arn_id = arn.split(':')[4]
        arn_path = arn.split(':')[5]

        logger.info('-- Account ARN : %s', arn)
        logger.info('-- Account Id  : %s', arn.split(':')[4])
        logger.info('-- Account Path: %s', arn.split(':')[5])

        return arn, arn_id, arn_path

    return None, None, None


def enumerate_using_bruteforce(access_key, secret_key, session_token, region):
    """
    Attempt to brute-force common describe calls.
    """
    output = dict()

    logger = logging.getLogger()
    logger.info('Attempting common-service describe / list brute force.')

    pool = ThreadPool(MAX_THREADS)
    args_generator = generate_args(access_key, secret_key, session_token, region)

    try:
        results = pool.map(check_one_permission, args_generator)
    except KeyboardInterrupt:
        print('')

        results = []

        logger.info('Ctrl+C received, stopping all threads.')
        logger.info('Hit Ctrl+C again to force exit.')

        try:
            pool.close()
            pool.join()
        except KeyboardInterrupt:
            print('')
            return output

    for thread_result in results:
        if thread_result is None:
            continue

        key, action_result = thread_result
        output[key] = action_result

    pool.close()
    pool.join()

    return output


def generate_args(access_key, secret_key, session_token, region):

    service_names = list(BRUTEFORCE_TESTS.keys())

    random.shuffle(service_names)

    for service_name in service_names:
        actions = list(BRUTEFORCE_TESTS[service_name])
        random.shuffle(actions)

        for action in actions:
            yield access_key, secret_key, session_token, region, service_name, action


cached_user_agent = None
def get_safe_user_agent():
    """Returns random ua on kali/parrot/pentoo systems, otherwise uses the current ua."""
    global cached_user_agent
    if cached_user_agent is not None:
        return cached_user_agent
        
    boto3_session = boto3.session.Session()
    ua = boto3_session._session.user_agent()
    if 'kali' in ua.lower() or 'parrot' in ua.lower() or 'pentoo' in ua.lower():  # If the local OS is Kali/Parrot/Pentoo Linux
        print('Detected environment as one of Kali/Parrot/Pentoo Linux. Modifying user agent to hide that from GuardDuty...')
        cached_user_agent = random_user_agent()
    else:
        cached_user_agent = ua
    return cached_user_agent

get_safe_user_agent() # Cache global

def get_iam_client(access_key, secret_key, session_token):
    config = config = Config(connect_timeout=5,
            user_agent=get_safe_user_agent(),
            read_timeout=5,
            retries={'max_attempts': 30},
            max_pool_connections=MAX_POOL_CONNECTIONS * 2)
    
    return boto3.client(
        'iam',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        verify=False,
        config=config,
    )

def get_client(access_key, secret_key, session_token, service_name, region):
    key = '%s-%s-%s-%s-%s' % (access_key, secret_key, session_token, service_name, region)

    client = CLIENT_POOL.get(key, None)
    if client is not None:
        return client

    logger = logging.getLogger()
    logger.debug('Getting client for %s in region %s' % (service_name, region))

    config = Config(connect_timeout=5,
                    user_agent=get_safe_user_agent(),
                    read_timeout=5,
                    retries={'max_attempts': 30},
                    max_pool_connections=MAX_POOL_CONNECTIONS * 2)

    try:
        client = boto3.client(
            service_name,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region,
            verify=False,
            config=config,
        )
    except:
        # The service might not be available in this region
        return

    CLIENT_POOL[key] = client

    return client


def check_one_permission(arg_tuple):
    access_key, secret_key, session_token, region, service_name, operation_name = arg_tuple
    logger = logging.getLogger()

    service_client = get_client(access_key, secret_key, session_token, service_name, region)
    if service_client is None:
        return

    try:
        action_function = getattr(service_client, operation_name)
    except AttributeError:
        # The service might not have this action (this is most likely
        # an error with generate_bruteforce_tests.py)
        logger.error('Remove %s.%s action' % (service_name, operation_name))
        return

    logger.debug('Testing %s.%s() in region %s' % (service_name, operation_name, region))

    try:
        action_response = action_function()
    except (botocore.exceptions.ClientError,
            botocore.exceptions.EndpointConnectionError,
            botocore.exceptions.ConnectTimeoutError,
            botocore.exceptions.ReadTimeoutError):
        return
    except botocore.exceptions.ParamValidationError:
        logger.error('Remove %s.%s action' % (service_name, operation_name))
        return

    msg = '-- %s.%s() worked!'
    args = (service_name, operation_name)
    logger.info(msg % args)

    key = '%s.%s' % (service_name, operation_name)

    return key, remove_metadata(action_response)


def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(process)d - [%(levelname)s] %(message)s',
    )

    # Suppress boto INFO.
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('nose').setLevel(logging.WARNING)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # import botocore.vendored.requests.packages.urllib3 as urllib3
    urllib3.disable_warnings(botocore.vendored.requests.packages.urllib3.exceptions.InsecureRequestWarning)


def enumerate_iam(access_key, secret_key, session_token, region):
    """IAM Account Enumerator.

    This code provides a mechanism to attempt to validate the permissions assigned
    to a given set of AWS tokens.
    """
    output = dict()
    configure_logging()

    output['iam'] = enumerate_using_iam(access_key, secret_key, session_token, region)
    output['bruteforce'] = enumerate_using_bruteforce(access_key, secret_key, session_token, region)

    return output


def enumerate_using_iam(access_key, secret_key, session_token, region):
    output = dict()
    logger = logging.getLogger()

    # Connect to the IAM API and start testing.
    logger.info('Starting permission enumeration for access-key-id "%s"', access_key)
    iam_client = get_iam_client(access_key, secret_key, session_token)

    # Try for the kitchen sink.
    try:
        everything = iam_client.get_account_authorization_details()
    except (botocore.exceptions.ClientError,
            botocore.exceptions.EndpointConnectionError,
            botocore.exceptions.ReadTimeoutError):
        pass
    else:
        logger.info('Run for the hills, get_account_authorization_details worked!')
        logger.info('-- %s', json.dumps(everything, indent=4, default=json_encoder))

        output['iam.get_account_authorization_details'] = remove_metadata(everything)

    enumerate_user(iam_client, output)
    enumerate_role(iam_client, output)

    return output


def enumerate_role(iam_client, output):
    logger = logging.getLogger()

    # This is the closest thing we have to a role ARN
    user_or_role_arn = output.get('arn', None)

    if user_or_role_arn is None:
        # The checks which follow all required the user name to run, if we were
        # unable to get that piece of information just return
        return

    # Attempt to get role to start.
    try:
        role = iam_client.get_role(RoleName=user_or_role_arn)
    except botocore.exceptions.ClientError as err:
        arn, arn_id, arn_path = report_arn(str(err))

        if arn is not None:
            output['arn'] = arn
            output['arn_id'] = arn_id
            output['arn_path'] = arn_path

        if 'role' not in user_or_role_arn:
            # We did out best, but we got nothing from iam
            return
        else:
            role_name = user_or_role_arn

    else:
        output['iam.get_role'] = remove_metadata(role)
        role_name = role['Role']['RoleName']

    # Attempt to get policies attached to this user.
    try:
        role_policies = iam_client.list_attached_role_policies(RoleName=role_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_attached_role_policies'] = remove_metadata(role_policies)

        logger.info(
            'Role "%s" has %0d attached policies',
            role['Role']['RoleName'],
            len(role_policies['AttachedPolicies'])
        )

        # List all policies, if present.
        for policy in role_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])

    # Attempt to get inline policies for this user.
    try:
        role_policies = iam_client.list_role_policies(RoleName=role_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_role_policies'] = remove_metadata(role_policies)

        logger.info(
            'User "%s" has %0d inline policies',
            role['Role']['RoleName'],
            len(role_policies['PolicyNames'])
        )

        # List all policies, if present.
        for policy in role_policies['PolicyNames']:
            logger.info('-- Policy "%s"', policy)

    return output


def enumerate_user(iam_client, output):
    logger = logging.getLogger()
    output['root_account'] = False

    # Attempt to get user to start.
    try:
        user = iam_client.get_user()
    except botocore.exceptions.ClientError as err:
        arn, arn_id, arn_path = report_arn(str(err))

        output['arn'] = arn
        output['arn_id'] = arn_id
        output['arn_path'] = arn_path

        # The checks which follow all required the user name to run, if we were
        # unable to get that piece of information just return
        return
    else:
        output['iam.get_user'] = remove_metadata(user)

    if 'UserName' not in user['User']:
        if user['User']['Arn'].endswith(':root'):
            # OMG
            logger.warn('Found root credentials!')
            output['root_account'] = True
            return
        else:
            logger.error('Unexpected iam.get_user() response: %s' % user)
            return
    else:
        user_name = user['User']['UserName']

    # Attempt to get policies attached to this user.
    try:
        user_policies = iam_client.list_attached_user_policies(UserName=user_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_attached_user_policies'] = remove_metadata(user_policies)

        logger.info(
            'User "%s" has %0d attached policies',
            user_name,
            len(user_policies['AttachedPolicies'])
        )

        # List all policies, if present.
        for policy in user_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])

    # Attempt to get inline policies for this user.
    try:
        user_policies = iam_client.list_user_policies(UserName=user_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_user_policies'] = remove_metadata(user_policies)

        logger.info(
            'User "%s" has %0d inline policies',
            user_name,
            len(user_policies['PolicyNames'])
        )

        # List all policies, if present.
        for policy in user_policies['PolicyNames']:
            logger.info('-- Policy "%s"', policy)

    # Attempt to get the groups attached to this user.
    user_groups = dict()
    user_groups['Groups'] = []

    try:
        user_groups = iam_client.list_groups_for_user(UserName=user_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_groups_for_user'] = remove_metadata(user_groups)

        logger.info(
            'User "%s" has %0d groups associated',
            user_name,
            len(user_groups['Groups'])
        )

    # Attempt to get the group policies
    output['iam.list_group_policies'] = dict()

    for group in user_groups['Groups']:
        try:
            group_policy = iam_client.list_group_policies(GroupName=group['GroupName'])

            output['iam.list_group_policies'][group['GroupName']] = remove_metadata(group_policy)

            logger.info(
                '-- Group "%s" has %0d inline policies',
                group['GroupName'],
                len(group_policy['PolicyNames'])
            )

            # List all group policy names.
            for policy in group_policy['PolicyNames']:
                logger.info('---- Policy "%s"', policy)
        except botocore.exceptions.ClientError as err:
            pass

    return output

