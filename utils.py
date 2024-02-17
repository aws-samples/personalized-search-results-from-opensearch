from opensearchpy import OpenSearch, RequestsHttpConnection
from botocore.exceptions import ClientError
import json
import boto3
import requests
import time
import pandas as pd
import sys
from requests_auth_aws_sigv4 import AWSSigV4
import logging

client = boto3.client('opensearch')

logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
logger.setLevel(logging.INFO)
logger.addHandler(handler)


def get_secret(secret_name):
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager')

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        # print(get_secret_value_response)
    except ClientError as e:
        raise e
    else:
        # Decrypted secret using KMS
        secret = get_secret_value_response['SecretString']
        return secret


def delete_index_data(client, index_name):
    # index_name = 'movies'
    client.indices.delete(index=index_name)


def upload_to_s3(file_name, bucket_name, s3_key):
    """Uploads file to S3"""
    s3 = boto3.client('s3')
    try:
        s3.upload_file(file_name, bucket_name, s3_key)
        print('Upload successful')
        return True
    except FileNotFoundError:
        sys.exit('File not found. Make sure you specified the correct file path.')


def update_package(package_id, bucket_name, s3_key):
    """Updates the package in OpenSearch Service"""
    print(package_id, bucket_name, s3_key)
    response = client.update_package(
        PackageID=package_id,
        PackageSource={
            'S3BucketName': bucket_name,
            'S3Key': s3_key
        }
    )
    print(response)


def create_package(package_name, bucket_name, s3_key):
    """Updates the package in OpenSearch Service"""

    response = client.create_package(
        PackageName=package_name,
        PackageType='TXT-DICTIONARY',
        PackageDescription='Package for personalized ranking',
        PackageSource={
            'S3BucketName': bucket_name,
            'S3Key': s3_key
        }
    )

    # print(response['PackageDetails']['PackageID'])
    return response['PackageDetails']['PackageID']


def associate_package(package_id, domain_name):
    """Associates the package to the domain"""
    response = client.associate_package(
        PackageID=package_id, DomainName=domain_name)
    print(response)
    print('Associating...')
    wait_for_update(domain_name, package_id)


def wait_for_update(domain_name, package_id):
    """Waits for the package to be updated"""
    response = client.list_packages_for_domain(DomainName=domain_name)
    package_details = response['DomainPackageDetailsList']
    for package in package_details:
        if package['PackageID'] == package_id:
            status = package['DomainPackageStatus']
            if status == 'ACTIVE':
                print('Association successful.')
                return
            elif status == 'ASSOCIATION_FAILED':
                sys.exit('Association failed. Please try again.')
            else:
                time.sleep(10)  # Wait 10 seconds before rechecking the status
                wait_for_update(domain_name, package_id)


def wait_for_package_creation(package_id):
    status = None
    max_time = time.time() + 3 * 60 * 60  # 3 hours
    while time.time() < max_time:
        response = client.describe_packages(
            Filters=[
                {
                    'Name': 'PackageID',
                    'Value': [
                        package_id,
                    ]
                },
            ]
        )

        status = response["PackageDetailsList"][0]["PackageStatus"]
        print("Create package: {}".format(status))

        if status == "AVAILABLE" or status == "COPY_FAILED" or status == "VALIDATION_FAILED":
            if status == "COPY_FAILED" or status == "VALIDATION_FAILED":
                raise Exception(f"Error while executing: {status}")
            break

        time.sleep(20)
    return status


def create_s3_bucket(bucket_suffix, region):
    s3 = boto3.client('s3')
    # region = 'us-west-2'
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    bucket_name = account_id + "-" + region + "-" + bucket_suffix
    # print('bucket_name:', bucket_name)

    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
    except s3.exceptions.BucketAlreadyOwnedByYou:
        print("Bucket already exists. Using bucket", bucket_name)

    policy = {
        "Version": "2012-10-17",
        "Id": "PersonalizeS3BucketAccessPolicy",
        "Statement": [
            {
                "Sid": "PersonalizeS3BucketAccessPolicy",
                "Effect": "Allow",
                "Principal": {
                    "Service": "personalize.amazonaws.com"
                },
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    "arn:aws:s3:::{}".format(bucket_name),
                    "arn:aws:s3:::{}/*".format(bucket_name)
                ]
            }
        ]
    }

    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    return bucket_name


def create_iam_role(role_suffix, bucket_name):
    iam = boto3.client("iam")
    account_id = boto3.client('sts').get_caller_identity().get('Account')

    role_name = f"{account_id}-{role_suffix}"
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "personalize.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        create_role_response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        );

    except iam.exceptions.EntityAlreadyExistsException as e:
        print('Warning: role already exists:', e)
        create_role_response = iam.get_role(
            RoleName=role_name
        );

    role_arn = create_role_response["Role"]["Arn"]
    s3_access_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Action': [
                    's3:GetObject',
                    's3:ListBucket',
                    's3:PutObject'
                ],
                'Resource': [f'arn:aws:s3:::{bucket_name}', f"arn:aws:s3:::{bucket_name}/*"]
            }
        ]
    }

    print('IAM Role: {}'.format(role_arn))

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName='S3AccessPolicy',
        PolicyDocument=json.dumps(s3_access_policy)
    )

    role_arn = create_role_response["Role"]["Arn"]

    # Pause to allow role to be fully consistent
    time.sleep(30)
    return role_arn


def create_iam_role_for_personalize(role_suffix, campaign_arn):
    iam = boto3.client("iam")
    account_id = boto3.client('sts').get_caller_identity().get('Account')

    role_name = f"{account_id}-{role_suffix}"
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "es.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        create_role_response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )

    except iam.exceptions.EntityAlreadyExistsException as e:
        print('Warning: role already exists:', e)
        create_role_response = iam.get_role(
            RoleName=role_name
        )

    role_arn = create_role_response["Role"]["Arn"]

    print('IAM Role: {}'.format(role_arn))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "personalize:GetPersonalizedRanking"
                ],
                "Resource": campaign_arn
            }
        ]
    }

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName='personalize-access',
        PolicyDocument=json.dumps(policy)
    )

    role_arn = create_role_response["Role"]["Arn"]

    # Pause to allow role to be fully consistent
    time.sleep(30)
    return role_arn


def bulk_upload(index_file_name, endpoint, auth):
    print("Start bulk upload")
    url = f'{endpoint}_bulk'
    print(url)

    headers = {'Content-Type': 'application/json'}

    with open(index_file_name, 'rb') as f:
        data = f.read()

    response = requests.post(url, auth=auth, headers=headers, data=data, timeout=120)

    print("All Done!", response)


def update_pipeline(pipeline_name, weight, campaign_arn, iam_role_arn, os_region, HOST, PORT):
    auth = AWSSigV4('es', region=os_region)

    if weight != "Select":
        url = f'https://{HOST}:{PORT}/_search/pipeline/{pipeline_name}'

        headers = {'Content-Type': 'application/json'}

        body = {
            "description": "A pipeline to apply custom re-ranking from Amazon Personalize",
            "response_processors": [
                {
                    "personalized_search_ranking": {
                        "campaign_arn": campaign_arn,
                        "item_id_field": "",
                        "recipe": "aws-personalized-ranking",
                        "weight": weight,
                        "tag": "personalize-processor",
                        "iam_role_arn": iam_role_arn,
                        "aws_region": os_region,
                        "ignore_failure": True
                    }
                }
            ]
        }
        try:
            response = requests.put(url, auth=auth, json=body, headers=headers, timeout=120)
        except Exception as e:
            return f"Error: {e}"

        return response.text


def personalize_request_present(search_body):
    data = json.loads(search_body)

    user_id = data.get('ext', {}).get('personalize_request_parameters', {}).get('user_id')

    if user_id:
        return True
    else:
        return False


def convert_response_to_dataframe(data):
    # data = json.loads(json_str)

    titles = []
    genres = []

    for hit in data['hits']['hits']:
        title = hit['_source']['title']
        genre = hit['_source']['genres']

        if isinstance(genre, list):
            genre = '|'.join(genre)

        titles.append(title)
        genres.append(genre)

    df = pd.DataFrame({
        f'TITLE': titles,
        f'GENRES': genres
    })

    return df


def load_recent_movies(user_id: str, interactions_df, items_df):
    ints_df = interactions_df.loc[interactions_df["USER_ID"] == int(user_id)].sort_values(by="TIMESTAMP",
                                                                                          ascending=False)

    ints_df = ints_df.drop_duplicates(subset='ITEM_ID').head(10)

    movies = []
    for movie_id in ints_df["ITEM_ID"]:
        movie, genre = get_movie_by_id(movie_id, items_df)
        movies.append({"Title": movie, "Genre": genre})

    return pd.DataFrame(movies)


def get_interactions(file_path):
    interactions_path = f"{file_path}/interactions.csv"
    df = pd.read_csv(interactions_path)
    df["TIMESTAMP"] = pd.to_datetime(df['TIMESTAMP'], unit='s', utc=True)
    df["TIMESTAMP_LOCAL"] = df['TIMESTAMP'].dt.tz_convert('US/Eastern')
    return df


def get_items(file_path):
    items_path = f"{file_path}/movies.csv"
    df = pd.read_csv(items_path, sep=',', index_col=0)

    return df


def get_movie_by_id(movieId, movie_df):
    """
    This takes in an artist_id from Personalize so it will be a string,
    converts it to an int, and then does a lookup in a default or specified
    dataframe.

    A really broad try/except clause was added in case anything goes wrong.

    Feel free to add more debugging or filtering here to improve results if
    you hit an error.
    """
    try:
        return movie_df.loc[movieId]['title'], movie_df.loc[movieId]['genres']
    except Exception as e:
        return "Error obtaining title" + str(e)


def run_search(search_body, host, pipeline_name=None):
    auth = AWSSigV4('es')

    # Connect to OpenSearch
    es = OpenSearch(
        hosts=[{'host': host, 'port': 443}],
        http_auth=auth,
        use_ssl=True,
        connection_class=RequestsHttpConnection
    )

    if personalize_request_present(search_body):
        res = es.search(index="movies", body=search_body, params={
            'search_pipeline': pipeline_name
        })
    else:
        res = es.search(index="movies", body=search_body)

    return res


def personalize_request_present(search_body):
    data = json.loads(search_body)

    user_id = data.get('ext', {}).get('personalize_request_parameters', {}).get('user_id')

    if user_id:
        return True
    else:
        return False


def get_opensearch_package_id(package_name, opensearch_version):
    response = client.describe_packages(
        Filters=[
            {
                'Name': 'PackageName',
                'Value': [package_name]
            },
        ],
        MaxResults=100,
    )

    for package in response['PackageDetailsList']:
        if (package['PackageName'] == package_name) & (
                package['AvailablePluginProperties']['Version'] == opensearch_version):
            print(f"Package found {package['PackageID']}")
            break

    return package['PackageID']


def compare_results(res1, res2):
    df_unranked = convert_response_to_dataframe(res1)
    df_ranked = convert_response_to_dataframe(res2)

    df_unranked['index'] = range(1, len(df_unranked) + 1)
    df_ranked['index'] = range(1, len(df_ranked) + 1)

    df = df_ranked.merge(df_unranked, on='TITLE')

    df_ranked['Ranking Delta'] = df['index_y'] - df['index_x']
    df_ranked['Ranking Delta'] = df_ranked['Ranking Delta'].apply(lambda x: f'+{x}' if x > 0 else x)

    df_unranked = df_unranked.drop(columns=['index'])
    df_ranked = df_ranked.drop(columns=['index'], axis=1)

    df_unranked = df_unranked.rename(columns={'TITLE': 'TITLE (unranked)', 'GENRES': 'GENRES (unranked)'})
    df_ranked = df_ranked.rename(columns={'TITLE': 'TITLE (ranked)', 'GENRES': 'GENRES (ranked)'})

    rerank_df = pd.concat([df_unranked, df_ranked], axis=1)
    return rerank_df


def delete_iam_role(role_arn):
    iam = boto3.client('iam')

    role_name = role_arn.split('/')[-1]
    # Get list of policies attached to the role
    response = iam.list_attached_role_policies(RoleName=role_name)

    policies = response['AttachedPolicies']

    # Detach each policy
    for policy in policies:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])

    # List and detach inline policies
    inline_policies = iam.list_role_policies(RoleName=role_name)['PolicyNames']

    for policy in inline_policies:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy)

    # Delete the role
    iam.delete_role(RoleName=role_name)

    print(f"Role {role_name} deleted")


def _get_dataset_group_arn(dataset_group_name, region):
    dsg_arn = None
    try:
        if (personalize is None):
            personalize = boto3.client(service_name='personalize', region_name=region)
    except:
        personalize = boto3.client(service_name='personalize', region_name=region)

    paginator = personalize.get_paginator('list_dataset_groups')
    for paginate_result in paginator.paginate():
        for dataset_group in paginate_result["datasetGroups"]:
            if dataset_group['name'] == dataset_group_name:
                dsg_arn = dataset_group['datasetGroupArn']
                break

        if dsg_arn:
            break

    if not dsg_arn:
        raise NameError(f'Dataset Group "{dataset_group_name}" does not exist; verify region is correct')

    return dsg_arn


def _get_solutions(dataset_group_arn):
    solution_arns = []

    paginator = personalize.get_paginator('list_solutions')
    for paginate_result in paginator.paginate(datasetGroupArn=dataset_group_arn):
        for solution in paginate_result['solutions']:
            solution_arns.append(solution['solutionArn'])

    return solution_arns


def _delete_recommenders(dataset_group_arn):
    recommender_arns = []
    recommenders_response = personalize.list_recommenders(datasetGroupArn=dataset_group_arn, maxResults=100)
    for recommender in recommenders_response['recommenders']:
        logger.info('Deleting recommender ' + recommender['recommenderArn'])
        personalize.delete_recommender(recommenderArn=recommender['recommenderArn'])
        recommender_arns.append(recommender['recommenderArn'])
    max_time = time.time() + 30 * 60  # 30 mins
    while time.time() < max_time:
        for recommender_arn in recommender_arns:
            try:
                describe_response = personalize.describe_recommender(recommenderArn=recommender_arn)
                logger.debug(
                    'Recommender {} status is {}'.format(recommender_arn, describe_response['recommender']['status']))
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceNotFoundException':
                    recommender_arns.remove(recommender_arn)

        if len(recommender_arns) == 0:
            logger.info('All recommenders have been deleted or none exist for dataset group')
            break
        else:
            logger.info('Waiting for {} recommender(s) to be deleted'.format(len(recommender_arns)))
            time.sleep(20)

    if len(recommender_arns) > 0:
        raise Exception('Timed out waiting for all recommender(s) to be deleted')


def _delete_campaigns(solution_arns):
    campaign_arns = []

    for solution_arn in solution_arns:
        paginator = personalize.get_paginator('list_campaigns')
        for paginate_result in paginator.paginate(solutionArn=solution_arn):
            for campaign in paginate_result['campaigns']:
                if campaign['status'] in ['ACTIVE', 'CREATE FAILED']:
                    logger.info('Deleting campaign: ' + campaign['campaignArn'])

                    personalize.delete_campaign(campaignArn=campaign['campaignArn'])
                elif campaign['status'].startswith('DELETE'):
                    logger.warning('Campaign {} is already being deleted so will wait for delete to complete'.format(
                        campaign['campaignArn']))
                else:
                    raise Exception(
                        'Campaign {} has a status of {} so cannot be deleted'.format(campaign['campaignArn'],
                                                                                     campaign['status']))

                campaign_arns.append(campaign['campaignArn'])

    max_time = time.time() + 30 * 60  # 30 mins
    while time.time() < max_time:
        for campaign_arn in campaign_arns:
            try:
                describe_response = personalize.describe_campaign(campaignArn=campaign_arn)
                logger.debug('Campaign {} status is {}'.format(campaign_arn, describe_response['campaign']['status']))
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceNotFoundException':
                    campaign_arns.remove(campaign_arn)

        if len(campaign_arns) == 0:
            logger.info('All campaigns have been deleted or none exist for dataset group')
            break
        else:
            logger.info('Waiting for {} campaign(s) to be deleted'.format(len(campaign_arns)))
            time.sleep(20)

    if len(campaign_arns) > 0:
        raise Exception('Timed out waiting for all campaigns to be deleted')


def _delete_solutions(solution_arns):
    for solution_arn in solution_arns:
        try:
            describe_response = personalize.describe_solution(solutionArn=solution_arn)
            solution = describe_response['solution']
            if solution['status'] in ['ACTIVE', 'CREATE FAILED']:
                logger.info('Deleting solution: ' + solution_arn)

                personalize.delete_solution(solutionArn=solution_arn)
            elif solution['status'].startswith('DELETE'):
                logger.warning(
                    'Solution {} is already being deleted so will wait for delete to complete'.format(solution_arn))
            else:
                raise Exception(
                    'Solution {} has a status of {} so cannot be deleted'.format(solution_arn, solution['status']))
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code != 'ResourceNotFoundException':
                raise e

    max_time = time.time() + 30 * 60  # 30 mins
    while time.time() < max_time:
        for solution_arn in solution_arns:
            try:
                describe_response = personalize.describe_solution(solutionArn=solution_arn)
                logger.debug('Solution {} status is {}'.format(solution_arn, describe_response['solution']['status']))
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceNotFoundException':
                    solution_arns.remove(solution_arn)

        if len(solution_arns) == 0:
            logger.info('All solutions have been deleted or none exist for dataset group')
            break
        else:
            logger.info('Waiting for {} solution(s) to be deleted'.format(len(solution_arns)))
            time.sleep(20)

    if len(solution_arns) > 0:
        raise Exception('Timed out waiting for all solutions to be deleted')


def _delete_event_trackers(dataset_group_arn):
    event_tracker_arns = []

    event_trackers_paginator = personalize.get_paginator('list_event_trackers')
    for event_tracker_page in event_trackers_paginator.paginate(datasetGroupArn=dataset_group_arn):
        for event_tracker in event_tracker_page['eventTrackers']:
            if event_tracker['status'] in ['ACTIVE', 'CREATE FAILED']:
                logger.info('Deleting event tracker {}'.format(event_tracker['eventTrackerArn']))
                personalize.delete_event_tracker(eventTrackerArn=event_tracker['eventTrackerArn'])
            elif event_tracker['status'].startswith('DELETE'):
                logger.warning('Event tracker {} is already being deleted so will wait for delete to complete'.format(
                    event_tracker['eventTrackerArn']))
            else:
                raise Exception(
                    'Solution {} has a status of {} so cannot be deleted'.format(event_tracker['eventTrackerArn'],
                                                                                 event_tracker['status']))

            event_tracker_arns.append(event_tracker['eventTrackerArn'])

    max_time = time.time() + 30 * 60  # 30 mins
    while time.time() < max_time:
        for event_tracker_arn in event_tracker_arns:
            try:
                describe_response = personalize.describe_event_tracker(eventTrackerArn=event_tracker_arn)
                logger.debug('Event tracker {} status is {}'.format(event_tracker_arn,
                                                                    describe_response['eventTracker']['status']))
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceNotFoundException':
                    event_tracker_arns.remove(event_tracker_arn)

        if len(event_tracker_arns) == 0:
            logger.info('All event trackers have been deleted or none exist for dataset group')
            break
        else:
            logger.info('Waiting for {} event tracker(s) to be deleted'.format(len(event_tracker_arns)))
            time.sleep(20)

    if len(event_tracker_arns) > 0:
        raise Exception('Timed out waiting for all event trackers to be deleted')


def _delete_filters(dataset_group_arn):
    filter_arns = []

    filters_response = personalize.list_filters(datasetGroupArn=dataset_group_arn, maxResults=100)
    for filter in filters_response['Filters']:
        logger.info('Deleting filter ' + filter['filterArn'])
        personalize.delete_filter(filterArn=filter['filterArn'])
        filter_arns.append(filter['filterArn'])

    max_time = time.time() + 30 * 60  # 30 mins
    while time.time() < max_time:
        for filter_arn in filter_arns:
            try:
                describe_response = personalize.describe_filter(filterArn=filter_arn)
                logger.debug('Filter {} status is {}'.format(filter_arn, describe_response['filter']['status']))
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceNotFoundException':
                    filter_arns.remove(filter_arn)

        if len(filter_arns) == 0:
            logger.info('All filters have been deleted or none exist for dataset group')
            break
        else:
            logger.info('Waiting for {} filter(s) to be deleted'.format(len(filter_arns)))
            time.sleep(20)

    if len(filter_arns) > 0:
        raise Exception('Timed out waiting for all filter to be deleted')


def _delete_datasets_and_schemas(dataset_group_arn):
    dataset_arns = []
    schema_arns = []

    dataset_paginator = personalize.get_paginator('list_datasets')
    for dataset_page in dataset_paginator.paginate(datasetGroupArn=dataset_group_arn):
        for dataset in dataset_page['datasets']:
            describe_response = personalize.describe_dataset(datasetArn=dataset['datasetArn'])
            schema_arns.append(describe_response['dataset']['schemaArn'])

            if dataset['status'] in ['ACTIVE', 'CREATE FAILED']:
                logger.info('Deleting dataset ' + dataset['datasetArn'])
                personalize.delete_dataset(datasetArn=dataset['datasetArn'])
            elif dataset['status'].startswith('DELETE'):
                logger.warning('Dataset {} is already being deleted so will wait for delete to complete'.format(
                    dataset['datasetArn']))
            else:
                raise Exception('Dataset {} has a status of {} so cannot be deleted'.format(dataset['datasetArn'],
                                                                                            dataset['status']))

            dataset_arns.append(dataset['datasetArn'])

    max_time = time.time() + 30 * 60  # 30 mins
    while time.time() < max_time:
        for dataset_arn in dataset_arns:
            try:
                describe_response = personalize.describe_dataset(datasetArn=dataset_arn)
                logger.debug('Dataset {} status is {}'.format(dataset_arn, describe_response['dataset']['status']))
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceNotFoundException':
                    dataset_arns.remove(dataset_arn)

        if len(dataset_arns) == 0:
            logger.info('All datasets have been deleted or none exist for dataset group')
            break
        else:
            logger.info('Waiting for {} dataset(s) to be deleted'.format(len(dataset_arns)))
            time.sleep(20)

    if len(dataset_arns) > 0:
        raise Exception('Timed out waiting for all datasets to be deleted')

    for schema_arn in schema_arns:
        try:
            logger.info('Deleting schema ' + schema_arn)
            personalize.delete_schema(schemaArn=schema_arn)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceInUseException':
                logger.info(
                    'Schema {} is still in-use by another dataset (likely in another dataset group)'.format(schema_arn))
            else:
                raise e

    logger.info('All schemas used exclusively by datasets have been deleted or none exist for dataset group')


def _delete_dataset_group(dataset_group_arn):
    logger.info('Deleting dataset group ' + dataset_group_arn)
    personalize.delete_dataset_group(datasetGroupArn=dataset_group_arn)

    max_time = time.time() + 30 * 60  # 30 mins
    while time.time() < max_time:
        try:
            describe_response = personalize.describe_dataset_group(datasetGroupArn=dataset_group_arn)
            logger.debug(
                'Dataset group {} status is {}'.format(dataset_group_arn, describe_response['datasetGroup']['status']))
            break
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                logger.info('Dataset group {} has been fully deleted'.format(dataset_group_arn))
            else:
                raise e

        logger.info('Waiting for dataset group to be deleted')
        time.sleep(20)


def delete_dataset_groups(dataset_group_arns, region=None):
    global personalize
    personalize = boto3.client(service_name='personalize', region_name=region)

    for dataset_group_arn in dataset_group_arns:
        logger.info('Dataset Group ARN: ' + dataset_group_arn)

        solution_arns = _get_solutions(dataset_group_arn)

        # 1. Delete Recommenders
        _delete_recommenders(dataset_group_arn)

        # 2. Delete campaigns
        _delete_campaigns(solution_arns)

        # 3. Delete solutions
        _delete_solutions(solution_arns)

        # 4. Delete event trackers
        _delete_event_trackers(dataset_group_arn)

        # 5. Delete filters
        _delete_filters(dataset_group_arn)

        # 6. Delete datasets and their schemas
        _delete_datasets_and_schemas(dataset_group_arn)

        # 7. Delete dataset group
        _delete_dataset_group(dataset_group_arn)

        logger.info(f'Dataset group {dataset_group_arn} fully deleted')
