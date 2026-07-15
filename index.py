import boto3
import json
import logging
import re
import urllib.request
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")

VPCE_PATTERN = re.compile(r"^vpce-[a-zA-Z0-9]+$")


def send(event, context, status, data=None, reason=None):
    response = {
        "Status": status,
        "Reason": reason or "See CloudWatch Logs",
        "PhysicalResourceId": event.get(
            "PhysicalResourceId",
            context.log_stream_name
        ),
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Data": data or {}
    }

    logger.info(json.dumps(response))

    req = urllib.request.Request(
        event["ResponseURL"],
        data=json.dumps(response).encode("utf-8"),
        method="PUT"
    )

    urllib.request.urlopen(req)


def validate_endpoint(endpoint_id):
    if not VPCE_PATTERN.match(endpoint_id):
        raise ValueError(f"Invalid VPC Endpoint Id: {endpoint_id}")


def validate_policy(policy):
    try:
        document = json.loads(policy)
    except json.JSONDecodeError as ex:
        raise ValueError(f"Invalid JSON Policy: {str(ex)}")

    if "Version" not in document:
        raise ValueError("Policy must contain Version")

    if "Statement" not in document:
        raise ValueError("Policy must contain Statement")

    if not isinstance(document["Statement"], list):
        raise ValueError("Statement must be a list")


def endpoint_exists(endpoint_id):
    response = ec2.describe_vpc_endpoints(
        VpcEndpointIds=[endpoint_id]
    )

    if len(response["VpcEndpoints"]) == 0:
        raise ValueError(f"VPC Endpoint {endpoint_id} not found")


def update_policy(endpoint_id, policy):
    ec2.modify_vpc_endpoint(
        VpcEndpointId=endpoint_id,
        PolicyDocument=policy
    )


def handler(event, context):

    logger.info(json.dumps(event))

    try:

        request_type = event["RequestType"]

        if request_type == "Delete":
            send(event, context, "SUCCESS")
            return

        props = event["ResourceProperties"]

        endpoint = props["VpcEndpointId"]

        policy = props["PolicyDocument"]

        validate_endpoint(endpoint)

        validate_policy(policy)

        endpoint_exists(endpoint)

        update_policy(endpoint, policy)

        send(
            event,
            context,
            "SUCCESS",
            {
                "VpcEndpointId": endpoint
            }
        )

    except ClientError as ex:

        logger.exception(ex)

        send(
            event,
            context,
            "FAILED",
            reason=str(ex)
        )

    except Exception as ex:

        logger.exception(ex)

        send(
            event,
            context,
            "FAILED",
            reason=str(ex)
        )
