import json
import gzip
import base64
import boto3
import random

ec2 = boto3.client('ec2')
sns = boto3.client('sns')

NACL_ID = "acl-08083***865897e05"
SNS_TOPIC_ARN = "arn:aws:****"

# Simple in-memory counter
ip_counter = {}

# Threshold before blocking
THRESHOLD = 5

def lambda_handler(event, context):

    compressed_payload = base64.b64decode(event['awslogs']['data'])
    uncompressed_payload = gzip.decompress(compressed_payload)
    logs_data = json.loads(uncompressed_payload)

    for log_event in logs_data['logEvents']:

        message = log_event['message']
        print("Received Log:", message)

        fields = message.split()

        try:
            src_ip = fields[3]
            dst_port = fields[6]
            action = fields[12]

            print(f"IP: {src_ip}")
            print(f"Port: {dst_port}")
            print(f"Action: {action}")

            # Detect SSH traffic
            if dst_port == "22":

                # Initialize counter
                if src_ip not in ip_counter:
                    ip_counter[src_ip] = 0

                # Increase count
                ip_counter[src_ip] += 1

                print(f"{src_ip} count = {ip_counter[src_ip]}")

                # Block only after threshold exceeded
                if ip_counter[src_ip] >= THRESHOLD:

                    print(f"Blocking IP {src_ip}")

                    rule_number = random.randint(200, 300)

                    ec2.create_network_acl_entry(
                        NetworkAclId=NACL_ID,
                        RuleNumber=rule_number,
                        Protocol='6',
                        RuleAction='deny',
                        Egress=False,
                        CidrBlock=f"{src_ip}/32",
                        PortRange={
                            'From': 22,
                            'To': 22
                        }
                    )

                    print("NACL rule created")

                    sns.publish(
                        TopicArn=SNS_TOPIC_ARN,
                        Subject='Brute Force Detected',
                        Message=f'Blocked IP {src_ip} after {THRESHOLD} SSH attempts'
                    )

                    print("SNS alert sent")

                    # Reset counter after blocking
                    ip_counter[src_ip] = 0

        except Exception as e:
            print("Error:", str(e))
