# MVISION Insights & AWS GuardDuty Integrations

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
---

Threat Intelligence is a critical component for improving fidelity of alerts and improving the overall mean time to respond. AWS guard duty provides extensive managed threat hunting capabilities for their cloud customers. Guard Duty comes with built-in threat detection playbooks and telemetry correlation. Guard Duty can detect network , IAM and
workload behaviour anomalies. Threat intelligence plays a vital role in the preparation
phase of a Cloud incident. Threat intel helps Guarduty to automatically raise
the severity of the findings when there is threat intel hit and also bring additional
context. The goal of the solution was to use MVISION Insights
campaign data to enrich the Guard Duty findings.



## Integration Architecture

![image](https://user-images.githubusercontent.com/60926235/143061272-4b84a1c8-2a66-4d11-8c36-3b667194c70d.png)

### Install Pre-Reqs:

To use the provided Lambda script, you need to build the Lambda python layer with the dependencies provided in the requirements.txt file.



Minimum Permissions the Lambda Execution Role attached to the Lambda Funtion must have at a minimum the following policy bellow

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:GetObjectVersion"
            ],
            "Resource": [
                "arn:aws:s3:::*/*",
                "arn:aws:s3:::<replace with your S3 Bucket>"
            ]
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "guardduty:GetFindings",
                "guardduty:ListThreatIntelSets",
                "secretsmanager:DescribeSecret",
                "guardduty:GetThreatIntelSet",
                "guardduty:DeleteIPSet",
                "guardduty:CreateDetector",
                "iam:PutRolePolicy",
                "guardduty:UpdateMemberDetectors",
                "guardduty:GetDetector",
                "secretsmanager:ListSecretVersionIds",
                "secretsmanager:GetRandomPassword",
                "logs:CreateLogStream",
                "secretsmanager:GetSecretValue",
                "ec2:DescribeNetworkInterfaces",
                "guardduty:DeleteDetector",
                "guardduty:CreatePublishingDestination",
                "guardduty:GetFilter",
                "guardduty:ListIPSets",
                "guardduty:ListDetectors",
                "ec2:DeleteNetworkInterface",
                "guardduty:UpdateThreatIntelSet",
                "guardduty:CreateIPSet",
                "guardduty:UpdateDetector",
                "guardduty:GetIPSet",
                "guardduty:CreateThreatIntelSet",
                "guardduty:UpdateFilter",
                "logs:CreateLogGroup",
                "logs:PutLogEvents",
                "ec2:CreateNetworkInterface",
                "guardduty:CreateFilter",
                "guardduty:UpdateIPSet",
                "guardduty:CreateMembers",
                "guardduty:UpdatePublishingDestination",
                "guardduty:DeleteThreatIntelSet",
                "guardduty:ListFilters"
            ],
            "Resource": "*"
        }
    ]
}
```

#### Other Component Configuration:

AWS Secret Manager : Use to store the MVISION API Credentials securely.

```json
{
  "mv_api_key": "<your api key>",
  "mv_client_id": "<client id>",
  "mv_secret": "<secret>"
}
```

Configure Lambda Environment Variables as follows :

![image](https://user-images.githubusercontent.com/60926235/143058823-74f37b41-1586-4af9-935f-9094fc226edf.png)

Configure event bridge scheduled event as a trigger for Lambda:

![](C:\Users\arnab\AppData\Roaming\marktext\images\2021-11-23-16-04-48-image.png)

Note: The event schedule rate should match the value for ins_dur environment variable in the lambda function

### **Testing**

You can generate test events in guardDuty by taking a sample IP/ Domain from the Insights feed and run a query to that malicious IP from an EC2 Instance and it should generate some findings in the GuardDuty
