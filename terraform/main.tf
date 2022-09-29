provider "aws" {
  region = "us-west-2"
  profile = "Admin" #TODO: Remove this
  default_tags {
    tags = {
      app_name = "security_hawk"
      dept     = "awslabs"
    }
  }
}

resource "aws_cloudwatch_event_rule" "sspg_sh_findings_rule" {
  name        = "sspg-sh-findings-rule"
  description = "Capture events of the Security Hub findings"

  event_pattern = <<EOF
{
  "source": ["aws.securityhub"],
  "detail-type": ["Security Hub Findings - Imported"]
}
EOF
}

resource "aws_cloudwatch_event_target" "firehose_delivery_stream_target" {
  target_id = "firehose-delivery-stream-target"
  rule      = aws_cloudwatch_event_rule.sspg_sh_findings_rule.name
  arn       = aws_kinesis_firehose_delivery_stream.sspg_findings_stream.arn
  role_arn  = aws_iam_role.sspg_eventbridge_firehose_role.arn

}

resource "aws_iam_role" "sspg_eventbridge_firehose_role" {
  name = "sspg-eventbridge-firehose-role"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "events.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
}

resource "aws_iam_policy" "sspg_eventbridge_firehose_policy" {
  name        = "sspg-eventbridge-firehose-policy"
  path        = "/"
  description = "My test policy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
        {
            Effect = "Allow",
            Action = [
                "firehose:PutRecord",
                "firehose:PutRecordBatch"
            ],
            Resource = [
                aws_kinesis_firehose_delivery_stream.sspg_findings_stream.arn
            ]
        }
    ]
})
}

resource "aws_iam_role_policy_attachment" "sspg_eventbridge_policy_attachment" {
 role        = aws_iam_role.sspg_eventbridge_firehose_role.name
 policy_arn  = aws_iam_policy.sspg_eventbridge_firehose_policy.arn
}