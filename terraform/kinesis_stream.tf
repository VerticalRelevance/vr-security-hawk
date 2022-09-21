resource "aws_kinesis_firehose_delivery_stream" "sspg_findings_stream" {
  name        = "sspg-findings-delivery-stream"
  destination = "extended_s3"

  lifecycle {
    ignore_changes = [
      extended_s3_configuration[0].processing_configuration[0].processors[0],
    ]
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.sspg_findings_stream_role.arn
    bucket_arn = aws_s3_bucket.sspg_findings.arn
    prefix = "sh_findings/"
    error_output_prefix = "errors/"
    processing_configuration {
      enabled = "true"


      processors {
        type = "Lambda"
        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.sspg_transform_lambda.arn}:$LATEST"
        }
        parameters {
           parameter_name = "BufferSizeInMBs"
           parameter_value = "3"
        }
        parameters {
           parameter_name = "BufferIntervalInSeconds"
           parameter_value = "60"
        }
      }
    }

    cloudwatch_logging_options {
        enabled = false # Set to true for debugging
    }
  }
}

resource "aws_iam_role" "sspg_findings_stream_role" {
  name = "sspg-findings-stream-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "firehose.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_policy" "sspg_kinesis_access_policy" {
  name        = "sspg-kinesis-access-policy"
  description = "My test policy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
        {
            Effect = "Allow",
            Action = [
                "glue:GetTable",
                "glue:GetTableVersion",
                "glue:GetTableVersions"
            ],
            Resource = [
                "arn:aws:glue:us-west-2:899456967600:catalog",
                "arn:aws:glue:us-west-2:899456967600:database/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%",
                "arn:aws:glue:us-west-2:899456967600:table/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
            ]
        },
        {
            Effect = "Allow",
            Action = [
                "s3:AbortMultipartUpload",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:PutObject"
            ],
            Resource = [
                "${aws_s3_bucket.sspg_findings.arn}",
                "${aws_s3_bucket.sspg_findings.arn}/*"
            ]
        },
        {
            Effect = "Allow",
            Action = [
                "lambda:InvokeFunction",
                "lambda:GetFunctionConfiguration"
            ],
            Resource = "${aws_lambda_function.sspg_transform_lambda.arn}:$LATEST"
        },
        {
            Effect = "Allow",
            Action = [
                "kms:GenerateDataKey",
                "kms:Decrypt"
            ],
            Resource = [
                "arn:aws:kms:us-west-2:899456967600:key/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
            ],
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": "s3.us-west-2.amazonaws.com"
                },
                "StringLike": {
                    "kms:EncryptionContext:aws:s3:arn": [
                        "arn:aws:s3:::%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%/*",
                        "arn:aws:s3:::%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
                    ]
                }
            }
        },
        {
            Effect = "Allow",
            Action = [
                "logs:PutLogEvents"
            ],
            Resource = [
                "arn:aws:logs:us-west-2:899456967600:log-group:/aws/kinesisfirehose/*:log-stream:*",
                "arn:aws:logs:us-west-2:899456967600:log-group:%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%:log-stream:*"
            ]
        },
        {
            Effect = "Allow",
            Action = [
                "kinesis:DescribeStream",
                "kinesis:GetShardIterator",
                "kinesis:GetRecords",
                "kinesis:ListShards"
            ],
            Resource = "arn:aws:kinesis:us-west-2:899456967600:stream/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
        },
        {
            Effect = "Allow",
            Action = [
                "kms:Decrypt"
            ],
            Resource = [
                "arn:aws:kms:us-west-2:899456967600:key/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
            ],
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": "kinesis.us-west-2.amazonaws.com"
                },
                "StringLike": {
                    "kms:EncryptionContext:aws:kinesis:arn": "arn:aws:kinesis:us-west-2:899456967600:stream/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
                }
            }
        }
    ]
})
}

resource "aws_iam_role_policy_attachment" "sspg_kinesis_policy_attachment" {
 role        = aws_iam_role.sspg_findings_stream_role.name
 policy_arn  = aws_iam_policy.sspg_kinesis_access_policy.arn
}