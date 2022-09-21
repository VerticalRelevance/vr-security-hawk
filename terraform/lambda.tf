resource "aws_iam_role" "sspg_lambda_role" {
  name = "sspg-lambda-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "sspg_lambda_policy_attachment" {
 role        = aws_iam_role.sspg_lambda_role.name
 policy_arn  = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}


data "archive_file" "zip_the_python_lambda" {
type        = "zip"
source_dir  = "${path.module}/lambda/"
output_path = "${path.module}/lambda_code.zip"
}

resource "aws_lambda_function" "sspg_transform_lambda" {
filename                       = "${path.module}/lambda_code.zip"
function_name                  = "sspg_transform_data_lambda"
description = "Lambda to transform Security Hub data from Kinesis into Athena usable JSON format."
role                           = aws_iam_role.sspg_lambda_role.arn
handler                        = "lambda_function.lambda_handler"
runtime                        = "python3.9"
depends_on                     = [aws_iam_role_policy_attachment.sspg_lambda_policy_attachment]
timeout                        = 60
}