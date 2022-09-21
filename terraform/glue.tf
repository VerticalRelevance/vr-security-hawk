resource "aws_glue_catalog_database" "sspg_glue_database" {
  name = "sspg_glue_database"
}

resource "aws_glue_crawler" "sspg_glue_crawler" {
  database_name = aws_glue_catalog_database.sspg_glue_database.name
  name          = "sspg_findings_crawler"
  role          = aws_iam_role.sspg_glue_crawler_role.arn
  schedule      = "cron(20 * * * ? *)"
  recrawl_policy {
    recrawl_behavior = "CRAWL_EVERYTHING"
  }
  schema_change_policy {
    delete_behavior = "LOG"
    update_behavior = "LOG"
  }
  s3_target {
    path = "s3://${aws_s3_bucket.sspg_findings.bucket}/sh_findings/"
  }
}

resource "aws_iam_role" "sspg_glue_crawler_role" {
  name = "sspg-glue-crawler-role"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "glue.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
}

resource "aws_iam_policy" "sspg_glue_crawler_s3_policy" {
  name        = "sspg-glue-crawler-s3-policy"
  description = "Policy for Glue Crawler to access S3 bucket."

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode(
{
    Version = "2012-10-17",
    Statement = [
        {
            Effect = "Allow",
            Action = [
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:PutObject"
            ],
            Resource = [
                "${aws_s3_bucket.sspg_findings.arn}",
                "${aws_s3_bucket.sspg_findings.arn}/*"
            ]
        }
    ]
}
  )
}

resource "aws_iam_role_policy_attachment" "sspg_glue_s3_policy_attachment" {
 role        = aws_iam_role.sspg_glue_crawler_role.name
 policy_arn  = aws_iam_policy.sspg_glue_crawler_s3_policy.arn
}

resource "aws_iam_role_policy_attachment" "sspg_glue_service_role_attachment" {
 role        = aws_iam_role.sspg_glue_crawler_role.name
 policy_arn  = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}