resource "aws_grafana_workspace" "sspg_grafana_workspace" {
  name                     = "sspg-grafana-workspace"
  account_access_type      = "CURRENT_ACCOUNT"
  authentication_providers = ["AWS_SSO"]
  permission_type          = "CUSTOMER_MANAGED"
  role_arn                 = aws_iam_role.sspg_grafana_workspace_role.arn
  data_sources             = [ "ATHENA" ]
  description              = "Grafana workspace for Security Single Pane of Glass."
}

resource "aws_iam_role" "sspg_grafana_workspace_role" {
  name = "sspg-grafana-workspace-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "grafana.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "sspg_athena_policy_attachment" {
 role        = aws_iam_role.sspg_grafana_workspace_role.name
 policy_arn  = "arn:aws:iam::aws:policy/service-role/AmazonGrafanaAthenaAccess"
}

resource "aws_iam_policy" "sspg_grafana_athena_s3_access_policy" {
  name        = "sspg-grafana-athena-s3-access-policy"
  description = "Policy for Grafana to access Athena and S3 resources"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode(
{
    Version =  "2012-10-17",
    Statement =  [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAccessPointsForObjectLambda",
                "s3:GetAccessPoint",
                "athena:ListEngineVersions",
                "s3:PutAccountPublicAccessBlock",
                "athena:ListDataCatalogs",
                "s3:ListAccessPoints",
                "s3:ListJobs",
                "s3:PutStorageLensConfiguration",
                "s3:ListMultiRegionAccessPoints",
                "athena:ListWorkGroups",
                "s3:ListStorageLensConfigurations",
                "s3:GetAccountPublicAccessBlock",
                "s3:ListAllMyBuckets",
                "s3:PutAccessPointPublicAccessBlock",
                "s3:CreateJob"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": [
                "${aws_s3_bucket.sspg_findings.arn}",
                "${aws_s3_bucket.sspg_findings.arn}/*",
                "${aws_s3_bucket.sspg_athena_queries.arn}",
                "${aws_s3_bucket.sspg_athena_queries.arn}/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": "athena:*",
            "Resource": [
                "arn:aws:athena:*:899456967600:datacatalog/*",
                "arn:aws:athena:*:899456967600:workgroup/*"
            ]
        }
    ]
}
  )
}

resource "aws_iam_role_policy_attachment" "sspg_grafana_athena_s3_policy_attachment" {
 role        = aws_iam_role.sspg_grafana_workspace_role.name
 policy_arn  = aws_iam_policy.sspg_grafana_athena_s3_access_policy.arn
}