resource "aws_athena_workgroup" "sspg_athena_workgroup" {
  name = "sspg-athena-workgroup"
  description = "Athena workgroup used by SSPG Grafana Instance for querying"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false 

    result_configuration {
      output_location = "s3://${aws_s3_bucket.sspg_athena_queries.bucket}/output/"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}