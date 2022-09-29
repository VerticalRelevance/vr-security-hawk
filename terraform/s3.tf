resource "random_string" "s3_id" {
  length           = 6
  special          = false
  lower            = true
  upper            = false
}

resource "aws_s3_bucket" "sspg_findings" {
  bucket = "sspg-sh-findings-${random_string.s3_id.id}"
}

resource "aws_s3_bucket" "sspg_athena_queries" {
  bucket = "sspg-athena-queries-${random_string.s3_id.id}"
}

resource "aws_s3_bucket_lifecycle_configuration" "delete_expired_sh_findings" {
  bucket = aws_s3_bucket.sspg_findings.id
  rule {
    status = "Enabled"
    id     = "expire_all_files"
    expiration {
        days = 3
    }
  }
}