# WARNING: This Terraform configuration contains INTENTIONAL security vulnerabilities
# for testing security scanning tools. DO NOT use in production environments!

terraform {
  required_version = ">= 0.12"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
  default     = "vulnerable-test-bucket-12345"
}

# CRITICAL FINDING 1: S3 bucket with public read access
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = var.bucket_name

  tags = {
    Name        = "VulnerableTestBucket"
    Environment = "Testing"
    Purpose     = "SecurityScanTesting"
  }
}

# CRITICAL FINDING 2: Public ACL allowing public read access
resource "aws_s3_bucket_acl" "vulnerable_acl" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  acl    = "public-read"
  
  depends_on = [aws_s3_bucket_ownership_controls.s3_bucket_acl_ownership]
}

# Required for ACL to work
resource "aws_s3_bucket_ownership_controls" "s3_bucket_acl_ownership" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# CRITICAL FINDING 3: Bucket policy allowing public access
resource "aws_s3_bucket_policy" "vulnerable_policy" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      },
      {
        Sid       = "PublicListBucket"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.vulnerable_bucket.arn
      }
    ]
  })
}

# CRITICAL FINDING 4: No server-side encryption configured
# (Intentionally omitting aws_s3_bucket_server_side_encryption_configuration)

# CRITICAL FINDING 5: No versioning enabled
resource "aws_s3_bucket_versioning" "vulnerable_versioning" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  versioning_configuration {
    status = "Disabled"
  }
}

# CRITICAL FINDING 6: No MFA delete protection
# (MFA delete can only be enabled via CLI/API, not Terraform, but this shows the intent)

# CRITICAL FINDING 7: Logging disabled
# (Intentionally omitting aws_s3_bucket_logging)

# CRITICAL FINDING 8: No lifecycle configuration for sensitive data
# (Intentionally omitting aws_s3_bucket_lifecycle_configuration)

# CRITICAL FINDING 9: CORS configuration allowing all origins
resource "aws_s3_bucket_cors_configuration" "vulnerable_cors" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

# CRITICAL FINDING 10: Website configuration with public access
resource "aws_s3_bucket_website_configuration" "vulnerable_website" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

# CRITICAL FINDING 11: Public access block disabled
resource "aws_s3_bucket_public_access_block" "vulnerable_pab" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# CRITICAL FINDING 12: Notification configuration with insecure SNS topic
resource "aws_sns_topic" "vulnerable_topic" {
  name = "vulnerable-s3-notifications"
  
  # No encryption configured
  # No access policy restrictions
}

resource "aws_sns_topic_policy" "vulnerable_topic_policy" {
  arn = aws_sns_topic.vulnerable_topic.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = [
          "SNS:Subscribe",
          "SNS:Receive",
          "SNS:Publish"
        ]
        Resource = aws_sns_topic.vulnerable_topic.arn
      }
    ]
  })
}

resource "aws_s3_bucket_notification" "vulnerable_notification" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  topic {
    topic_arn = aws_sns_topic.vulnerable_topic.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.vulnerable_topic_policy]
}

# CRITICAL FINDING 13: Object with public-read ACL
resource "aws_s3_object" "vulnerable_object" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  key    = "sensitive-data.txt"
  content = "This file contains sensitive information that should not be public!"
  acl    = "public-read"
  
  # No server-side encryption
  # No metadata restrictions
  
  depends_on = [aws_s3_bucket_acl.vulnerable_acl]
}

# Additional vulnerable resources for more findings

# CRITICAL FINDING 14: IAM role with overly permissive S3 access
resource "aws_iam_role" "vulnerable_role" {
  name = "VulnerableS3Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = "*"  # CRITICAL: Allows anyone to assume this role
      }
    ]
  })
}

resource "aws_iam_role_policy" "vulnerable_policy_attachment" {
  name = "VulnerableS3Policy"
  role = aws_iam_role.vulnerable_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*"  # CRITICAL: Full S3 access
        ]
        Resource = "*"  # CRITICAL: On all resources
      }
    ]
  })
}

# Outputs for testing
output "bucket_name" {
  description = "Name of the vulnerable S3 bucket"
  value       = aws_s3_bucket.vulnerable_bucket.id
}

output "bucket_arn" {
  description = "ARN of the vulnerable S3 bucket"
  value       = aws_s3_bucket.vulnerable_bucket.arn
}

output "bucket_website_endpoint" {
  description = "Website endpoint of the bucket"
  value       = aws_s3_bucket_website_configuration.vulnerable_website.website_endpoint
}

output "sns_topic_arn" {
  description = "ARN of the vulnerable SNS topic"
  value       = aws_sns_topic.vulnerable_topic.arn
}

output "vulnerable_role_arn" {
  description = "ARN of the vulnerable IAM role"
  value       = aws_iam_role.vulnerable_role.arn
}
