# Terraform configuration with INTENTIONAL security vulnerabilities
# DO NOT USE IN PRODUCTION - FOR TESTING ONLY

terraform {
  required_version = ">= 1.0"
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

# Variables
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
  default     = "insecure-test-bucket"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "test"
}

# Random suffix for unique bucket name
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# CRITICAL FINDING #1: S3 bucket with completely open public access
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "${var.bucket_name}-${random_string.suffix.result}"
  force_destroy = true  # FINDING: Force destroy enabled

  tags = {
    Name        = "Vulnerable Test Bucket"
    Environment = var.environment
    Purpose     = "security-testing"
    # FINDING: Missing required tags like Owner, CostCenter
  }
}

# CRITICAL FINDING #2: All public access protections disabled
resource "aws_s3_bucket_public_access_block" "vulnerable_bucket_pab" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false  # CRITICAL: Should be true
  block_public_policy     = false  # CRITICAL: Should be true
  ignore_public_acls      = false  # CRITICAL: Should be true
  restrict_public_buckets = false  # CRITICAL: Should be true
}

# CRITICAL FINDING #3: Bucket policy with wildcard permissions
resource "aws_s3_bucket_policy" "vulnerable_bucket_policy" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"  # CRITICAL: Wildcard principal
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.vulnerable_bucket.arn,
          "${aws_s3_bucket.vulnerable_bucket.arn}/*"
        ]
      },
      {
        Sid       = "PublicWriteAccess"
        Effect    = "Allow"
        Principal = "*"  # CRITICAL: Public write access
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      },
      {
        Sid       = "DangerousAdminAccess"
        Effect    = "Allow"
        Principal = "*"  # CRITICAL: Public admin access
        Action = [
          "s3:*"  # CRITICAL: Wildcard action
        ]
        Resource = [
          aws_s3_bucket.vulnerable_bucket.arn,
          "${aws_s3_bucket.vulnerable_bucket.arn}/*"
        ]
      }
    ]
  })
}

# HIGH FINDING #4: No server-side encryption or weak encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "vulnerable_bucket_encryption" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # HIGH: Should use aws:kms
      # kms_master_key_id = aws_kms_key.bucket_key.arn  # Missing KMS key
    }
    bucket_key_enabled = false  # HIGH: Should be true for cost optimization
  }
}

# HIGH FINDING #5: Versioning disabled
resource "aws_s3_bucket_versioning" "vulnerable_bucket_versioning" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  versioning_configuration {
    status = "Disabled"  # HIGH: Should be "Enabled"
  }
}

# MEDIUM FINDING #6: No MFA delete protection
# Note: MFA delete can only be enabled via CLI/API, not Terraform
# This is a configuration gap that scanners may flag

# MEDIUM FINDING #7: No access logging
# Intentionally commented out - missing logging is a finding
# resource "aws_s3_bucket_logging" "vulnerable_bucket_logging" {
#   bucket = aws_s3_bucket.vulnerable_bucket.id
#   target_bucket = aws_s3_bucket.log_bucket.id
#   target_prefix = "access-logs/"
# }

# MEDIUM FINDING #8: No lifecycle configuration
# Missing lifecycle rules for cost optimization and data management

# LOW FINDING #9: No notification configuration
# Missing event notifications for security monitoring

# CRITICAL FINDING #10: Bucket ACL with public permissions
resource "aws_s3_bucket_acl" "vulnerable_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.vulnerable_bucket_ownership]
  bucket     = aws_s3_bucket.vulnerable_bucket.id
  acl        = "public-read-write"  # CRITICAL: Public ACL
}

resource "aws_s3_bucket_ownership_controls" "vulnerable_bucket_ownership" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"  # MEDIUM: Should be BucketOwnerEnforced
  }
}

# HIGH FINDING #11: CORS configuration too permissive
resource "aws_s3_bucket_cors_configuration" "vulnerable_bucket_cors" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  cors_rule {
    allowed_headers = ["*"]  # HIGH: Wildcard headers
    allowed_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]  # HIGH: Too many methods
    allowed_origins = ["*"]  # CRITICAL: Wildcard origins
    expose_headers  = ["*"]  # MEDIUM: Wildcard expose headers
    max_age_seconds = 3000
  }
}

# MEDIUM FINDING #12: Website configuration enabled
resource "aws_s3_bucket_website_configuration" "vulnerable_bucket_website" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

# HIGH FINDING #13: No request payer configuration
# Missing request payer configuration for cost control

# MEDIUM FINDING #14: No object lock configuration
# Missing object lock for compliance and data protection

# LOW FINDING #15: No intelligent tiering
# Missing intelligent tiering for cost optimization

# CRITICAL FINDING #16: IAM role with overly broad S3 permissions
resource "aws_iam_role" "vulnerable_s3_role" {
  name = "vulnerable-s3-role-${random_string.suffix.result
