# Terraform template demonstrating S3 bucket misconfiguration - Access to Any Principal
# WARNING: This is for security testing and training purposes only!

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "bucket_name" {
  description = "Name for the S3 bucket (must be globally unique)"
  type        = string
  default     = "misconfigured-bucket-any-principal"
  
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.bucket_name))
    error_message = "Bucket name must be lowercase, start and end with alphanumeric characters."
  }
}

variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "test"
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Random suffix to ensure bucket name uniqueness
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# S3 Bucket with misconfiguration
resource "aws_s3_bucket" "misconfigured_bucket" {
  bucket = "${var.bucket_name}-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "Misconfigured S3 Bucket"
    Environment = var.environment
    Purpose     = "Security Testing"
    Warning     = "MISCONFIGURED - Any Principal Access"
  }
}

# Disable Public Access Block (enables the misconfiguration)
resource "aws_s3_bucket_public_access_block" "misconfigured_pab" {
  bucket = aws_s3_bucket.misconfigured_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Enable versioning
resource "aws_s3_bucket_versioning" "misconfigured_versioning" {
  bucket = aws_s3_bucket.misconfigured_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "misconfigured_encryption" {
  bucket = aws_s3_bucket.misconfigured_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Bucket policy with ANY principal misconfiguration
resource "aws_s3_bucket_policy" "misconfigured_policy" {
  bucket = aws_s3_bucket.misconfigured_bucket.id
  
  # Ensure public access block is configured first
  depends_on = [aws_s3_bucket_public_access_block.misconfigured_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAnyPrincipalAccess"
        Effect    = "Allow"
        Principal = "*"  # This is the misconfiguration - allows ANY principal
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.misconfigured_bucket.arn,
          "${aws_s3_bucket.misconfigured_bucket.arn}/*"
        ]
      }
    ]
  })
}

# Optional: Create a sample object to demonstrate the vulnerability
resource "aws_s3_object" "sample_object" {
  bucket = aws_s3_bucket.misconfigured_bucket.id
  key    = "sample-file.txt"
  content = "This file is accessible by ANY AWS principal due to misconfiguration!"
  
  tags = {
    Purpose = "Demonstration"
    Warning = "Publicly accessible due to bucket policy"
  }
}

# Outputs
output "bucket_name" {
  description = "Name of the misconfigured S3 bucket"
  value       = aws_s3_bucket.misconfigured_bucket.id
}

output "bucket_arn" {
  description = "ARN of the misconfigured S3 bucket"
  value       = aws_s3_bucket.misconfigured_bucket.arn
}

output "bucket_domain_name" {
  description = "Domain name of the S3 bucket"
  value       = aws_s3_bucket.misconfigured_bucket.bucket_domain_name
}

output "bucket_regional_domain_name" {
  description = "Regional domain name of the S3 bucket"
  value       = aws_s3_bucket.misconfigured_bucket.bucket_regional_domain_name
}

output "security
