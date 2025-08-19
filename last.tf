# Terraform configuration with intentional critical errors
terraform {
  required_version = ">= 0.12"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

# Missing provider configuration - Critical Error #1
# provider "aws" {
#   region = "us-east-1"
# }

# S3 bucket with critical security and configuration issues
resource "aws_s3_bucket" "example_bucket" {
  bucket = "my-super-insecure-bucket-${random_string.bucket_suffix.result}"
  
  # Critical Error #2: Deprecated argument (should use separate resources)
  acl = "public-read"
  
  # Critical Error #3: Deprecated argument (should use aws_s3_bucket_cors_configuration)
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
  
  # Critical Error #4: Deprecated argument (should use aws_s3_bucket_versioning)
  versioning {
    enabled = false
  }
  
  # Critical Error #5: Deprecated argument (should use aws_s3_bucket_server_side_encryption_configuration)
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  # Critical Error #6: Deprecated argument (should use aws_s3_bucket_lifecycle_configuration)
  lifecycle_rule {
    id      = "log"
    enabled = true
    
    expiration {
      days = 90
    }
  }
  
  # Critical Error #7: Force destroy without proper consideration
  force_destroy = true
  
  tags = {
    Name        = "InsecureBucket"
    Environment = "production"  # Critical Error #8: Insecure bucket in production
  }
}

# Critical Error #9: Missing resource definition
resource "random_string" "bucket_suffix" {
  # Missing length and other required arguments
}

# Critical Error #10: Public bucket policy allowing unrestricted access
resource "aws_s3_bucket_policy" "bucket_policy" {
  bucket = aws_s3_bucket.example_bucket.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"  # Critical Error #11: Wildcard principal
        Action    = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"  # Critical Error #12: Public delete permissions
        ]
        Resource = "${aws_s3_bucket.example_bucket.arn}/*"
      }
    ]
  })
}

# Critical Error #13: Public access block disabled
resource "aws_s3_bucket_public_access_block" "bucket_pab" {
  bucket = aws_s3_bucket.example_bucket.id
  
  block_public_acls       = false  # Should be true
  block_public_policy     = false  # Should be true
  ignore_public_acls      = false  # Should be true
  restrict_public_buckets = false  # Should be true
}

# Critical Error #14: Referencing non-existent resource
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.nonexistent_bucket.id  # Wrong bucket reference
  
  topic {
    topic_arn = "arn:aws:sns:us-east-1:123456789012:nonexistent-topic"
    events    = ["s3:ObjectCreated:*"]
  }
}

# Critical Error #15: Invalid output reference
output "bucket_url" {
  value = aws_s3_bucket.example_bucket.bucket_domain_name  # Incorrect attribute
}

# Critical Error #16: Missing required variable
variable "environment" {
  description = "Environment name"
  # Missing type and default
}

# Critical Error #17: Hardcoded sensitive values
locals {
  aws_access_key = "AKIAIOSFODNN7EXAMPLE"  # Hardcoded credentials
  aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
