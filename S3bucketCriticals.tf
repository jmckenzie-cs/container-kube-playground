# WARNING: This template contains CRITICAL SECURITY ISSUES for demonstration purposes
# DO NOT use this in production without addressing the security findings below

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
  region = "us-east-1"
}

# CRITICAL FINDING 1: S3 bucket with public read access
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-super-insecure-bucket-${random_string.suffix.result}"
  
  tags = {
    Environment = "production"
    Purpose     = "data-storage"
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# CRITICAL FINDING 2: Public ACL allowing public read access
resource "aws_s3_bucket_acl" "vulnerable_acl" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  acl    = "public-read"  # CRITICAL: Allows public read access
  
  depends_on = [aws_s3_bucket_ownership_controls.s3_bucket_acl_ownership]
}

# CRITICAL FINDING 3: Ownership controls allowing ACLs
resource "aws_s3_bucket_ownership_controls" "s3_bucket_acl_ownership" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  
  rule {
    object_ownership = "BucketOwnerPreferred"  # Allows ACLs
  }
}

# CRITICAL FINDING 4: Public access block disabled
resource "aws_s3_bucket_public_access_block" "vulnerable_pab" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false  # CRITICAL: Should be true
  block_public_policy     = false  # CRITICAL: Should be true
  ignore_public_acls      = false  # CRITICAL: Should be true
  restrict_public_buckets = false  # CRITICAL: Should be true
}

# CRITICAL FINDING 5: Bucket policy allowing public access
resource "aws_s3_bucket_policy" "vulnerable_policy" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"  # CRITICAL: Wildcard principal allows anyone
        Action    = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      },
      {
        Sid       = "PublicListBucket"
        Effect    = "Allow"
        Principal = "*"  # CRITICAL: Wildcard principal allows anyone
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.vulnerable_bucket.arn
      }
    ]
  })
}

# CRITICAL FINDING 6: No server-side encryption configured
# The bucket has no default encryption, leaving data unencrypted at rest

# CRITICAL FINDING 7: No versioning enabled
# Without versioning, accidental deletions or modifications cannot be recovered

# CRITICAL FINDING 8: No logging configured
# No access logging means no audit trail for bucket access

# CRITICAL FINDING 9: No lifecycle policy
# Objects will remain indefinitely, potentially increasing costs and exposure

# CRITICAL FINDING 10: No MFA delete protection
# Objects can be deleted without multi-factor authentication

# Sample object upload to demonstrate the vulnerability
resource "aws_s3_object" "sample_sensitive_data" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  key    = "sensitive-data.txt"
  content = "This is sensitive data that should not be publicly accessible!"
  content_type = "text/plain"
  
  # CRITICAL FINDING 11: No object-level encryption
  # CRITICAL FINDING 12: Potentially sensitive data in publicly accessible bucket
}

# Outputs that expose sensitive information
output "bucket_name" {
  value = aws_s3_bucket.vulnerable_bucket.id
  description = "Name of the vulnerable S3 bucket"
}

output "bucket_domain_name" {
  value = aws_s3_bucket.vulnerable_bucket.bucket_domain_name
  description = "Domain name of the vulnerable S3 bucket"
}

output "public_url" {
  value = "https://${aws_s3_bucket.vulnerable_bucket.bucket_domain_name}/sensitive-data.txt"
  description = "CRITICAL: Publicly accessible URL to sensitive data"
}
