# S3 Bucket with MISCONFIGURED policy containing Delete actions
resource "aws_s3_bucket" "misconfigured_bucket" {
  bucket = var.bucket_name

  tags = {
    Name        = var.bucket_name
    Environment = var.environment
    Owner       = var.owner
  }
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "bucket_versioning" {
  bucket = aws_s3_bucket.misconfigured_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Server Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_encryption" {
  bucket = aws_s3_bucket.misconfigured_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# MISCONFIGURED S3 Bucket Policy - Contains Delete Actions (SECURITY ISSUE)
resource "aws_s3_bucket_policy" "misconfigured_policy" {
  bucket = aws_s3_bucket.misconfigured_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowFullAccess"
        Effect = "Allow"
        Principal = {
          AWS = var.allowed_principals
        }
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket",
          "s3:PutObject",
          "s3:PutObjectAcl",
          # MISCONFIGURATION: Delete actions present - triggers security finding
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource = [
          aws_s3_bucket.misconfigured_bucket.arn,
          "${aws_s3_bucket.misconfigured_bucket.arn}/*"
        ]
      },
      {
        Sid    = "AllowAdminAccess"
        Effect = "Allow"
        Principal = {
          AWS = var.admin_principals
        }
        Action = [
          "s3:*",
          # MISCONFIGURATION: Wildcard includes delete actions
          "s3:DeleteBucket"  # Explicit delete bucket permission
        ]
        Resource = [
          aws_s3_bucket.misconfigured_bucket.arn,
          "${aws_s3_bucket.misconfigured_bucket.arn}/*"
        ]
      },
      {
        Sid    = "AllowServiceAccess"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          # MISCONFIGURATION: Service also has delete permissions
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.misconfigured_bucket.arn}/*"
      }
    ]
  })
}

# Variables
variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "development"
}

variable "owner" {
  description = "Owner of the bucket"
  type        = string
  default     = "dev-team"
}

variable "allowed_principals" {
  description = "List of AWS principals allowed to access the bucket"
  type        = list(string)
  default     = ["arn:aws:iam::123456789012:user/dev-user"]
}

variable "admin_principals" {
  description = "List of AWS admin principals with full access"
  type        = list(string)
  default     = ["arn:aws:iam::123456789012:role/admin-role"]
}

# Outputs
output "bucket_name" {
  description = "Name of the created S3 bucket"
  value       = aws_s3_bucket.misconfigured_bucket.id
}

output "bucket_arn" {
  description = "ARN of the created S3 bucket"
  value       = aws_s3_bucket.misconfigured_bucket.arn
}

output "security_warning" {
  description = "Security warning about this configuration"
  value       = "WARNING: This bucket policy contains Delete actions which may trigger security findings!"
}
