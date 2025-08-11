# This Terraform configuration intentionally contains critical security vulnerabilities
# for testing purposes with CrowdStrike FCS scanning

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

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
  default     = "my-insecure-test-bucket"
}

# CRITICAL FINDING #1: S3 bucket with public read access
# This allows anyone on the internet to read all objects in the bucket
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "${var.bucket_name}-${random_string.suffix.result}"

  tags = {
    Name        = "Insecure Test Bucket"
    Environment = "test"
    Purpose     = "security-testing"
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# CRITICAL FINDING #2: S3 bucket with public write access
# This allows anyone to upload/modify/delete objects in the bucket
resource "aws_s3_bucket_public_access_block" "insecure_bucket_pab" {
  bucket = aws_s3_bucket.insecure_bucket.id

  # These should be true for security, but setting to false creates vulnerabilities
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# CRITICAL FINDING #3: S3 bucket policy allowing public access
# This bucket policy grants public read and write permissions
resource "aws_s3_bucket_policy" "insecure_bucket_policy" {
  bucket = aws_s3_bucket.insecure_bucket.id

  policy = jsonencode({
    Version = "2012-10
