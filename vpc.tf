# Provider configuration
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  # Hardcoded credentials - CRITICAL FINDING
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# VPC with insecure configuration
resource "aws_vpc" "insecure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "insecure-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "insecure_igw" {
  vpc_id = aws_vpc.insecure_vpc.id

  tags = {
    Name = "insecure-igw"
  }
}

# Public subnet - overly permissive
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.insecure_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true # CRITICAL: Auto-assigns public IPs

  tags = {
    Name = "public-subnet"
  }
}

# Route table with overly permissive routes
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.insecure_vpc.id

  route {
    cidr_block = "0.0.0.0/0" # CRITICAL: Routes all traffic to internet
    gateway_id = aws_internet_gateway.insecure_igw.id
  }

  tags = {
    Name = "public-route-table"
  }
}

resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# Security Group - EXTREMELY INSECURE
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-security-group"
  description = "Insecure security group with wide open access"
  vpc_id      = aws_vpc.insecure_vpc.id

  # CRITICAL: Allow all inbound traffic from anywhere
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all TCP traffic from anywhere"
  }

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all UDP traffic from anywhere"
  }

  # CRITICAL: SSH access from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access from anywhere"
  }

  # CRITICAL: RDP access from anywhere
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP access from anywhere"
  }

  # CRITICAL: Database ports open to world
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "MySQL access from anywhere"
  }

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "PostgreSQL access from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "insecure-sg"
  }
}

# S3 Bucket with multiple critical issues
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-super-insecure-bucket-${random_string.bucket_suffix.result}"

  tags = {
    Name = "insecure-bucket"
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# CRITICAL: Public read/write ACL
resource "aws_s3_bucket_acl" "insecure_acl" {
  bucket = aws_s3_bucket.insecure_bucket.id
  acl    = "public-read-write"
}

# CRITICAL: Bucket policy allows public access
resource "aws_s3_bucket_policy" "insecure_policy" {
  bucket = aws_s3_bucket.insecure_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.insecure_bucket.arn,
          "${aws_s3_bucket.insecure_bucket.arn}/*"
        ]
      }
    ]
  })
}

# CRITICAL: No versioning enabled
resource "aws_s3_bucket_versioning" "insecure_versioning" {
  bucket = aws_s3_bucket.insecure_bucket.id
  versioning_configuration {
    status = "Disabled"
  }
}

# CRITICAL: No encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "insecure_encryption" {
  bucket = aws_s3_bucket.insecure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # Should use KMS
    }
  }
}

# CRITICAL: Public access block disabled
resource "aws_s3_bucket_public_access_block" "insecure_pab" {
  bucket = aws_s3_bucket.insecure_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# CRITICAL: Insecure CORS configuration
resource "aws_s3_bucket_cors_configuration" "insecure_cors" {
  bucket = aws_s3_bucket.insecure_bucket.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]
    allowed_origins = ["*"]
    expose_headers  = ["*"]
    max_age_seconds = 3000
  }
}

# EC2 Instance with security issues
resource "aws_instance" "insecure_instance" {
  ami                    = "ami-0c02fb55956c7d316" # Amazon Linux 2
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.insecure_sg.id]

  # CRITICAL: No encryption for root volume
  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = false
  }

  # CRITICAL: Instance metadata service v1 enabled
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional" # Should be "required"
  }

  user_data = base64encode(<<-EOF
              #!/bin/bash
              # CRITICAL: Hardcoded secrets in user data
              export DB_PASSWORD="super_secret_password_123"
              export API_KEY="sk-1234567890abcdef"
              echo "root:password123" | chpasswd
              EOF
  )

  tags = {
    Name = "insecure-instance"
  }
}

# RDS Instance with multiple issues
resource "aws_db_subnet_group" "insecure_db_subnet_group" {
  name       = "insecure-db-subnet-group"
  subnet_ids = [aws_subnet.public_subnet.id, aws_subnet.public_subnet2.id]

  tags = {
    Name = "insecure-db-subnet-group"
  }
}

resource "aws_subnet" "public_subnet2" {
  vpc_id            = aws_vpc.insecure_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "public-subnet-2"
  }
}

resource "aws_db_instance" "insecure_db" {
  identifier = "insecure-database"
  
  engine         = "mysql"
  engine_version = "5.7" # CRITICAL: Outdated version
  instance_class = "db.t3.micro"
  
  allocated_storage = 20
  storage_type      = "gp2"
  storage_encrypted = false # CRITICAL: No encryption
  
  db_name  = "insecuredb"
  username = "admin"
  password = "password123" # CRITICAL: Hardcoded weak password
  
  vpc_security_group_ids = [aws_security_group.insecure_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.insecure_db_subnet_group.name
  
  publicly_accessible = true # CRITICAL: Database accessible from internet
  
  backup_retention_period = 0    # CRITICAL: No backups
  backup_window          = null
  maintenance_window     = null
  
  skip_final_snapshot = true # CRITICAL: No final snapshot
  deletion_protection = false # CRITICAL: No deletion protection
  
  # CRITICAL: No monitoring
  monitoring_interval = 0
  
  tags = {
    Name = "insecure-database"
  }
}

# Load Balancer with security issues
resource "aws_lb" "insecure_alb" {
  name               = "insecure-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.insecure_sg.id]
  subnets            = [aws_subnet.public_subnet.id, aws_subnet.public_subnet2.id]

  # CRITICAL: No access logs
  access_logs {
    bucket  = ""
    enabled = false
  }

  # CRITICAL: Deletion protection disabled
  enable_deletion_protection = false

  tags = {
    Name = "insecure-alb"
  }
}

# CRITICAL: HTTP listener (no HTTPS)
resource "aws_lb_listener" "insecure_listener" {
  load_balancer_arn = aws_lb.insecure_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Insecure HTTP endpoint"
      status_code  = "200"
    }
  }
}

# CloudTrail with issues
resource "aws_cloudtrail" "insecure_trail" {
  name           = "insecure-trail"
  s3_bucket_name = aws_s3_bucket.insecure_bucket.bucket

  # CRITICAL: Not encrypted
  kms_key_id = null

  # CRITICAL: No log file validation
  enable_log_file_validation = false

  # CRITICAL: Only management events
  include_global_service_events = false
  is_multi_region_trail         = false

  tags = {
    Name = "insecure-trail"
  }
}

# IAM Role with overly permissive policy
resource "aws_iam_role" "insecure_role" {
  name = "insecure-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "*" # CRITICAL: Any service can assume this role
        }
      }
    ]
  })
}

# CRITICAL: Policy with full admin access
resource "aws_iam_role_policy" "insecure_policy" {
  name = "insecure-policy"
  role = aws_iam_role.insecure_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"
        Resource = "*"
      }
    ]
  })
}

# Output sensitive information
output "database_password" {
  value     = aws_db_instance.insecure_db.password
  sensitive = false # CRITICAL: Sensitive data not marked as sensitive
}

output "bucket_name" {
  value = aws_s3_bucket.insecure_bucket.bucket
}
