terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" { region = "us-east-1" }

resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "Web server security group"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-company-data-bucket-prod"
}

resource "aws_s3_bucket_public_access_block" "data_pab" {
  bucket                  = aws_s3_bucket.data_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_db_instance" "main_db" {
  identifier              = "main-database"
  engine                  = "postgres"
  engine_version          = "14.7"
  instance_class          = "db.r5.4xlarge"
  allocated_storage       = 100
  db_name                 = "appdb"
  username                = "admin"
  password                = "SuperSecret123!"
  publicly_accessible     = true
  storage_encrypted       = false
  skip_final_snapshot     = true
  deletion_protection     = false
  backup_retention_period = 0
  vpc_security_group_ids  = [aws_security_group.web_sg.id]
}

resource "aws_instance" "app_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "m5.4xlarge"
  security_groups = [aws_security_group.web_sg.name]
  root_block_device {
    volume_type = "gp2"
    volume_size = 100
    encrypted   = false
  }
  tags = { Name = "app-server" }
}

resource "aws_iam_role_policy" "app_policy" {
  name = "app-full-access"
  role = "app-role"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
