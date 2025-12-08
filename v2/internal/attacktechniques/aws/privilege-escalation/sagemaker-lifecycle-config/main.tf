terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.54.0, < 5.0.0" # 4.54.0 at least is required for proper AWS SSO support, see #626
    }
  }
}
provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}


# Data Source for Current Account ID
data "aws_caller_identity" "current" {}

locals {
  resource_prefix = "stratus-red-team-update-sagemaker-config-profile"
}

# --- 1. High-Privilege Target Role (The Goal of the Attack) ---

resource "aws_iam_role" "high_priv_execution_role" {
  name = "${local.resource_prefix}-high-priv-role"
  description = "Execution role for SageMaker instance. Target for privilege escalation."
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "sagemaker.amazonaws.com"
        },
        Action = "sts:AssumeRole",
      },
    ],
  })
}
# The High-Privilege Policy: Contains sensitive permissions the attacker is seeking.
resource "aws_iam_policy" "high_priv_policy" {
  name = "${local.resource_prefix}-sagemaker-high-priv-policy"
  description = "Policy with IAM and S3 admin privileges."
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        # IAM Privilege Escalation Vector
        Effect = "Allow",
        Action = [
          "iam:CreateUser",
          "iam:AttachUserPolicy",
          "iam:ListUsers",
          "iam:ListPolicies",
        ],
        Resource = "*"
      },
      {
        # S3 Data Access / Exfiltration Vector
        Effect = "Allow",
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
        ],
        Resource = "*"
      },
      {
        # Necessary base permissions for SageMaker
        Effect = "Allow",
        Action = [
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
        ],
        Resource = "*"
      },
    ],
  })
}

resource "aws_iam_role_policy_attachment" "high_priv_attach" {
  role       = aws_iam_role.high_priv_execution_role.name
  policy_arn = aws_iam_policy.high_priv_policy.arn
}

# --- 2. Low-Privilege Attacker Role (The Enabler of the Attack) ---

resource "aws_iam_role" "low_priv_attacker_role" {
  name = "${local.resource_prefix}-low-priv-role"
  description = "Role with permissions to execute the SageMaker update attack."
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action = "sts:AssumeRole",
      },
    ],
  })
}

# The Low-Privilege Policy: Contains the specific permissions for the exploit chain.
resource "aws_iam_policy" "low_priv_attacker_policy" {
  name = "${local.resource_prefix}-sagemaker-low-priv-attacker-policy"
  description = "Vulnerable policy allowing SageMaker notebook modification."
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          # CRITICAL EXPLOIT PERMISSIONS
          "sagemaker:StopNotebookInstance",
          "sagemaker:UpdateNotebookInstance",
          "sagemaker:StartNotebookInstance",
          "sagemaker:CreateNotebookInstanceLifecycleConfig",
        ],
        Resource = "*" # VULNERABILITY: Resource scope is deliberately too broad here.
      },
      # The attacker will also need PassRole for the high-priv role IF 
      # they want to create a new notebook, but for attacking an EXISTING
      # notebook, these four actions are key.
      {
        Effect = "Allow",
        Action = "sagemaker:DescribeNotebookInstance",
        Resource = "*"
      }
    ],
  })
}

resource "aws_iam_role_policy_attachment" "low_priv_attach" {
  role       = aws_iam_role.low_priv_attacker_role.name
  policy_arn = aws_iam_policy.low_priv_attacker_policy.arn
}


# --- 3. SageMaker Notebook Instance (The Target) ---

resource "aws_sagemaker_notebook_instance" "target_notebook" {
  name          = "${local.resource_prefix}-vuln-notebook"
  role_arn      = aws_iam_role.high_priv_execution_role.arn
  instance_type = "ml.t2.medium"
  # Set to skip root access to ensure only the role is the entry point
  root_access   = "Disabled" 
}

# --- Variable Definitions ---

resource "random_integer" "random" {
  min = 1000
  max = 9999
}

# --- Outputs for Execution ---

output "attacker_role_arn" {
  description = "The IAM role with the low-privilege, vulnerable permissions."
  value = aws_iam_role.low_priv_attacker_role.arn
}

output "target_notebook_name" {
  description = "The name of the target SageMaker Notebook Instance."
  value = aws_sagemaker_notebook_instance.target_notebook.name
}

output "high_priv_role_arn" {
  description = "The ARN of the high-privilege role that the attacker will attempt to assume."
  value = aws_iam_role.high_priv_execution_role.arn
}


