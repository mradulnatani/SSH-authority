variable "aws_region" {
  description = "AWS Region"
  default     = "ap-south-1"
}

variable "vpc_cidrblock" {
  description = "AWS VPC CIDR block information"
  default     = "10.0.0.0/16"
}

variable "vpc_name" {
  description = "Name of the VPC made using Terraform"
  default     = "Terraform-vpc"
}

variable "vpc_public_subnet_cidr" {
  description = "CIDR block information for the public subnet"
  default     = "10.0.1.0/24"
}

variable "public_subnet_zone" {
  description = "Public subnet availability zone"
  default     = "ap-south-1a"
}

variable "vpc_private_subnet_cidr" {
  description = "Private VPC CIDR block"
  default     = "10.0.2.0/24"
}

variable "private_vpc_zone" {
  description = "Private subnet availability zone"
  default     = "ap-south-1a" 
}

variable "AWS_ACCESS_KEY_ID" {
  description = "AWS Access Key ID"
}

variable "AWS_SECRET_ACCESS_KEY" {
  description = "AWS Secret Access Key"
}
