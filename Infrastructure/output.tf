output "vpc_id" {
  value = aws_vpc.my_vpc.id
}

output "public_subnet_id" {
  value = aws_subnet.public_subnet.id
}

output "private_subnet_id" {
  value = aws_subnet.private_subnet.id
}

output "internet_gateway_id" {
  value = aws_internet_gateway.gw.id
}

output "public_security_group_id" {
  value = aws_security_group.public_sg.id
}