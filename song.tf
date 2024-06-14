provider "aws" {
  region = "ap-northeast-2"
}

# VPC 생성
resource "aws_vpc" "eks_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "eks-vpc"
  }
}

# 인터넷 게이트웨이 생성
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.eks_vpc.id

  tags = {
    Name = "eks-igw"
  }
}

# 퍼블릭 서브넷 생성
resource "aws_subnet" "public_subnet_1" {
  vpc_id            = aws_vpc.eks_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "eks-public-subnet-1"
  }
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id            = aws_vpc.eks_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "eks-public-subnet-2"
  }
}

# 프라이빗 서브넷 생성 (EKS 용)
resource "aws_subnet" "private_subnet_eks_1" {
  vpc_id            = aws_vpc.eks_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "eks-private-subnet-1"
  }
}

resource "aws_subnet" "private_subnet_eks_2" {
  vpc_id            = aws_vpc.eks_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "eks-private-subnet-2"
  }
}

# 프라이빗 서브넷 생성 (RDS 용)
resource "aws_subnet" "private_subnet_rds_1" {
  vpc_id            = aws_vpc.eks_vpc.id
  cidr_block        = "10.0.5.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "rds-private-subnet-1"
  }
}

resource "aws_subnet" "private_subnet_rds_2" {
  vpc_id            = aws_vpc.eks_vpc.id
  cidr_block        = "10.0.6.0/24"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "rds-private-subnet-2"
  }
}

# 라우팅 테이블 생성
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.eks_vpc.id

  tags = {
    Name = "eks-public-rt"
  }
}

# 인터넷 게이트웨이를 통해 라우팅 테이블에 라우트 추가
resource "aws_route" "igw_route" {
  route_table_id         = aws_route_table.public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

# 퍼블릭 서브넷을 라우팅 테이블과 연결
resource "aws_route_table_association" "public_subnet_1_association" {
  subnet_id      = aws_subnet.public_subnet_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_subnet_2_association" {
  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.public_rt.id
}

# NAT 게이트웨이 생성
resource "aws_eip" "nat_eip" {
  domain = "vpc"

  tags = {
    Name = "eks-nat-eip"
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet_1.id

  tags = {
    Name = "eks-nat-gateway"
  }
}

# 프라이빗 라우팅 테이블 생성
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.eks_vpc.id

  tags = {
    Name = "eks-private-rt"
  }
}

# 프라이빗 서브넷을 라우팅 테이블과 연결
resource "aws_route_table_association" "private_subnet_eks_1_association" {
  subnet_id      = aws_subnet.private_subnet_eks_1.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_subnet_eks_2_association" {
  subnet_id      = aws_subnet.private_subnet_eks_2.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_subnet_rds_1_association" {
  subnet_id      = aws_subnet.private_subnet_rds_1.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_subnet_rds_2_association" {
  subnet_id      = aws_subnet.private_subnet_rds_2.id
  route_table_id = aws_route_table.private_rt.id
}

# NAT 게이트웨이를 통해 프라이빗 서브넷에 인터넷 라우팅 설정
resource "aws_route" "private_nat_route" {
  route_table_id         = aws_route_table.private_rt.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}

# 보안 그룹 생성 - Bastion
resource "aws_security_group" "bastion_sg" {
  name        = "bastion_security_group"
  description = "Bastion host security group"
  vpc_id      = aws_vpc.eks_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "bastion-security-group"
  }
}


#pemkey 설정
resource "tls_private_key" "cicd_make_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "cicd_make_keypair" {
  key_name   = "cicd_key"
  public_key = tls_private_key.cicd_make_key.public_key_openssh
}

resource "local_file" "cicd_downloads_key" {
  filename = "cicd_key.pem"
  content  = tls_private_key.cicd_make_key.private_key_pem
}




# Bastion 서버 생성
resource "aws_instance" "bastion_server" {
  ami           = "ami-0425f132103cb3ed8"     
  instance_type = "t2.micro"         
  subnet_id     = aws_subnet.public_subnet_1.id
  key_name = aws_key_pair.cicd_make_keypair.key_name
  

  security_groups = [aws_security_group.bastion_sg.id] 

  tags = {
    Name = "Bastion Server"
  }
}

resource "aws_eip" "bastion_eip" {
  tags = {
    Name = "bastion-EIP"  
  }
}

resource "aws_eip_association" "bastion_eip_association" {
  instance_id   = aws_instance.bastion_server.id
  allocation_id = aws_eip.bastion_eip.id
}


# 보안 그룹 생성
resource "aws_security_group" "eks_security_group" {
  name        = "eks_security_group"
  description = "EKS cluster security group"
  vpc_id      = aws_vpc.eks_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "eks-security-group"
  }
}

# EKS 클러스터 생성
resource "aws_eks_cluster" "eks_cluster" {
  name     = "my-eks-cluster"
  role_arn = aws_iam_role.eks_role.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.private_subnet_eks_1.id,
      aws_subnet.private_subnet_eks_2.id,
    ]

    security_group_ids = [aws_security_group.eks_security_group.id]
  }

  tags = {
    Name = "my-eks-cluster"
  }
}

# EKS 노드 그룹 생성
resource "aws_eks_node_group" "eks_node_group" {
  cluster_name    = aws_eks_cluster.eks_cluster.name
  node_group_name = "my-eks-node-group"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = [
    aws_subnet.private_subnet_eks_1.id,
    aws_subnet.private_subnet_eks_2.id,
  ]

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  instance_types = ["t3.medium"]

  remote_access {
    ec2_ssh_key = aws_key_pair.cicd_make_keypair.key_name
  }

  tags = {
    Name = "my-eks-node-group"
  }
}

# IAM 역할 생성 (EKS 클러스터와 노드 그룹에 필요)
resource "aws_iam_role" "eks_role" {
  name = "eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "eks.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      },
    ]
  })

  tags = {
    Name = "eks-cluster-role"
  }
}

resource "aws_iam_role" "eks_node_role" {
  name = "eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action    = "sts:AssumeRole"
      },
    ]
  })

  tags = {
    Name = "eks-node-role"
  }
}

resource "aws_iam_role_policy_attachment" "eks_node_role_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "ec2_container_registry_read_only" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "eks_role_policy" {
  role       = aws_iam_role.eks_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# ALB 생성
resource "aws_lb" "eks_alb" {
  name               = "eks-alb"
  internal           = false  # 내부 ALB를 사용할 경우 true로 설정
  load_balancer_type = "application"
  security_groups    = [aws_security_group.eks_security_group.id]
  subnets            = [
    aws_subnet.public_subnet_1.id,
    aws_subnet.public_subnet_2.id,
  ]

  tags = {
    Name = "eks-alb"
  }
}

# 타겟 그룹 생성
resource "aws_lb_target_group" "eks_target_group" {
  name     = "eks-target-group"
  port     = 80  # 어플리케이션이 80번 포트에서 동작하는 것으로 가정
  protocol = "HTTP"
  vpc_id   = aws_vpc.eks_vpc.id

  health_check {
    path                = "/"  # 어플리케이션의 헬스체크 경로에 맞게 설정
    interval            = 30   # 헬스체크 간격 (초)
    timeout             = 10   # 타임아웃 (초)
    healthy_threshold   = 3    # 연속으로 성공한 헬스체크 횟수
    unhealthy_threshold = 2    # 연속으로 실패한 헬스체크 횟수
  }

  tags = {
    Name = "eks-target-group"
  }
}

# ALB 리스너 및 리스너 규칙 설정
resource "aws_lb_listener" "eks_alb_listener" {
  load_balancer_arn = aws_lb.eks_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.eks_target_group.arn
  }
}

resource "aws_lb_listener_rule" "eks_alb_rule" {
  listener_arn = aws_lb_listener.eks_alb_listener.arn

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.eks_target_group.arn
  }

  condition {
    path_pattern {
      values = ["/*"]
    }
  }
}
