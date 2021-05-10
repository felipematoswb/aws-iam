# AWS IAM

## - Introdução

Para logar em qualquer sistema, precisamos de 2 informações criticas.

1. Autenticação: Define quem é a pessoa ou o grupo.
2. Autorização: Define qual ação o usuário pode executar

IAM Users podem ser a pessoa que usará AWS Console com usuário e senha ou uma conta de serviço com uma access key e secret key.

IAM é um serviço global e não é especificado em *regions*, você não precisa especificar a região quando definir uma permissão para o usuário, ou seja, o usuário pode acessar o serviço de qualquer região, se ele estiver habilitado pela politica definida.

## - Criar um usuário

Para criar um usuário com o username **user01**, utilize o comando abaixo na AWS Console ou AWS Cli.

```bash
aws iam create-user --user-name user01
```

A saída da console:

```json
{
    "User": {
        "Path": "/",
        "UserName": "user01",
        "UserId": "AIDA5CVO4T2FH6FKL3KFD",
        "Arn": "arn:aws:iam::999088880999:user/user01",
        "CreateDate": "2021-05-08T03:37:53+00:00"
    }
}
```

Quando usamos o comando ***aws iam create-user --user-name user01*** a saída dele tem as seguintes informações.

1. Path - Caminho para o usuário, o default é /
2. UserName - O username definido pelo provedor durante a criação do IAM user.
3. UserId: Está é a string que irá identificar o usuário.
4. Arn: É o identificador único do recurso (haverá uma explicação melhor mais abaixo)
5. CreateDate: Data de criação do usuário

## - Listando usuários

Para listar usuários, utilizamos o comando abaixo.

```bash
aws iam list-users --query User[].[UserName,Arn] --output table
```

Agora que você ja sabe como criar e listar os usuários, vamos focar em IAM Groups

## - IAM Groups

Groups é uma coleção de usuários. Groups podem listar usuários especificos, deixando o gerenciamento bem mais agradavel, ou seja, podemos criar um grupo de administradores e introduzir usuários que precisam dessa permissão nele, entao, assim que forem chegando novas pessoas na organização que necessitam de acesso administrador, iremos precisar apenas adiciona-los ao grupo de administradores e todos os acessos já serão dados.
Caso a pessoa mude de função, será necessário apenas mover o usuário do grupo.
Adendo, IAM Groups não é um objeto real, pois não podemos menciona-los numa permissão, mas é um mero caminho para anexarmos politicas para multiplos usuários.

Para criar um group, execute o comando:

```bash
aws iam create-group --group-name admins
```

Iremos obter uma saída abaixo

```json
{
    "Group": {
        "Path": "/",
        "GroupName": "admins",
        "GroupId": "AGPA5CVO4T2FLJBBKZXEU",
        "Arn": "arn:aws:iam::999088880999:group/admins",
        "CreateDate": "2021-05-08T03:59:13+00:00"
    }
}
```

Para listar os Groups, execute o comando:

```bash
aws iam list-groups --query Groups[].GroupName --output table
```

Para adicionar usuário a um group, execute o comando:

```bash
aws iam add-user-to-group --user-name user01 --group-name admins
```

Agora sabemos como criar, listar e adicionar usuário a um IAM Group

## - Introdução Politicas

As IAM Policy são em formato JSON, elas definem as ações de um usuário, group e roles podem fazer com recursos AWS, quando usuários, groups ou roles efetuam um requisição, AWS Policy Engine, verifica policy necessária para execução e então bloqueia ou permite o acesso ao recurso AWS.
Por padrão, todas as requisições são implicitamente negadas e usuários ou groups não tem permissão ou roles anexadas por padrão.

AWS suporta 4 tipos de politicas

1. Identity-based-policies: Para garatir permissão para qualquer identidade, como usuário, groups ou roles.
2. Resource-based policies: Está é a mais usada, pois garante a permissão diretamente a um recurso.
3. Permissions Boundaries: Este tipo não garante nenhuma permissão, mas define o maximo de acesso que uma permissão pode conceder.
4. Organizations SCPs: É o serviço de controle de politicas, é usado para uma conta que é membro de uma organização ou unidade organizacional (OU) e ela define o maximo que uma permissão pode conceder a membros de uma organização.

## - Estrutura IAM Policy

Como mencionado, IAM Policy é em formato JSON, para construir um JSON, nós precisamos de um estrutura, IAM Policy é divida em quatro partes.

1. Effect: Existe apenas 2 opções, Allow or Deny, que já dizem por si, permite ou nega o recurso.
2. Action: Lista o service-level que será permitido ou negado, exemplo ***s3:GetObject*** s3 é o nome do serviço e GetObject é a ação que será tomada.
3. Resource: Especifica a lista de recursos que será permitido ou negado o acesso.
4. Condition: Especifica a condição que o recurso será acessado, por exemplo, codição baseada num IP especifico.

```json
"Condition": {
    "NotIpAddress": {
        "aws:SourceIp": [
        "192.0.2.0/24",
        "203.0.113.0/24"
        ]
    }
}
```

Combinando todas as partes de uma IAM Policy a estrutura será parecida com esta abaxo:

```json
{
    "Statement":[{
        "Effect":"effect",
        "Action":"action",
        "Resource":"arn",
        "Condition":{
            "condition":{
            "key":"value"
            }
        }
    }]
}
```

Um real exemplo, nesta politica, o trafego para um S3 Bucket de um IP especifico, usaremos a opção de Condition com aws:SourceIP, a qual irá permitir as requisições de um IP especifico.

```json
{
    "Id": "Policy1604259866496",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt1604259864802",
            "Action": "s3:*",
            "Effect": "Deny",
            "Resource": "arn:aws:s3:::myexamplebucket/*",
            "Condition": {
                "NotIpAddress": {
                    "aws:SourceIp": "192.168.1.10/24"
                }
            },
            "Principal": "*"
        }
    ]
}
```

Adendo, ***Principal*** é a definição de quem pode assumir essa role, ou seja, posso limitar quem pode utilizar, não posso utilizar essa opção quando o tipo IAM Identity-based, pois estou dizendo que o recurso pode ser utilizado por qualquer usuário que seja especificado na politica.

Refinando a explicação, quando utilizo baseado em Identidades, eu digo que o usuário1 pode desligar uma EC2, quando eu uso baseado em Recursos, eu digo que uma EC2 pode ser desligada pelo usuário2, então o que acontece? AWS primeiro verifica todas as politicas que NEGAM o recurso, se houver, a solicitação é negada. Em seguida verifica cada uma das politicas que PERMITEM, se pelo menos uma declaração permitir a ação na solicitação, ela será permitida, não importa se a permissão está na Identidade ou no Recurso.

Aqui segue o exemplo de especificação:

```json
"Principal": { "AWS": "arn:aws:iam::123456789012:root" }
```

Aqui digo que o usuário root pode utilizar essa politica.

## - ARN Introdução

É utilizado para definir a identidade de qualquer recursos AWS unicamente.
É especificado para ser utilizado entre todos os recursos AWS, como IAM, API calls e etc..
Recurso global você não precisa especificar a **Region** ou **Account Number**.

```bash
arn:partition:service:region:account-id:resource-id
```

1. Partition - É um grupo de AWS Regions que podem ser: AWS, AWS-CN e AWS-US-GOV
2. Service - Identificador do produto: iam, s3, ec2, etc.
3. Region - Especificadamente a Region: us-west-2, us-east-1, etc.
4. Account-id - É o dono do recurso: 123456789012
5. Resource-id - Este pode ser o nome ou o ID do recurso: my_test_bucket

```bash
arn:aws:iam::123456789012:user/Prod/test1234/*
```

## - IAM Policy Avaliação

1. Por default todas as solicitações são rejeitadas
2. AWS policy engine avalia todas as politicas que permitem e rejeitam
3. Verifica se há policitas que habilitam ou rejeitam explicitamente
4. Se existe alguma politica com SCP (Service Control Policy) ou Permissions Boundaries
5. Se existir alguma rejeição, o acesso é negado.

Iremos criar um IAM Policy que faça as seguintes permissoões:

1. Start e Stop de uma instancia especifica
2. Describe instances e DeleteKeypair de qualquer instancia

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ec2:StartInstances",
                "ec2:StopInstances"
            ],
            "Resource": "arn:aws:ec2:us-west-2:XXXXXX:instance/i-02ba5c9e4250bf322"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DeleteKeyPair"
            ],
            "Resource": "*"
        }
    ]
}
```

Crie uma Instance e substitua o ARN descrito no Resource pelo ARN da sua instancia.
Salve esse script JSON num arquivo chamado: **ec2-instance.json**

Para criar a Policy e anexar ela no usuário user01, insira o comando abaixo

```bash
aws iam put-user-policy --user-name user01 --policy-name ec2_restrict --policy-document file://ec2-instance.json
```

O comando abaixo lista a Policy em questão

```bash
aws iam get-user-policy --user-name  user01 --policy-name ec2_restrict
```

## - Criando IAM Roles

Eu penso que IAM Roles é bem similar um IAM User, porque AWS defini um grupo de permissões que podem fazer requisições aos Serviços AWS.
IAM Roles podem ser usadas para Aplicações e Usuário Externos.

Vamos utilizar o Terraform para criar essa Role.

A Role abaixo vai permitir acesso ao recurso EC2.

```hcl
resource "aws_iam_role" "my-test-iam-role" {
  name               = "my-test-iam-role"
  assume_role_policy = <<EOF
{

    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
            "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow"
        }
    ]
}
EOF

  tags = {
    tag-key = "my-test-iam-role"
  }

}
```

Agora vamos criar um Instance Profile

```hcl
resource "aws_iam_instance_profile" "my-test-iam-instance-profile" {
    name = "my-test-iam-instance-profile"
    role = aws_iam_role.my-test-iam-role.name
}
```

Agora vamos criar um Policy que permita que os usuário da EC2 possam executar alguns comandos num S3

```hcl
resource "aws_iam_role_policy" "my-test-policy" {
  name   = "my-test-iam-policy"
  role   = aws_iam_role.my-test-iam-role.id
  policy = <<EOF
{

    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:PutObject",
                "s3:GetObject"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}
```

Finalmente, podemos anexar a Role criada na EC2 Instance Profile

```hcl
resource "aws_instance" "test_ec2_role" {
    ami = "ami-0d5fad86866a3a449"
    instance_type = "t2.micro"
    iam_instance_profile = aws_iam_instance_profile.my-test-iam-instance-profile.name
    key_name = "my_key_test"
}
```

Vamos executar o codigo

```bash
terraform init
```

```bash
terraform plan
```

```bash
terraform apply
```

Para verificar que está tudo certo, executaremos o comando abaixo:

```bash
ssh -i <public key> ec2-user@<public ip of the instance>
```

Até a proxima,

Minhas redes sociais

[Twitter](https://twitter.com/felipematoswb)

[LinkedIn](https://www.linkedin.com/in/felipematoswb/)
