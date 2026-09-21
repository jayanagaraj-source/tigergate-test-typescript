// Deliberately insecure AWS CDK stack for IaC scanner validation. Never deploy.
import { App, Duration, RemovalPolicy, SecretValue, Size, Stack, StackProps } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';

export class InsecureFixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    new s3.Bucket(this, 'PublicAssets', {
      publicReadAccess: true, // tg-expect: IAC-S3-001 public-read-bucket
      blockPublicAccess: new s3.BlockPublicAccess({ blockPublicAcls: false, blockPublicPolicy: false, ignorePublicAcls: false, restrictPublicBuckets: false }), // tg-expect: IAC-S3-002 public-access-block-disabled
      accessControl: s3.BucketAccessControl.PUBLIC_READ_WRITE, // tg-expect: IAC-S3-003 public-write-acl
      objectOwnership: s3.ObjectOwnership.OBJECT_WRITER,
      encryption: s3.BucketEncryption.UNENCRYPTED, // tg-expect: IAC-S3-004 bucket-unencrypted
      enforceSSL: false, // tg-expect: IAC-S3-005 bucket-allows-http
      versioned: false,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const vpc = new ec2.Vpc(this, 'Vpc', { maxAzs: 2 });

    const bastionSg = new ec2.SecurityGroup(this, 'BastionSg', { vpc, allowAllOutbound: true });
    bastionSg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'ssh from anywhere'); // tg-expect: IAC-SG-001 ssh-open-to-world
    bastionSg.addIngressRule(ec2.Peer.anyIpv6(), ec2.Port.allTraffic(), 'everything over ipv6'); // tg-expect: IAC-SG-002 all-ports-open-to-world

    new ec2.Instance(this, 'Bastion', {
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      securityGroup: bastionSg,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage: new ec2.AmazonLinuxImage(),
      requireImdsv2: false, // tg-expect: IAC-EC2-001 imdsv1-allowed
      blockDevices: [{ deviceName: '/dev/xvda', volume: ec2.BlockDeviceVolume.ebs(30, { encrypted: false }) }], // tg-expect: IAC-EBS-001 root-volume-unencrypted
      userData: ec2.UserData.custom('#!/bin/bash\nexport DB_PASSWORD=Pl41nT3xt-UserData-Pass'), // tg-expect: IAC-EC2-002 secret-in-user-data
    });

    new ec2.Volume(this, 'DataVolume', {
      availabilityZone: vpc.availabilityZones[0],
      size: Size.gibibytes(100),
      encrypted: false, // tg-expect: IAC-EBS-002 volume-unencrypted
    });

    new rds.DatabaseInstance(this, 'OrdersDb', {
      engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_5_7 }), // tg-expect: IAC-RDS-001 outdated-engine-version advanced
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      publiclyAccessible: true, // tg-expect: IAC-RDS-002 database-publicly-accessible
      storageEncrypted: false, // tg-expect: IAC-RDS-003 database-unencrypted
      backupRetention: Duration.days(0), // tg-expect: IAC-RDS-004 backups-disabled
      deletionProtection: false,
      iamAuthentication: false,
      multiAz: false,
      credentials: rds.Credentials.fromPassword('admin', SecretValue.unsafePlainText('Rds-Adm1n-Passw0rd!')), // tg-expect: IAC-RDS-005 plaintext-master-password
    });

    const adminRole = new iam.Role(this, 'EveryoneAdmin', {
      assumedBy: new iam.AnyPrincipal(), // tg-expect: IAC-IAM-001 role-assumable-by-anyone
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('AdministratorAccess')], // tg-expect: IAC-IAM-002 admin-managed-policy
    });
    adminRole.addToPolicy(new iam.PolicyStatement({ actions: ['*'], resources: ['*'] })); // tg-expect: IAC-IAM-003 wildcard-policy

    const fn = new lambda.Function(this, 'LegacyHandler', {
      runtime: lambda.Runtime.NODEJS_14_X, // tg-expect: IAC-LAMBDA-001 deprecated-runtime
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => ({ statusCode: 200 });'),
      role: adminRole,
      environment: { STRIPE_SECRET_KEY: 'sk_live_51Lm4Qx8Zt2Vn6Rp9Kw3Yb7C' }, // tg-expect: IAC-LAMBDA-002 secret-in-environment
    });
    fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE }); // tg-expect: IAC-LAMBDA-003 unauthenticated-function-url

    new sqs.Queue(this, 'Events', {
      encryption: sqs.QueueEncryption.UNENCRYPTED, // tg-expect: IAC-SQS-001 queue-unencrypted
    });

    new kms.Key(this, 'DataKey', {
      enableKeyRotation: false, // tg-expect: IAC-KMS-001 key-rotation-disabled
    });

    // Negative control: a hardened bucket that must not be flagged.
    new s3.Bucket(this, 'HardenedLogs', { // tg-clean: NEG-IAC-001
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.KMS_MANAGED,
      enforceSSL: true,
      versioned: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });
  }
}

if (require.main === module) {
  const app = new App();
  new InsecureFixtureStack(app, 'TigergateInsecureFixture');
  app.synth();
}
