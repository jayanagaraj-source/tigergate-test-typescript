// Deliberately insecure cdk8s chart for Kubernetes IaC scanner validation. Never apply.
import { ApiObject, App, Chart } from 'cdk8s';
import { Construct } from 'constructs';

export class InsecureWorkloadChart extends Chart {
  constructor(scope: Construct, id: string) {
    super(scope, id, { namespace: 'default' });

    new ApiObject(this, 'payments-api', {
      apiVersion: 'apps/v1',
      kind: 'Deployment',
      metadata: { name: 'payments-api' },
      spec: {
        replicas: 1,
        selector: { matchLabels: { app: 'payments-api' } },
        template: {
          metadata: { labels: { app: 'payments-api' } },
          spec: {
            hostNetwork: true, // tg-expect: IAC-K8S-001 host-network
            hostPID: true, // tg-expect: IAC-K8S-002 host-pid
            automountServiceAccountToken: true,
            containers: [
              {
                name: 'api',
                image: 'nginx:latest', // tg-expect: IAC-K8S-003 image-latest-tag
                securityContext: {
                  privileged: true, // tg-expect: IAC-K8S-004 privileged-container
                  runAsUser: 0, // tg-expect: IAC-K8S-005 runs-as-root
                  allowPrivilegeEscalation: true, // tg-expect: IAC-K8S-006 privilege-escalation
                  readOnlyRootFilesystem: false,
                  capabilities: { add: ['SYS_ADMIN', 'NET_ADMIN'] }, // tg-expect: IAC-K8S-007 dangerous-capabilities
                },
                env: [{ name: 'DB_PASSWORD', value: 'K8s-Pl41n-Db-Passw0rd' }], // tg-expect: IAC-K8S-008 secret-in-env
                ports: [{ containerPort: 8080, hostPort: 8080 }],
              },
            ],
            volumes: [{ name: 'docker-sock', hostPath: { path: '/var/run/docker.sock' } }], // tg-expect: IAC-K8S-009 docker-socket-mount
          },
        },
      },
    });

    new ApiObject(this, 'default-sa-cluster-admin', {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRoleBinding',
      metadata: { name: 'default-sa-cluster-admin' },
      roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: 'cluster-admin' }, // tg-expect: IAC-K8S-010 cluster-admin-binding
      subjects: [{ kind: 'ServiceAccount', name: 'default', namespace: 'default' }],
    });
  }
}

if (require.main === module) {
  const app = new App();
  new InsecureWorkloadChart(app, 'tigergate-insecure-workload');
  app.synth();
}
