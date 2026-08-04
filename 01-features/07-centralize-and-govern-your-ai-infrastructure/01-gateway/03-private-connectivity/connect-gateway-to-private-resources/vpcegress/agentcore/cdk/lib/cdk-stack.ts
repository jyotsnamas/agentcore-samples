import {
  AgentCoreApplication,
  AgentCoreMcp,
  type AgentCoreProjectSpec,
  type AgentCoreMcpSpec,
} from '@aws/agentcore-cdk';
import { CfnOutput, Stack, type StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface AgentCoreStackProps extends StackProps {
  /** The AgentCore project specification containing agents, memories, and credentials. */
  spec: AgentCoreProjectSpec;
  /** The MCP specification containing gateways and targets. */
  mcpSpec?: AgentCoreMcpSpec;
  /** Credential provider ARNs from deployed state, keyed by credential name. */
  credentials?: Record<string, { credentialProviderArn: string; clientSecretArn?: string }>;
}

/**
 * CDK Stack that deploys the AgentCore resources declared in agentcore.json.
 *
 * This is a thin wrapper around the L3 constructs: all resource logic and
 * outputs live inside AgentCoreApplication (runtimes, memories, credentials)
 * and AgentCoreMcp (gateway + targets). The gateway tutorials in this folder
 * declare only gateways and targets, so `agentCoreGateways` is the field that
 * drives most deployments here.
 *
 * Deployment: `agentcore deploy`
 */
export class AgentCoreStack extends Stack {
  /** The AgentCore application containing all agent environments. */
  public readonly application: AgentCoreApplication;

  constructor(scope: Construct, id: string, props: AgentCoreStackProps) {
    super(scope, id, props);

    const { spec, mcpSpec, credentials } = props;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const appProps: Record<string, unknown> = { spec };
    if (credentials) {
      appProps.credentials = credentials;
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    this.application = new AgentCoreApplication(this, 'Application', appProps as any);

    // Only synthesize the MCP construct when the project declares a gateway;
    // an empty agentCoreGateways array must not create gateway resources.
    if (mcpSpec?.agentCoreGateways && mcpSpec.agentCoreGateways.length > 0) {
      new AgentCoreMcp(this, 'Mcp', {
        projectName: spec.name,
        mcpSpec,
        agentCoreApplication: this.application,
        credentials,
        projectTags: spec.tags,
      });
    }

    new CfnOutput(this, 'StackNameOutput', {
      description: 'Name of the CloudFormation Stack',
      value: this.stackName,
    });
  }
}
