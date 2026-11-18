export default {
  title: 'Plugins',
  desc: 'Unified device gateway; each plugin declares its IOC types and capabilities in a manifest',
  col: {
    code: 'Plugin code',
    name: 'Name',
    version: 'Version',
    iocTypes: 'IOC types',
    capabilities: 'Capabilities',
    desc: 'Description',
    actions: 'Actions',
  },
  test: {
    title: 'Test plugin: {code}',
    hint: 'A connectivity test never blocks anything. Real device credentials are injected through the device credential_ref.',
    run: 'Run test',
    invalidJson: 'Config is not valid JSON',
  },
}
