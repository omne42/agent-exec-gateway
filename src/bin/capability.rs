use agent_exec_gateway::ExecGateway;

fn main() {
    let gateway = ExecGateway::new();
    let report = gateway.capability_report();
    println!("supported_isolation={:?}", report.supported_isolation);
}
