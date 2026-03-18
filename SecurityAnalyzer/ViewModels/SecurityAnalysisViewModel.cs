using SecurityAnalyzer.Models;

namespace SecurityAnalyzer.ViewModels;

public sealed class SecurityAnalysisViewModel
{
    public string IpAddress { get; set; } = "";

    public List<PortInfo> Ports { get; set; } = [];
    public List<VulnerabilityInfo> Vulnerabilities { get; set; } = [];
    public List<IncidentInfo> Incidents { get; set; } = [];

    public double PortIndex { get; set; }
    public double VulnerabilityIndex { get; set; }
    public double IncidentIndex { get; set; }

    public double Score { get; set; }

    public string Conclusion { get; set; } = "";
    //@@
    public string PortConclusion { get; set; } = string.Empty;
    public string VulnerabilityConclusion { get; set; } = string.Empty;
    public string IncidentConclusion { get; set; } = string.Empty;
    //
    public List<VulnerabilityInfo> TopVulnerabilities { get; set; } = [];
    public List<IncidentInfo> TopIncidents { get; set; } = [];
    
    public bool HostReachable { get; set; }
    public string HostStatusMessage { get; set; } = "";

}