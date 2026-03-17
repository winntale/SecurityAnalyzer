namespace SecurityAnalyzer.Models;

public class PortInfo
{
    public int Port { get; set; }
    public string Protocol { get; set; } = "";
    public string Status { get; set; } = "";
    public int Risk { get; set; }
}