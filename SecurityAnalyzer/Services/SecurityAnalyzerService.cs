using System.Net.Sockets;
using System.Net.Http;
using SecurityAnalyzer.Models;

namespace SecurityAnalyzer.Services;

public sealed class SecurityAnalyzerService
{
    public async Task<(bool HostReachable,
            List<PortInfo> Ports,
            List<VulnerabilityInfo> Vulns,
            List<IncidentInfo> Incidents)>
        GenerateDataAsync(string ip)
    {
        var ports = await ScanPortsAsync(ip);

        var hostReachable = ports.Any(p => p.Status == "Open");

        if (!hostReachable)
        {
            return (false, ports, new List<VulnerabilityInfo>(), new List<IncidentInfo>());
        }

        var vulns = await AnalyzeHttpSecurityAsync(ip);
        var incidents = GenerateIncidentsDeterministic(ip);

        return (true, ports, vulns, incidents);
    }


    public async Task<List<PortInfo>> ScanPortsAsync(string ip)
    {
        var portsToCheck = new[] { 22, 80, 443, 3389, 8080 };

        var list = new List<PortInfo>();

        foreach (var port in portsToCheck)
        {
            var info = new PortInfo
            {
                Port = port,
                Protocol = "TCP"
            };

            using var client = new TcpClient();
            try
            {
                var connectTask = client.ConnectAsync(ip, port);
                var timeoutTask = Task.Delay(1000);

                var done = await Task.WhenAny(connectTask, timeoutTask);
                if (done == timeoutTask || !client.Connected)
                {
                    info.Status = "Closed";
                    info.Risk = 0;
                }
                else
                {
                    info.Status = "Open";
                    info.Risk = (port == 22 || port == 3389) ? 5 : 2;
                }
            }
            catch
            {
                info.Status = "Closed";
                info.Risk = 0;
            }

            list.Add(info);
        }

        return list;
    }


    public async Task<List<VulnerabilityInfo>> AnalyzeHttpSecurityAsync(string ip)
    {
        var result = new List<VulnerabilityInfo>();

        var urlHttp = $"http://{ip}/";
        var urlHttps = $"https://{ip}/";

        using var http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(3)
        };

        HttpResponseMessage? resp = null;
        bool httpsAvailable = false;

        try
        {
            resp = await http.GetAsync(urlHttps);
            httpsAvailable = true;
        }
        catch
        {
            try
            {
                resp = await http.GetAsync(urlHttp);
            }
            catch
            {
                return result;
            }
        }

        var headers = resp.Headers;

        void AddIfMissing(string headerName, string vulnName, string severity, int scoreIfMissing)
        {
            if (!headers.Contains(headerName))
            {
                result.Add(new VulnerabilityInfo
                {
                    Name = vulnName,
                    Severity = severity,
                    Score = scoreIfMissing
                });
            }
        }

        AddIfMissing("Strict-Transport-Security",
            "Отсутствует Strict-Transport-Security (HSTS)",
            "High", 8);

        AddIfMissing("X-Content-Type-Options",
            "Отсутствует X-Content-Type-Options",
            "Medium", 5);

        AddIfMissing("X-Frame-Options",
            "Отсутствует X-Frame-Options",
            "Medium", 4);

        AddIfMissing("Content-Security-Policy",
            "Отсутствует Content-Security-Policy",
            "High", 9);

        if (!httpsAvailable)
        {
            result.Add(new VulnerabilityInfo
            {
                Name = "Отсутствие HTTPS-доступа",
                Severity = "High",
                Score = 7
            });
        }

        return result;
    }


    public List<IncidentInfo> GenerateIncidentsDeterministic(string ip)
    {
        var seed = string.IsNullOrWhiteSpace(ip) ? 0 : ip.GetHashCode();
        var rnd = new Random(seed);

        return new List<IncidentInfo>
        {
            new()
            {
                Type = "Неудачные попытки входа",
                Count = rnd.Next(0, 15),
                Risk = 2
            },
            new()
            {
                Type = "Подозрительный трафик",
                Count = rnd.Next(0, 8),
                Risk = 4
            },
            new()
            {
                Type = "Блокированные подключения",
                Count = rnd.Next(0, 12),
                Risk = 1
            }
        };
    }


    public double CalcPortIndex(List<PortInfo> ports)
    {
        double riskSum = 0;

        foreach (var p in ports)
        {
            double weight = (p.Port == 22 || p.Port == 3389) ? 2.0 : 1.0;
            riskSum += weight * p.Risk;
        }

        var raw = 100 - 2.0 * riskSum;
        if (raw < 0) raw = 0;
        if (raw > 100) raw = 100;
        return Math.Round(raw, 1);
    }

    public double CalcVulnIndex(List<VulnerabilityInfo> vulns)
    {
        double riskSum = 0;

        foreach (var v in vulns)
        {
            double wSev = v.Severity.ToLower() switch
            {
                "high" or "critical" => 2.0,
                "medium" => 1.5,
                _ => 1.0
            };

            riskSum += wSev * v.Score;
        }

        var raw = 100 - 1.5 * riskSum;
        if (raw < 0) raw = 0;
        if (raw > 100) raw = 100;
        return Math.Round(raw, 1);
    }

    public double CalcIncidentIndex(List<IncidentInfo> incidents)
    {
        double riskSum = incidents.Sum(i => i.Risk * i.Count);

        var raw = 100 - 1.0 * riskSum;
        if (raw < 0) raw = 0;
        if (raw > 100) raw = 100;
        return Math.Round(raw, 1);
    }

    public double CalculateScore(
        List<PortInfo> ports,
        List<VulnerabilityInfo> vulns,
        List<IncidentInfo> incidents,
        out double portIndex,
        out double vulnIndex,
        out double incidentIndex)
    {
        portIndex = CalcPortIndex(ports);
        vulnIndex = CalcVulnIndex(vulns);
        incidentIndex = CalcIncidentIndex(incidents);

        const double wp = 0.3;
        const double wv = 0.5;
        const double wi = 0.2;

        var s = wp * portIndex + wv * vulnIndex + wi * incidentIndex;

        if (s < 0) s = 0;
        if (s > 100) s = 100;

        return Math.Round(s, 1);
    }

    public string GetConclusion(double score)
    {
        if (score >= 80)
            return "Высокий уровень безопасности. Существенных рисков не выявлено.";
        if (score >= 60)
            return "Средний уровень безопасности. Требуется аудит конфигурации и устранение выявленных уязвимостей.";
        return "Низкий уровень безопасности. Рекомендуется пересмотр сетевой архитектуры и настроек веб-сервиса, а также анализ инцидентов.";
    }
}
