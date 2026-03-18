using Microsoft.AspNetCore.Mvc;
using SecurityAnalyzer.ViewModels;
using SecurityAnalyzer.Services;

namespace SecurityAnalyzer.Controllers;

public class HomeController(SecurityAnalyzerService analyzer) : Controller
{
    [HttpGet]
    public IActionResult Index()
    {
        var vm = new SecurityAnalysisViewModel();
        return View(vm);
    }

    [HttpPost]
    public async Task<IActionResult> Index(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
        {
            ModelState.AddModelError("IpAddress", "IP-адрес обязателен");
            return View(new SecurityAnalysisViewModel());
        }

        var (hostReachable, ports, vulns, incidents) = await analyzer.GenerateDataAsync(ipAddress);

        var vm = new SecurityAnalysisViewModel
        {
            IpAddress = ipAddress,
            HostReachable = hostReachable,
            Ports = ports
        };

        if (!hostReachable)
        {
            vm.HostStatusMessage =
                "Все проверенные порты закрыты. Узел считается недоступным, анализ безопасности не выполнялся.";
            return View(vm);
        }

        var score = analyzer.CalculateScore(
            ports,
            vulns,
            incidents,
            out var sp,
            out var sv,
            out var si);
        //@@ сортировку
        vm.Vulnerabilities = vulns
            .OrderByDescending(v => v.Score)
            .ToList();
        //@@
        vm.Incidents = incidents
            .Where(i => i.Count > 0)
            .OrderByDescending(i => i.Risk * i.Count)
            .ToList();
        vm.PortIndex = sp;
        vm.VulnerabilityIndex = sv;
        vm.IncidentIndex = si;
        vm.Score = score;
        vm.Conclusion = analyzer.GetConclusion(score);
        vm.HostStatusMessage = "Узел доступен. Анализ выполнен.";
        //@@
        vm.PortConclusion = analyzer.GetPortConclusion(ports);
        vm.VulnerabilityConclusion = analyzer.GetVulnerabilityConclusion(vulns);
        vm.IncidentConclusion = analyzer.GetIncidentConclusion(incidents);
        //

        vm.TopVulnerabilities = vulns
            .OrderByDescending(v => v.Score)
            .Take(3)
            .ToList();
        vm.TopIncidents = incidents
            .OrderByDescending(i => i.Risk * i.Count)
            .Take(3)
            .ToList();

        return View(vm);
    }
}