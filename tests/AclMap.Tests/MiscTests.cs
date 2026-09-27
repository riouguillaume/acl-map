using System.Text;
using AclMap.Core.Validation;
using AclMap.Export;
using AclMap.Logging;
using AclMap.Services;
using L = AclMap.Testing.LabSnapshotFactory;

namespace AclMap.Tests;

public class MiscTests
{
    [Theory]
    [InlineData("contoso.local", true)]
    [InlineData("contoso", false)]
    [InlineData("-bad.local", false)]
    public void Domain(string v, bool ok) => Assert.Equal(ok, InputValidator.Domain(v) is null);

    [Theory]
    [InlineData("FS01", true)]
    [InlineData("FS01.contoso.local", true)]
    [InlineData("192.168.1.11", true)]
    [InlineData("FS 01", false)]
    public void Server(string v, bool ok) => Assert.Equal(ok, InputValidator.Server(v) is null);

    [Theory]
    [InlineData(@"CONTOSO\audit", true)]
    [InlineData("audit@contoso.local", true)]
    [InlineData("audit", false)]
    public void Account(string v, bool ok) => Assert.Equal(ok, InputValidator.Account(v) is null);

    [Theory]
    [InlineData(@"\\FS01\Donnees", true)]
    [InlineData(@"\\FS01\Donnees\Compta\2025", true)]
    [InlineData(@"\\FS01", false)]
    [InlineData(@"\\FS01\Donnees\..\C$", false)]
    [InlineData(@"\\?\C:\x", false)]
    [InlineData(@"D:\Donnees", false)]
    public void Unc(string v, bool ok) => Assert.Equal(ok, InputValidator.Unc(v) is null);

    [Fact]
    public void Scan_path_accepts_local_and_unc()
    {
        Assert.Null(InputValidator.ScanPath(@"D:\Donnees"));
        Assert.Null(InputValidator.ScanPath(@"\\FS01\Donnees"));
        Assert.NotNull(InputValidator.ScanPath(@"Donnees"));
        Assert.Equal(("FS01", "Donnees", @"Compta\2025"), InputValidator.SplitUnc(@"\\FS01\Donnees\Compta\2025\")!.Value);
    }

    [Fact]
    public void Csv_exports_escape_formulas_and_use_semicolons()
    {
        var s = new AnalysisSession(L.Create());
        using var ms = new MemoryStream();
        Exporters.Write(s, ExportKind.AclCsv, ms);
        var text = Encoding.UTF8.GetString(ms.ToArray());
        Assert.StartsWith("\uFEFFChemin;Propriétaire", text);
        Assert.Contains("Compta", text);
        foreach (var k in new[] { ExportKind.FindingsCsv, ExportKind.SharesCsv, ExportKind.PrincipalsCsv, ExportKind.Json })
        {
            using var o = new MemoryStream(); Exporters.Write(s, k, o); Assert.True(o.Length > 100, k.ToString());
        }
        using var acc = new MemoryStream();
        Exporters.Write(s, ExportKind.AccessCsv, acc, L.Alice, "ntfs");
        Assert.Contains("Modification", Encoding.UTF8.GetString(acc.ToArray()));
    }

    [Fact]
    public void Html_report_contains_kpis_findings_and_matrix()
    {
        var html = Exporters.HtmlReport(new AnalysisSession(L.Create()));
        Assert.Contains("ACL-006", html);
        Assert.Contains("Matrice d'accès", html);
        Assert.Contains("DL_Donnees-Compta_RW", html);
        Assert.DoesNotContain("<script", html);
    }

    [Fact]
    public void Log_writes_and_reads_back()
    {
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            var log = new OperationLog(dir.FullName);
            log.Write("info", "scan.start", "Analyse", new() { ["path"] = @"\\FS01\Donnees" }, "c1");
            log.Write("audit", "plan.apply", "Appliqué");
            var r = log.Recent();
            Assert.Equal(2, r.Count);
            Assert.Equal("plan.apply", r[0].Event);
        }
        finally { dir.Delete(true); }
    }
}
