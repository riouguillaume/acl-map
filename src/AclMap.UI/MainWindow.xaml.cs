using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Navigation;
using AclMap.Hosting;
using AclMap.Logging;
using AclMap.UI.Hosting;
using Microsoft.Web.WebView2.Core;

namespace AclMap.UI;

/// <summary>
/// Fenêtre principale : héberge l'interface ACL Map (HTML local) dans WebView2 et la relie au contrôleur.
/// Aucun contenu distant n'est chargé ; les liens externes s'ouvrent dans le navigateur.
/// </summary>
public partial class MainWindow : Window
{
    private const string HostName = "aclmap.app";
    private readonly string? _initialSnapshot;
    private AppController? _controller;

    public MainWindow(string? initialSnapshot)
    {
        _initialSnapshot = initialSnapshot;
        InitializeComponent();
        Loaded += async (_, _) => await StartAsync();
    }

    private void ShowStatus(string text, bool runtimeMissing = false)
    {
        StatusText.Text = text;
        StatusLink.Visibility = runtimeMissing ? Visibility.Visible : Visibility.Collapsed;
        StatusPanel.Visibility = Visibility.Visible;
        Web.Visibility = Visibility.Hidden;
    }

    private async Task StartAsync()
    {
        string viewerFolder;
        try { viewerFolder = AssetExtractor.ExtractAll(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowStatus("Impossible de préparer les fichiers de l'application : " + ex.Message);
            return;
        }

        string? webViewVersion = null;
        try
        {
            webViewVersion = CoreWebView2Environment.GetAvailableBrowserVersionString();
            var dataFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AclMap", "WebView2");
            var env = await CoreWebView2Environment.CreateAsync(null, dataFolder);
            await Web.EnsureCoreWebView2Async(env);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            ShowStatus("Le composant Microsoft Edge WebView2 est absent de ce poste (inclus dans Windows 10/11, absent de Windows Server). " +
                       "Installez-le puis relancez ACL Map. Sur un serveur de fichiers, le collecteur en ligne de commande (AclMap.Collector.exe) fonctionne sans lui.", runtimeMissing: true);
            return;
        }

        var core = Web.CoreWebView2;
        core.Settings.IsStatusBarEnabled = false;
        core.Settings.AreHostObjectsAllowed = false;
        core.Settings.IsWebMessageEnabled = true;
        core.Settings.IsGeneralAutofillEnabled = false;
        core.Settings.IsPasswordAutosaveEnabled = false;
#if !DEBUG
        core.Settings.AreDevToolsEnabled = false;
#endif
        core.SetVirtualHostNameToFolderMapping(HostName, viewerFolder, CoreWebView2HostResourceAccessKind.DenyCors);
        core.NavigationStarting += (_, e) =>
        {
            if (e.Uri.StartsWith($"https://{HostName}/", StringComparison.OrdinalIgnoreCase)) return;
            e.Cancel = true; OpenExternal(e.Uri);
        };
        core.NewWindowRequested += (_, e) => { e.Handled = true; OpenExternal(e.Uri); };

        var bridge = new WebViewBridge(Dispatcher, core);
        var dataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AclMap");
        var collector = Path.Combine(AppContext.BaseDirectory, "AclMap.Collector.exe");
        _controller = new AppController(bridge, new WpfDialogService(this), new CollectorProcessRunner(collector, new DefaultProcessLauncher()),
            new WpfCredentialPrompt(this), new WindowsSystemInfo(webViewVersion), new SettingsStore(SettingsStore.DefaultPath),
            new OperationLog(OperationLog.DefaultFolder), dataRoot, _initialSnapshot);

        core.WebMessageReceived += async (_, e) =>
        {
            try { await _controller.HandleAsync(e.WebMessageAsJson); }
            catch (Exception ex) when (ex is not OutOfMemoryException) { bridge.Post(System.Text.Json.JsonSerializer.Serialize(new { type = "error", message = ex.Message })); }
        };
        core.NavigationCompleted += (_, e) =>
        {
            if (e.IsSuccess) { StatusPanel.Visibility = Visibility.Collapsed; Web.Visibility = Visibility.Visible; }
            else ShowStatus($"L'interface n'a pas pu être chargée ({e.WebErrorStatus}).");
        };
        core.Navigate($"https://{HostName}/index.html");
    }

    private static void OpenExternal(string uri)
    {
        if (Uri.TryCreate(uri, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || u.Scheme == Uri.UriSchemeHttp))
            Process.Start(new ProcessStartInfo(u.AbsoluteUri) { UseShellExecute = true });
    }

    private void OnRequestNavigate(object sender, RequestNavigateEventArgs e) { OpenExternal(e.Uri.AbsoluteUri); e.Handled = true; }
}
