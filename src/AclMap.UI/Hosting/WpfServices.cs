using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using AclMap.Hosting;
using Microsoft.Web.WebView2.Core;
using Microsoft.Win32;

namespace AclMap.UI.Hosting;

/// <summary>Extrait l'interface web embarquée vers %LOCALAPPDATA%\AclMap\app\&lt;version&gt;\Viewer.</summary>
public static class AssetExtractor
{
    public static string ExtractAll()
    {
        var asm = Assembly.GetExecutingAssembly();
        var version = asm.GetName().Version?.ToString() ?? "0";
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AclMap", "app", version, "Viewer");
        var full = Path.GetFullPath(root);
        foreach (var name in asm.GetManifestResourceNames().Where(n => n.StartsWith("Viewer/", StringComparison.Ordinal)))
        {
            var target = Path.GetFullPath(Path.Combine(root, name["Viewer/".Length..].Replace('/', Path.DirectorySeparatorChar)));
            if (!target.StartsWith(full, StringComparison.OrdinalIgnoreCase)) continue;
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            using var src = asm.GetManifestResourceStream(name)!;
            using var dst = File.Create(target);
            src.CopyTo(dst);
        }
        return root;
    }
}

/// <summary>Envoie les messages à l'interface sur le thread WPF (exigence de WebView2).</summary>
public sealed class WebViewBridge(Dispatcher dispatcher, CoreWebView2 core) : IHostBridge
{
    public void Post(string json)
    {
        if (dispatcher.CheckAccess()) core.PostWebMessageAsJson(json);
        else dispatcher.InvokeAsync(() => core.PostWebMessageAsJson(json));
    }
}

/// <summary>Boîtes de dialogue Windows.</summary>
public sealed class WpfDialogService(Window owner) : IDialogService
{
    private static string DefaultFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "AclMap");

    private T OnUi<T>(Func<T> f) => owner.Dispatcher.CheckAccess() ? f() : owner.Dispatcher.Invoke(f);

    public string? OpenSnapshot(string title) => OnUi(() =>
    {
        var dlg = new OpenFileDialog { Title = title, Filter = "Instantané ACL Map (*.aclmap)|*.aclmap", InitialDirectory = Directory.Exists(DefaultFolder) ? DefaultFolder : null, CheckFileExists = true };
        return dlg.ShowDialog(owner) == true ? dlg.FileName : null;
    });

    public string? SaveFile(string suggestedName, string filter) => OnUi(() =>
    {
        var dlg = new SaveFileDialog { FileName = suggestedName, Filter = filter, InitialDirectory = Directory.Exists(DefaultFolder) ? DefaultFolder : null, OverwritePrompt = true };
        return dlg.ShowDialog(owner) == true ? dlg.FileName : null;
    });

    public string? PickFolder(string? initial) => OnUi(() =>
    {
        var dlg = new OpenFolderDialog { Title = "Choisir un dossier", InitialDirectory = !string.IsNullOrWhiteSpace(initial) && Directory.Exists(initial) ? initial : null };
        return dlg.ShowDialog(owner) == true ? dlg.FolderName : null;
    });
}

/// <summary>
/// Demande le mot de passe dans une fenêtre Windows (jamais dans la page web). Il reste un SecureString :
/// ni affiché, ni enregistré, ni journalisé.
/// </summary>
public sealed class WpfCredentialPrompt(Window owner) : ICredentialPrompt
{
    public SecureString? PromptPassword(string account, string target, string purpose) =>
        owner.Dispatcher.CheckAccess() ? Show(account, target, purpose) : owner.Dispatcher.Invoke(() => Show(account, target, purpose));

    private SecureString? Show(string account, string target, string purpose)
    {
        var box = new PasswordBox { Margin = new Thickness(0, 4, 0, 0), Padding = new Thickness(6, 4, 6, 4), FontSize = 14 };
        var ok = new Button { Content = "Se connecter", IsDefault = true, MinWidth = 110, Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 0, 8, 0) };
        var cancel = new Button { Content = "Annuler", IsCancel = true, MinWidth = 90, Padding = new Thickness(10, 4, 10, 4) };
        var muted = new SolidColorBrush(Color.FromRgb(0x5B, 0x64, 0x70));
        var panel = new StackPanel { Margin = new Thickness(20) };
        panel.Children.Add(new TextBlock { Text = "Identifiants du domaine", FontSize = 16, FontWeight = FontWeights.SemiBold });
        panel.Children.Add(new TextBlock { Text = $"Domaine / contrôleur : {target}", Margin = new Thickness(0, 10, 0, 0) });
        panel.Children.Add(new TextBlock { Text = $"Compte : {account}", Margin = new Thickness(0, 2, 0, 2) });
        panel.Children.Add(new TextBlock { Text = purpose, Foreground = muted, FontSize = 12, Margin = new Thickness(0, 0, 0, 10), TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(new TextBlock { Text = "Mot de passe" });
        panel.Children.Add(box);
        panel.Children.Add(new TextBlock
        {
            Text = "Utilisé uniquement pour les accès réseau d'ACL Map (équivalent « runas /netonly »). Jamais écrit sur le disque ni transmis à l'interface. Attention : plusieurs erreurs peuvent verrouiller le compte.",
            TextWrapping = TextWrapping.Wrap, Foreground = muted, FontSize = 12, Margin = new Thickness(0, 10, 0, 14),
        });
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(ok); buttons.Children.Add(cancel);
        panel.Children.Add(buttons);
        var win = new Window
        {
            Title = "ACL Map – Identifiants", Content = panel, Width = 460, SizeToContent = SizeToContent.Height,
            ResizeMode = ResizeMode.NoResize, WindowStartupLocation = WindowStartupLocation.CenterOwner, Owner = owner, ShowInTaskbar = false,
        };
        ok.Click += (_, _) => { if (box.SecurePassword.Length > 0) win.DialogResult = true; };
        win.Loaded += (_, _) => Keyboard.Focus(box);
        if (win.ShowDialog() != true) { box.Clear(); return null; }
        var pwd = box.SecurePassword;
        box.Clear();
        pwd.MakeReadOnly();
        return pwd;
    }
}

/// <summary>État du poste Windows.</summary>
public sealed class WindowsSystemInfo(string? webView2) : ISystemInfo
{
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetGetJoinInformation(string? server, out IntPtr name, out int status);
    [DllImport("netapi32.dll")] private static extern int NetApiBufferFree(IntPtr buffer);

    public bool IsDomainJoined
    {
        get
        {
            try { if (NetGetJoinInformation(null, out var n, out var st) != 0) return false; NetApiBufferFree(n); return st == 3; }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { return false; }
        }
    }

    public string? JoinedDomain
    {
        get
        {
            if (!IsDomainJoined) return null;
            try { var d = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName; return string.IsNullOrWhiteSpace(d) ? null : d; }
            catch (System.Net.NetworkInformation.NetworkInformationException) { return null; }
        }
    }

    public string MachineName => Environment.MachineName;
    public string CurrentUser => $"{Environment.UserDomainName}\\{Environment.UserName}";
    public string? WebView2Version => webView2;
    public string? DotNetVersion => Environment.Version.ToString();
}
