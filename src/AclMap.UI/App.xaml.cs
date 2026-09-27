using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace AclMap.UI;

/// <summary>Point d'entrée d'ACL Map.</summary>
public partial class App : Application
{
    /// <inheritdoc/>
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandled;
        // Argument facultatif : un instantané .aclmap à ouvrir (double-clic dans l'Explorateur)
        var snapshot = e.Args.FirstOrDefault(a => a.EndsWith(".aclmap", StringComparison.OrdinalIgnoreCase) && File.Exists(a));
        new MainWindow(snapshot).Show();
    }

    private static void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show("Erreur inattendue : " + e.Exception.Message, "ACL Map", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
