using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using AclMap.Core.Collector;
using AclMap.Core.Snapshot;
using Microsoft.Win32.SafeHandles;

namespace AclMap.Hosting;

/// <summary>Lanceur par défaut : session courante, ou « runas /netonly » si des identifiants sont fournis.</summary>
public sealed class DefaultProcessLauncher : IProcessLauncher
{
    public IRunningProcess Start(string exe, string arguments, NetCredential? credential)
    {
        if (credential is not null)
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("« Autre compte » exige Windows.");
            return NetOnlyLauncher.Start(exe, arguments, credential);
        }
        var p = Process.Start(new ProcessStartInfo(exe, arguments) { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden })
            ?? throw new InvalidOperationException("Le collecteur n'a pas pu démarrer.");
        return new ManagedProcess(p);
    }

    private sealed class ManagedProcess(Process p) : IRunningProcess
    {
        public bool HasExited => p.HasExited;
        public async Task<int> WaitForExitAsync(CancellationToken ct) { await p.WaitForExitAsync(ct).ConfigureAwait(false); return p.ExitCode; }
        public void Kill() { try { if (!p.HasExited) p.Kill(true); } catch (InvalidOperationException) { } }
        public void Dispose() => p.Dispose();
    }
}

/// <summary>
/// Équivalent de « runas /netonly » (CreateProcessWithLogonW, LOGON_NETCREDENTIALS_ONLY) : le collecteur tourne dans
/// la session locale mais ses accès réseau (LDAP, SMB) utilisent le compte du domaine. Le mot de passe passe du
/// SecureString à Windows sans copie gérée ; la ligne de commande (≤ 1023 caractères) ne contient aucun secret.
/// </summary>
[SupportedOSPlatform("windows")]
public static class NetOnlyLauncher
{
    private const uint LogonNetCredentialsOnly = 0x2, CreateUnicodeEnvironment = 0x400, CreateNoWindow = 0x08000000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessWithLogonW(string lpUsername, string? lpDomain, IntPtr lpPassword, uint dwLogonFlags,
        string? lpApplicationName, StringBuilder lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
        ref StartupInfo lpStartupInfo, out ProcessInformation lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeProcessHandle h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(SafeProcessHandle h, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(SafeProcessHandle h, uint code);

    public static IRunningProcess Start(string exe, string arguments, NetCredential credential)
    {
        var (user, domain) = credential.Split();
        var si = new StartupInfo { cb = Marshal.SizeOf<StartupInfo>(), dwFlags = 1, wShowWindow = 0 };
        var cmd = new StringBuilder($"\"{exe}\" {arguments}");
        if (cmd.Length > 1023) throw new ArgumentException($"Ligne de commande trop longue pour CreateProcessWithLogonW ({cmd.Length} caractères, 1023 maximum).");
        var env = new StringBuilder();
        foreach (var kv in Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>().OrderBy(k => (string)k.Key, StringComparer.OrdinalIgnoreCase))
            env.Append((string)kv.Key).Append('=').Append((string?)kv.Value).Append('\0');
        env.Append('\0');
        var envPtr = Marshal.StringToHGlobalUni(env.ToString());
        var pwd = Marshal.SecureStringToGlobalAllocUnicode(credential.Password);
        try
        {
            if (!CreateProcessWithLogonW(user, domain, pwd, LogonNetCredentialsOnly, exe, cmd, CreateUnicodeEnvironment | CreateNoWindow, envPtr, Path.GetDirectoryName(exe), ref si, out var pi))
            {
                var code = Marshal.GetLastWin32Error();
                throw new Win32Exception(code, $"Impossible de démarrer le collecteur avec le compte {credential.Account} (erreur Windows {code} : {new Win32Exception(code).Message}).{Hint(code)}");
            }
            CloseHandle(pi.hThread);
            return new NativeProcess(new SafeProcessHandle(pi.hProcess, ownsHandle: true));
        }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(pwd); Marshal.FreeHGlobal(envPtr); }
    }

    /// <summary>Piste de résolution des erreurs courantes.</summary>
    public static string Hint(int code) => code switch
    {
        1058 or 1068 or 1079 => "\n→ Le service « Ouverture de session secondaire » (seclogon) est désactivé : passez-le en démarrage Manuel.",
        1326 or 1327 or 1331 or 1909 => "\n→ Vérifiez le compte et le mot de passe (attention au verrouillage).",
        5 => "\n→ Accès refusé par Windows : lancez ACL Map depuis votre session.",
        _ => "",
    };

    private sealed class NativeProcess(SafeProcessHandle handle) : IRunningProcess
    {
        public bool HasExited => WaitForSingleObject(handle, 0) == 0;
        public async Task<int> WaitForExitAsync(CancellationToken ct)
        {
            while (WaitForSingleObject(handle, 0) != 0) { ct.ThrowIfCancellationRequested(); await Task.Delay(200, ct).ConfigureAwait(false); }
            return GetExitCodeProcess(handle, out var code) ? unchecked((int)code) : -1;
        }
        public void Kill() { if (!HasExited) TerminateProcess(handle, 1); }
        public void Dispose() => handle.Dispose();
    }
}

/// <summary>
/// Exécute AclMap.Collector.exe : la requête est écrite dans un fichier JSON temporaire (sans secret), les
/// événements sont lus dans un fichier JSON Lines (compatible « runas /netonly », sans sortie standard).
/// Annulation : fichier « .cancel » (arrêt propre, instantané partiel enregistré), puis arrêt forcé après 30 s.
/// </summary>
public sealed class CollectorProcessRunner(string collectorExe, IProcessLauncher launcher) : ICollectorRunner
{
    public async Task<CollectorOutcome> RunAsync(CollectorRequest request, NetCredential? credential, Action<JsonElement> onEvent, CancellationToken ct)
    {
        if (!File.Exists(collectorExe)) throw new FileNotFoundException("Collecteur introuvable : réinstallez ACL Map.", collectorExe);
        var id = Guid.NewGuid().ToString("N");
        var dir = Path.Combine(Path.GetTempPath(), "AclMap");
        Directory.CreateDirectory(dir);
        var reqFile = Path.Combine(dir, $"req-{id}.json");
        var events = Path.Combine(dir, $"evt-{id}.jsonl");
        File.WriteAllText(reqFile, JsonSerializer.Serialize(request, AclMapJson.Options));
        File.WriteAllText(events, "");
        JsonElement? result = null; string? error = null;
        void Handle(JsonElement e)
        {
            var type = e.TryGetProperty("type", out var t) ? t.GetString() : null;
            if (type == CollectorEvents.Result && e.TryGetProperty("data", out var d)) result = d.Clone();
            else if (type == CollectorEvents.Error) error = e.TryGetProperty("message", out var m) ? m.GetString() : "Erreur du collecteur.";
            onEvent(e);
        }
        IRunningProcess proc;
        try { proc = launcher.Start(collectorExe, $"--request \"{reqFile}\" --events \"{events}\"", credential); }
        catch { TryDelete(reqFile); TryDelete(events); throw; }
        using var _ = proc;
        var reader = new JsonlTail(events);
        var cancelAsked = DateTime.MinValue;
        try
        {
            while (!proc.HasExited)
            {
                reader.Drain(Handle);
                if (ct.IsCancellationRequested)
                {
                    if (cancelAsked == DateTime.MinValue) { cancelAsked = DateTime.UtcNow; File.WriteAllText(events + CollectorEvents.CancelSuffix, ""); }
                    else if (DateTime.UtcNow - cancelAsked > TimeSpan.FromSeconds(30)) { proc.Kill(); break; }
                }
                await Task.Delay(250, CancellationToken.None).ConfigureAwait(false);
            }
            var code = await proc.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            reader.Drain(Handle);
            if (result is null && error is null) error = code == 0 ? "Le collecteur s'est arrêté sans résultat." : $"Le collecteur s'est arrêté (code {code}).";
            return new CollectorOutcome(code, result, error);
        }
        finally { TryDelete(reqFile); TryDelete(events); TryDelete(events + CollectorEvents.CancelSuffix); }
    }

    private static void TryDelete(string f) { try { File.Delete(f); } catch (IOException) { } catch (UnauthorizedAccessException) { } }

    /// <summary>Lecture incrémentale d'un fichier JSON Lines en cours d'écriture (découpage sur les octets de fin de ligne, sans couper un caractère UTF-8).</summary>
    public sealed class JsonlTail(string file)
    {
        private long _offset;
        private readonly List<byte> _pending = [];

        public void Drain(Action<JsonElement> onEvent)
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length <= _offset) return;
            fs.Seek(_offset, SeekOrigin.Begin);
            var buffer = new byte[fs.Length - _offset];
            var read = fs.Read(buffer, 0, buffer.Length);
            _offset += read;
            _pending.AddRange(buffer.AsSpan(0, read).ToArray());
            var last = _pending.LastIndexOf((byte)'\n');
            if (last < 0) return;
            var text = Encoding.UTF8.GetString(_pending.GetRange(0, last).ToArray());
            _pending.RemoveRange(0, last + 1);
            foreach (var line in text.Split('\n'))
            {
                var l = line.Trim().TrimStart('\uFEFF');
                if (!l.StartsWith('{')) continue;
                try { using var doc = JsonDocument.Parse(l); onEvent(doc.RootElement.Clone()); } catch (JsonException) { }
            }
        }
    }
}
