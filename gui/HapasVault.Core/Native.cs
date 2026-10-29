using System.Runtime.InteropServices;

namespace HapasVault.Core;

/// <summary>P/Invoke к pmapi (client/pmapi.h). Все вызовы блокирующие.</summary>
internal static unsafe partial class Native
{
    private const string Lib = "pmapi";

    [StructLayout(LayoutKind.Sequential)]
    internal struct Info
    {
        public int Paired, SetupDone, Unlocked;
        public uint Proto, Count, UptimeS;
    }

    [LibraryImport(Lib)] internal static partial int pmapi_version();
    [LibraryImport(Lib)] internal static partial uint pmapi_max_backup();

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nint pmapi_create(string? identityPath);
    [LibraryImport(Lib)] internal static partial void pmapi_destroy(nint h);
    [LibraryImport(Lib)] internal static partial int pmapi_is_paired(nint h);
    [LibraryImport(Lib)] internal static partial int pmapi_has_key(nint h);
    [LibraryImport(Lib)] internal static partial void pmapi_set_argon(nint h, uint kib, uint passes);

    [LibraryImport(Lib)] internal static partial int pmapi_attach(nint h, ushort port);
    [LibraryImport(Lib)] internal static partial void pmapi_detach(nint h);
    [LibraryImport(Lib)] internal static partial int pmapi_is_attached(nint h);

    [LibraryImport(Lib)] internal static partial int pmapi_pair(nint h, out uint code);
    [LibraryImport(Lib)] internal static partial int pmapi_forget_pairing(nint h);
    [LibraryImport(Lib)] internal static partial int pmapi_connect(nint h);
    [LibraryImport(Lib)] internal static partial int pmapi_info(nint h, out Info info);

    [LibraryImport(Lib)] internal static partial int pmapi_setup_begin(nint h, byte* words, nuint cap);
    [LibraryImport(Lib)] internal static partial int pmapi_setup_commit(nint h, byte* masterPassword);
    [LibraryImport(Lib)]
    internal static partial int pmapi_restore(nint h, byte* words, byte* masterPassword, byte* backup, nuint backupLen);
    [LibraryImport(Lib)] internal static partial int pmapi_unlock(nint h, byte* masterPassword);
    [LibraryImport(Lib)] internal static partial int pmapi_lock(nint h);

    [LibraryImport(Lib)]
    internal static partial int pmapi_list(nint h, delegate* unmanaged<nint, uint, byte*, byte*, void> cb, nint ctx);
    [LibraryImport(Lib)]
    internal static partial int pmapi_get(nint h, uint id, byte* login, nuint loginCap, byte* password, nuint pwCap);
    [LibraryImport(Lib)]
    internal static partial int pmapi_add(nint h, byte* category, byte* name, byte* login, byte* password, out uint id);
    [LibraryImport(Lib)] internal static partial int pmapi_delete(nint h, uint id);
    [LibraryImport(Lib)]
    internal static partial int pmapi_log(nint h, delegate* unmanaged<nint, uint, byte, byte, uint, void> cb, nint ctx);
    [LibraryImport(Lib)] internal static partial int pmapi_backup(nint h, byte* output, nuint cap, out nuint len);
    [LibraryImport(Lib)] internal static partial int pmapi_factory_reset(nint h);

    [LibraryImport(Lib)] internal static partial byte* pmapi_strerror(int code);
    [LibraryImport(Lib)] internal static partial byte* pmapi_bip39_word(int i);
    [LibraryImport(Lib)] internal static partial int pmapi_check_phrase(byte* words);

    internal static string Utf8(byte* p) => p == null ? "" : Marshal.PtrToStringUTF8((nint)p) ?? "";
}
