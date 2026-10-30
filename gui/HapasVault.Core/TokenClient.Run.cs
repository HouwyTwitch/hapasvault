namespace HapasVault.Core;

// await недоступен в unsafe-контексте, поэтому планировщик вызовов — в отдельной части класса.
public sealed partial class TokenClient
{
    private async Task<T> Run<T>(Func<nint, T> f)
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            nint h = Handle;
            return await Task.Run(() => f(h)).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }
}
