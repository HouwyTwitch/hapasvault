// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using HapasVault.Controls;

namespace HapasVault.Platform;

/// <summary>
/// Иконка программы — тот же знак, что в заголовке окна (печенье Cookie9 цвета Primary
/// с ключом OnPrimary), в цветах текущей палитры: окно, панель задач и трей меняются вместе с темой.
/// </summary>
public static partial class AppIcon
{
    private static readonly int[] Sizes = [16, 20, 24, 32, 40, 48, 64, 256];

    public static BitmapSource Render(Color fill, Color on, int px)
    {
        var dv = new DrawingVisual();
        using (var dc = dv.RenderOpen())
        {
            double pad = px * 0.02;
            var shape = Shapes.Geometry(ShapeKind.Cookie9, ShapeKind.Cookie9, 0, 0, new Rect(pad, pad, px - 2 * pad, px - 2 * pad));
            dc.DrawGeometry(new SolidColorBrush(fill), null, shape);
            if (Application.Current?.TryFindResource("Icon.KeyVerticalFill") is Geometry key)
            {
                double size = px * 16.0 / 28.0, s = size / 960, o = (px - size) / 2;   // как в заголовке: 16 из 28
                dc.PushTransform(new MatrixTransform(s, 0, 0, s, o, o + 960 * s));
                dc.DrawGeometry(new SolidColorBrush(on), null, key);
                dc.Pop();
            }
        }
        var bmp = new RenderTargetBitmap(px, px, 96, 96, PixelFormats.Pbgra32);
        bmp.Render(dv);
        bmp.Freeze();
        return bmp;
    }

    private static byte[] Png(BitmapSource b)
    {
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(b));
        using var ms = new MemoryStream();
        enc.Save(ms);
        return ms.ToArray();
    }

    /// <summary>ICO из PNG всех размеров — Windows сама берёт подходящий (16 в трее, 256 в Alt+Tab).</summary>
    public static byte[] Ico(Color fill, Color on)
    {
        var images = Sizes.Select(px => (px, png: Png(Render(fill, on, px)))).ToList();
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write((ushort)0); w.Write((ushort)1); w.Write((ushort)images.Count);
        int offset = 6 + 16 * images.Count;
        foreach (var (px, png) in images)
        {
            w.Write((byte)(px >= 256 ? 0 : px)); w.Write((byte)(px >= 256 ? 0 : px));
            w.Write((byte)0); w.Write((byte)0); w.Write((ushort)1); w.Write((ushort)32);
            w.Write(png.Length); w.Write(offset);
            offset += png.Length;
        }
        foreach (var (_, png) in images) w.Write(png);
        return ms.ToArray();
    }

    public static ImageSource WindowIcon(byte[] ico)
    {
        var dec = new IconBitmapDecoder(new MemoryStream(ico), BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
        return dec.Frames.OrderByDescending(f => f.PixelWidth).First();
    }

    [LibraryImport("user32.dll")]
    private static partial nint CreateIconFromResourceEx(byte[] bits, int size, [MarshalAs(UnmanagedType.Bool)] bool icon,
                                                          int version, int cx, int cy, int flags);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool DestroyIcon(nint icon);

    /// <summary>HICON нужного размера для трея (PNG внутри иконки Windows понимает с Vista).</summary>
    public static nint Handle(Color fill, Color on, int px)
    {
        byte[] png = Png(Render(fill, on, px));
        return CreateIconFromResourceEx(png, png.Length, true, 0x00030000, px, px, 0);
    }
}
