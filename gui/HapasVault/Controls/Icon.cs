using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;

namespace HapasVault.Controls;

/// <summary>
/// Иконка Material Symbols (геометрия в системе 0 -960 960 960).
/// Цвет наследуется от TextElement.Foreground, как у текста внутри кнопки.
/// </summary>
public sealed class Icon : FrameworkElement
{
    public static readonly DependencyProperty DataProperty = DependencyProperty.Register(
        nameof(Data), typeof(Geometry), typeof(Icon),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ForegroundProperty = TextElement.ForegroundProperty.AddOwner(
        typeof(Icon), new FrameworkPropertyMetadata(Brushes.Black,
            FrameworkPropertyMetadataOptions.Inherits | FrameworkPropertyMetadataOptions.AffectsRender));

    static Icon()
    {
        WidthProperty.OverrideMetadata(typeof(Icon), new FrameworkPropertyMetadata(24.0));
        HeightProperty.OverrideMetadata(typeof(Icon), new FrameworkPropertyMetadata(24.0));
        SnapsToDevicePixelsProperty.OverrideMetadata(typeof(Icon), new FrameworkPropertyMetadata(true));
    }

    public Geometry? Data { get => (Geometry?)GetValue(DataProperty); set => SetValue(DataProperty, value); }
    public Brush Foreground { get => (Brush)GetValue(ForegroundProperty); set => SetValue(ForegroundProperty, value); }

    protected override void OnRender(DrawingContext dc)
    {
        if (Data == null) return;
        double size = Math.Min(ActualWidth, ActualHeight);
        double s = size / 960;
        double ox = (ActualWidth - size) / 2, oy = (ActualHeight - size) / 2;
        dc.PushTransform(new MatrixTransform(s, 0, 0, s, ox, oy + 960 * s));
        dc.DrawGeometry(Foreground, null, Data);
        dc.Pop();
    }
}
