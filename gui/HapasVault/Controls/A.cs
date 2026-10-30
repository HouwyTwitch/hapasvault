using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using HapasVault.Motion;

namespace HapasVault.Controls;

public enum GroupPosition { Single, First, Middle, Last }

/// <summary>Вложенные свойства для стилей: иконки, подписи полей, позиция в группе, «тряска».</summary>
public static class A
{
    /// <summary>
    /// Трансформация нужного типа из общей группы элемента: эффекты (появление,
    /// нажатие, тряска, оборот) не затирают друг друга.
    /// </summary>
    public static T Xf<T>(UIElement el) where T : Transform, new()
    {
        switch (el.RenderTransform)
        {
            case TransformGroup g when !g.IsFrozen:
                if (g.Children.OfType<T>().FirstOrDefault() is { } found) return found;
                var add = new T();
                g.Children.Add(add);
                return add;
            case T t when !t.IsFrozen:
                return t;
        }
        var group = new TransformGroup();
        if (el.RenderTransform is { } old && old != Transform.Identity && !old.Value.IsIdentity) group.Children.Add(old.CloneCurrentValue());
        var made = new T();
        group.Children.Add(made);
        el.RenderTransform = group;
        el.RenderTransformOrigin = new Point(0.5, 0.5);
        return made;
    }

    // ---- иконки ----
    public static readonly DependencyProperty IconProperty = DependencyProperty.RegisterAttached(
        "Icon", typeof(Geometry), typeof(A), new PropertyMetadata(null));
    public static Geometry? GetIcon(DependencyObject o) => (Geometry?)o.GetValue(IconProperty);
    public static void SetIcon(DependencyObject o, Geometry? v) => o.SetValue(IconProperty, v);

    /// <summary>Иконка выбранного состояния (обычно залитый вариант).</summary>
    public static readonly DependencyProperty IconSelectedProperty = DependencyProperty.RegisterAttached(
        "IconSelected", typeof(Geometry), typeof(A), new PropertyMetadata(null));
    public static Geometry? GetIconSelected(DependencyObject o) => (Geometry?)o.GetValue(IconSelectedProperty);
    public static void SetIconSelected(DependencyObject o, Geometry? v) => o.SetValue(IconSelectedProperty, v);

    // ---- текстовые поля ----
    public static readonly DependencyProperty LabelProperty = DependencyProperty.RegisterAttached(
        "Label", typeof(string), typeof(A), new PropertyMetadata(null));
    public static string? GetLabel(DependencyObject o) => (string?)o.GetValue(LabelProperty);
    public static void SetLabel(DependencyObject o, string? v) => o.SetValue(LabelProperty, v);

    public static readonly DependencyProperty SupportingProperty = DependencyProperty.RegisterAttached(
        "Supporting", typeof(string), typeof(A), new PropertyMetadata(null));
    public static string? GetSupporting(DependencyObject o) => (string?)o.GetValue(SupportingProperty);
    public static void SetSupporting(DependencyObject o, string? v) => o.SetValue(SupportingProperty, v);

    public static readonly DependencyProperty ErrorProperty = DependencyProperty.RegisterAttached(
        "Error", typeof(string), typeof(A), new PropertyMetadata(null));
    public static string? GetError(DependencyObject o) => (string?)o.GetValue(ErrorProperty);
    public static void SetError(DependencyObject o, string? v) => o.SetValue(ErrorProperty, v);

    /// <summary>Подсказка внутри пустого поля (для полей без плавающей подписи, например поиска).</summary>
    public static readonly DependencyProperty PlaceholderProperty = DependencyProperty.RegisterAttached(
        "Placeholder", typeof(string), typeof(A), new PropertyMetadata(null));
    public static string? GetPlaceholder(DependencyObject o) => (string?)o.GetValue(PlaceholderProperty);
    public static void SetPlaceholder(DependencyObject o, string? v) => o.SetValue(PlaceholderProperty, v);

    // ---- группы кнопок ----
    public static readonly DependencyProperty PositionProperty = DependencyProperty.RegisterAttached(
        "Position", typeof(GroupPosition), typeof(A), new PropertyMetadata(GroupPosition.Single));
    public static GroupPosition GetPosition(DependencyObject o) => (GroupPosition)o.GetValue(PositionProperty);
    public static void SetPosition(DependencyObject o, GroupPosition v) => o.SetValue(PositionProperty, v);

    // ---- фокус при появлении ----
    public static readonly DependencyProperty FocusOnLoadProperty = DependencyProperty.RegisterAttached(
        "FocusOnLoad", typeof(bool), typeof(A), new PropertyMetadata(false, OnFocusOnLoad));
    public static bool GetFocusOnLoad(DependencyObject o) => (bool)o.GetValue(FocusOnLoadProperty);
    public static void SetFocusOnLoad(DependencyObject o, bool v) => o.SetValue(FocusOnLoadProperty, v);

    private static void OnFocusOnLoad(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement fe || e.NewValue is not true) return;
        fe.Loaded += (_, _) => fe.Dispatcher.BeginInvoke(() => Focus(fe), System.Windows.Threading.DispatcherPriority.Input);
    }

    public static void Focus(FrameworkElement fe)
    {
        if (fe is PasswordField pf) pf.FocusInput();
        else
        {
            fe.Focus();
            Keyboard.Focus(fe);
        }
    }

    // ---- «тряска» при ошибке: меняйте значение (счётчик), элемент вздрогнет ----
    public static readonly DependencyProperty ShakeProperty = DependencyProperty.RegisterAttached(
        "Shake", typeof(int), typeof(A), new PropertyMetadata(0, OnShake));
    public static int GetShake(DependencyObject o) => (int)o.GetValue(ShakeProperty);
    public static void SetShake(DependencyObject o, int v) => o.SetValue(ShakeProperty, v);

    private static void OnShake(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not UIElement el || (int)e.NewValue == 0) return;
        var tt = Xf<TranslateTransform>(el);
        var a = new DoubleAnimationUsingKeyFrames { Duration = TimeSpan.FromMilliseconds(520) };
        double[] xs = [0, -14, 12, -9, 6, -3, 0];
        for (int i = 0; i < xs.Length; i++)
            a.KeyFrames.Add(new EasingDoubleKeyFrame(xs[i], KeyTime.FromPercent(i / (double)(xs.Length - 1)),
                new SineEase { EasingMode = EasingMode.EaseInOut }));
        tt.BeginAnimation(TranslateTransform.XProperty, a);
    }

    // ---- слайдер: нажатие в любом месте дорожки сразу начинает перетаскивание ----
    public static readonly DependencyProperty DragAnywhereProperty = DependencyProperty.RegisterAttached(
        "DragAnywhere", typeof(bool), typeof(A), new PropertyMetadata(false, OnDragAnywhere));
    public static bool GetDragAnywhere(DependencyObject o) => (bool)o.GetValue(DragAnywhereProperty);
    public static void SetDragAnywhere(DependencyObject o, bool v) => o.SetValue(DragAnywhereProperty, v);

    private static void OnDragAnywhere(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not Slider s) return;
        if (e.NewValue is true) s.PreviewMouseLeftButtonDown += OnSliderDown;
        else s.PreviewMouseLeftButtonDown -= OnSliderDown;
    }

    private static void OnSliderDown(object sender, MouseButtonEventArgs e)
    {
        var s = (Slider)sender;
        if (s.Template.FindName("PART_Track", s) is not Track track || track.Thumb is not { } thumb) return;
        if (thumb.IsMouseOver) return;   // за сам бегунок — обычное перетаскивание
        double v = track.ValueFromPoint(e.GetPosition(track));
        if (s.IsSnapToTickEnabled && s.TickFrequency > 0)
            v = s.Minimum + Math.Round((v - s.Minimum) / s.TickFrequency) * s.TickFrequency;
        s.Value = Math.Clamp(v, s.Minimum, s.Maximum);
        s.Focus();
        // бегунок уже под курсором: передаём ему нажатие, и он захватывает мышь
        track.UpdateLayout();
        thumb.RaiseEvent(new MouseButtonEventArgs(e.MouseDevice, e.Timestamp, MouseButton.Left)
        {
            RoutedEvent = UIElement.MouseLeftButtonDownEvent,
            Source = thumb,
        });
        e.Handled = true;
    }

    // ---- оборот с упругим перелётом: меняйте значение (счётчик) ----
    public static readonly DependencyProperty SpinProperty = DependencyProperty.RegisterAttached(
        "Spin", typeof(int), typeof(A), new PropertyMetadata(0, OnSpin));
    public static int GetSpin(DependencyObject o) => (int)o.GetValue(SpinProperty);
    public static void SetSpin(DependencyObject o, int v) => o.SetValue(SpinProperty, v);

    private static void OnSpin(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not UIElement el || (int)e.NewValue == 0) return;
        var rt = Xf<RotateTransform>(el);
        rt.BeginAnimation(RotateTransform.AngleProperty, new DoubleAnimation(0, 360, TimeSpan.FromMilliseconds(800))
        { EasingFunction = M3Motion.SpringBouncy });
    }

    // ---- «появление» с пружиной (для списков и карточек) ----
    public static readonly DependencyProperty EnterProperty = DependencyProperty.RegisterAttached(
        "Enter", typeof(double), typeof(A), new PropertyMetadata(-1.0, OnEnter));
    /// <summary>Задержка появления в мс (≥ 0): элемент «всплывает» при загрузке.</summary>
    public static double GetEnter(DependencyObject o) => (double)o.GetValue(EnterProperty);
    public static void SetEnter(DependencyObject o, double v) => o.SetValue(EnterProperty, v);

    private static void OnEnter(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement fe || (double)e.NewValue < 0) return;
        double delay = Math.Min((double)e.NewValue, 400);
        fe.Opacity = 0;
        fe.Loaded += (_, _) =>
        {
            var tt = Xf<TranslateTransform>(fe);
            var begin = TimeSpan.FromMilliseconds(delay);
            fe.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(260))
            { BeginTime = begin, EasingFunction = M3Motion.EmphasizedDecelerate });
            tt.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(18, 0, TimeSpan.FromMilliseconds(650))
            { BeginTime = begin, EasingFunction = M3Motion.SpringSpatial });
        };
    }

    // ---- пружинное нажатие: элемент слегка «сжимается» ----
    public static readonly DependencyProperty PressScaleProperty = DependencyProperty.RegisterAttached(
        "PressScale", typeof(double), typeof(A), new PropertyMetadata(1.0, OnPressScale));
    public static double GetPressScale(DependencyObject o) => (double)o.GetValue(PressScaleProperty);
    public static void SetPressScale(DependencyObject o, double v) => o.SetValue(PressScaleProperty, v);

    private static void OnPressScale(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement fe) return;
        double s = (double)e.NewValue;
        var st = Xf<ScaleTransform>(fe);
        void To(double v, double ms, IEasingFunction ease)
        {
            st.BeginAnimation(ScaleTransform.ScaleXProperty, M3Motion.To(v, ms, ease));
            st.BeginAnimation(ScaleTransform.ScaleYProperty, M3Motion.To(v, ms, ease));
        }
        fe.PreviewMouseLeftButtonDown += (_, _) => { if (fe.IsEnabled) To(s, 250, M3Motion.SpringEffects); };
        fe.PreviewMouseLeftButtonUp += (_, _) => To(1, 600, M3Motion.SpringBouncy);
        fe.MouseLeave += (_, _) => To(1, 600, M3Motion.SpringBouncy);
    }
}
