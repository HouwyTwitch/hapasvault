using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace HapasVault.Controls;

/// <summary>
/// Поле пароля M3 с плавающей подписью и кнопкой «показать».
/// Password привязывается в обе стороны (PasswordBox этого не умеет).
/// </summary>
[TemplatePart(Name = "PART_Box", Type = typeof(PasswordBox))]
[TemplatePart(Name = "PART_Text", Type = typeof(TextBox))]
public sealed class PasswordField : Control
{
    public static readonly DependencyProperty PasswordProperty = DependencyProperty.Register(
        nameof(Password), typeof(string), typeof(PasswordField),
        new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.BindsTwoWayByDefault,
            (d, e) => ((PasswordField)d).OnPasswordChanged((string?)e.NewValue ?? "")));
    public static readonly DependencyProperty LabelProperty = DependencyProperty.Register(
        nameof(Label), typeof(string), typeof(PasswordField), new PropertyMetadata(""));
    public static readonly DependencyProperty SupportingProperty = DependencyProperty.Register(
        nameof(Supporting), typeof(string), typeof(PasswordField), new PropertyMetadata(null));
    public static readonly DependencyProperty ErrorProperty = DependencyProperty.Register(
        nameof(Error), typeof(string), typeof(PasswordField), new PropertyMetadata(null));
    public static readonly DependencyProperty IsRevealedProperty = DependencyProperty.Register(
        nameof(IsRevealed), typeof(bool), typeof(PasswordField),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault,
            (d, _) => ((PasswordField)d).OnRevealChanged()));
    public static readonly DependencyProperty CanRevealProperty = DependencyProperty.Register(
        nameof(CanReveal), typeof(bool), typeof(PasswordField), new PropertyMetadata(true));
    private static readonly DependencyPropertyKey HasTextKey = DependencyProperty.RegisterReadOnly(
        nameof(HasText), typeof(bool), typeof(PasswordField), new PropertyMetadata(false));
    public static readonly DependencyProperty HasTextProperty = HasTextKey.DependencyProperty;

    private PasswordBox? _box;
    private TextBox? _text;
    private bool _sync;

    public PasswordField() => Focusable = false;

    public string Password { get => (string)GetValue(PasswordProperty); set => SetValue(PasswordProperty, value); }
    public string Label { get => (string)GetValue(LabelProperty); set => SetValue(LabelProperty, value); }
    public string? Supporting { get => (string?)GetValue(SupportingProperty); set => SetValue(SupportingProperty, value); }
    public string? Error { get => (string?)GetValue(ErrorProperty); set => SetValue(ErrorProperty, value); }
    public bool IsRevealed { get => (bool)GetValue(IsRevealedProperty); set => SetValue(IsRevealedProperty, value); }
    public bool CanReveal { get => (bool)GetValue(CanRevealProperty); set => SetValue(CanRevealProperty, value); }
    public bool HasText => (bool)GetValue(HasTextProperty);

    public override void OnApplyTemplate()
    {
        if (_box != null) _box.PasswordChanged -= OnBoxChanged;
        if (_text != null) _text.TextChanged -= OnTextChanged;
        base.OnApplyTemplate();
        _box = GetTemplateChild("PART_Box") as PasswordBox;
        _text = GetTemplateChild("PART_Text") as TextBox;
        if (_box != null) _box.PasswordChanged += OnBoxChanged;
        if (_text != null) _text.TextChanged += OnTextChanged;
        OnPasswordChanged(Password);
        OnRevealChanged();
    }

    /// <summary>Перевести фокус ввода в поле.</summary>
    public void FocusInput()
    {
        Control? target = IsRevealed ? _text : _box;
        if (target == null) return;
        target.Focus();
        Keyboard.Focus(target);
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);
        if (!IsKeyboardFocusWithin) FocusInput();
    }

    private void OnBoxChanged(object sender, RoutedEventArgs e)
    {
        if (_sync || _box == null) return;
        Password = _box.Password;
    }

    private void OnTextChanged(object sender, TextChangedEventArgs e)
    {
        if (_sync || _text == null) return;
        Password = _text.Text;
    }

    private void OnPasswordChanged(string pw)
    {
        SetValue(HasTextKey, pw.Length > 0);
        _sync = true;
        try
        {
            if (_box != null && _box.Password != pw) _box.Password = pw;
            if (_text != null && _text.Text != pw) _text.Text = pw;
        }
        finally
        {
            _sync = false;
        }
    }

    private void OnRevealChanged()
    {
        if (_box == null || _text == null) return;
        bool hadFocus = IsKeyboardFocusWithin;
        _box.Visibility = IsRevealed ? Visibility.Collapsed : Visibility.Visible;
        _text.Visibility = IsRevealed ? Visibility.Visible : Visibility.Collapsed;
        if (hadFocus)
        {
            FocusInput();
            if (IsRevealed) _text.CaretIndex = _text.Text.Length;
        }
    }
}
