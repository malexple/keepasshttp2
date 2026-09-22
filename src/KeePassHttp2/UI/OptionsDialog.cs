// KeePassHttp2 Options dialog - reached via Tools menu (see
// KeePassHttp2Ext.GetMenuItem). Lets the user change the listen port and
// optionally restrict which WebSocket Origins are accepted.
//
// Layout note: every control's Y position is computed from the actual
// rendered Bottom of the previous control (via AutoSize + MaximumSize on
// labels), not hardcoded pixel offsets. Fixed pixel coordinates broke on
// a real machine because wrapped label text needed more vertical space
// than assumed at a different font/DPI scale than whatever this was
// eyeballed at - computing from .Bottom makes this self-adjusting instead
// of another guess.

using System.Drawing;
using System.Windows.Forms;

namespace KeePassHttp2.UI;

internal sealed class OptionsDialog : Form
{
    private readonly NumericUpDown _portInput;
    private readonly TextBox _originsInput;

    public ushort Port => (ushort)_portInput.Value;
    public string AllowedOrigins => _originsInput.Text.Trim();

    public OptionsDialog(ushort currentPort, string currentAllowedOrigins)
    {
        const int margin = 12;
        const int width = 420;

        Text = "KeePassHttp2 Options";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false;
        MaximizeBox = false;
        AutoScaleMode = AutoScaleMode.Font;

        int y = margin;

        var portLabel = new Label
        {
            Text = "Listen port (takes effect immediately):",
            AutoSize = true,
            MaximumSize = new Size(width - 2 * margin, 0),
            Location = new Point(margin, y),
        };
        Controls.Add(portLabel);
        y = portLabel.Bottom + 4;

        _portInput = new NumericUpDown
        {
            Minimum = 1,
            Maximum = 65535,
            Value = currentPort,
            Location = new Point(margin, y),
            Size = new Size(100, 23),
        };
        Controls.Add(_portInput);
        y = _portInput.Bottom + 16;

        var originsLabel = new Label
        {
            Text = "Allowed WebSocket Origins, comma-separated (empty = allow any).\n" +
                   "Only protects against a real browser on the wrong page - a local\n" +
                   "process can set this header to anything, so it's not a substitute\n" +
                   "for the Allow/Deny pairing prompt.",
            AutoSize = true,
            MaximumSize = new Size(width - 2 * margin, 0),
            Location = new Point(margin, y),
        };
        Controls.Add(originsLabel);
        y = originsLabel.Bottom + 4;

        _originsInput = new TextBox
        {
            Text = currentAllowedOrigins,
            Location = new Point(margin, y),
            Size = new Size(width - 2 * margin, 23),
        };
        Controls.Add(_originsInput);
        y = _originsInput.Bottom + 16;

        var okButton = new Button
        {
            Text = "Save",
            DialogResult = DialogResult.OK,
            Location = new Point(width - 2 * margin - 2 * 75 - 6, y),
            Size = new Size(75, 25),
        };
        Controls.Add(okButton);

        var cancelButton = new Button
        {
            Text = "Cancel",
            DialogResult = DialogResult.Cancel,
            Location = new Point(width - 2 * margin - 75, y),
            Size = new Size(75, 25),
        };
        Controls.Add(cancelButton);

        ClientSize = new Size(width, y + 25 + margin);

        AcceptButton = okButton;
        CancelButton = cancelButton;
    }
}